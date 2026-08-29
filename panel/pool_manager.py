#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoolManager — управляет пулом nfqws2 процессов.

Каждый слот пула:
  - свой QNUM (base + index)
  - свой nfqws2 процесс
  - своя стратегия (NFQWS2_OPT строка)

iptables правила (random connmark) пишутся через zapret2 custom.d хук.
PoolManager только перезаписывает /run/zapret-pool/size и перегружает fw
когда меняется размер пула.
"""

import os, re, signal, subprocess, threading, time, socket

NFQWS2_BIN     = "/opt/zapret2/nfq2/nfqws2"
ZAPRET_INIT    = "/opt/zapret2/init.d/sysv/zapret2"
POOL_RUN_DIR   = "/run/zapret-pool"
QNUM_BASE      = 300
MAX_SLOTS      = 10
TEST_SOCKS_BASE = 2300   # временные ss-local порты: 2300, 2301, ...

LUAOPT = (
    "--lua-init=@/opt/zapret2/lua/zapret-lib.lua "
    "--lua-init=@/opt/zapret2/lua/zapret-antidpi.lua "
    "--lua-init=@/opt/zapret2/lua/zapret-auto.lua"
)
DESYNC_MARK = os.environ.get("DESYNC_MARK", "0x40000000")
WS_USER     = "nobody"

_SS_SERVER_PORT = None   # выставляется из main()
_SS_PASSWORD    = None
_SS_METHOD      = None


class Slot:
    def __init__(self, index):
        self.index     = index
        self.qnum      = QNUM_BASE + index
        self.strategy  = None   # имя стратегии
        self.nfqws_opt = None   # строка аргументов
        self.proc      = None   # subprocess.Popen
        self.healthy   = None   # True/False/None
        self.started   = None   # timestamp

    def is_alive(self):
        return self.proc is not None and self.proc.poll() is None

    def to_dict(self):
        return {
            "index":     self.index,
            "qnum":      self.qnum,
            "strategy":  self.strategy,
            "healthy":   self.healthy,
            "alive":     self.is_alive(),
            "started":   self.started,
            "pid":       self.proc.pid if self.proc else None,
        }


class PoolManager:

    def __init__(self, log_fn=None):
        self._lock   = threading.Lock()
        self._slots  = []          # list[Slot]
        self._log    = log_fn or (lambda lvl, msg: print("[pool][%s] %s" % (lvl, msg), flush=True))
        os.makedirs(POOL_RUN_DIR, exist_ok=True)

    # ── public ────────────────────────────────────────────────────────────

    def get_status(self):
        with self._lock:
            return [s.to_dict() for s in self._slots]

    def start_slot(self, index, strategy_name, nfqws_opt):
        """Запустить/перезапустить один слот."""
        with self._lock:
            slot = self._get_or_create(index)
            self._stop_slot_proc(slot)
            slot.strategy  = strategy_name
            slot.nfqws_opt = nfqws_opt
            self._start_slot_proc(slot)
            self._write_size()
        self._reload_fw()

    def stop_slot(self, index):
        """Остановить слот и убрать из пула."""
        with self._lock:
            slot = self._find(index)
            if slot:
                self._stop_slot_proc(slot)
                self._slots.remove(slot)
            self._write_size()
        self._reload_fw()

    def replace_slot(self, index, strategy_name, nfqws_opt):
        """
        Запустить новый nfqws2 в слоте не останавливая старый.
        Старый убиваем только после того как новый поднялся (1с grace).
        """
        with self._lock:
            slot = self._get_or_create(index)
            old_proc = slot.proc

            # Запускаем новый
            slot.strategy  = strategy_name
            slot.nfqws_opt = nfqws_opt
            slot.proc      = None
            self._start_slot_proc(slot)

        # Grace period — новый поднимается, старый ещё работает
        time.sleep(1)

        # Убиваем старый
        if old_proc and old_proc.poll() is None:
            try:
                old_proc.terminate()
                old_proc.wait(timeout=3)
            except Exception:
                try:
                    old_proc.kill()
                except Exception:
                    pass
        self._log("info", "Слот %d заменён на «%s» (graceful)" % (index, strategy_name))

    def set_slot_health(self, index, healthy):
        with self._lock:
            slot = self._find(index)
            if slot:
                slot.healthy = healthy

    def test_slot_isolated(self, index, url, timeout=12):
        """
        Изолированно тестирует один слот:
          1. Добавляет временное iptables правило: sport=TEST_SOCKS_BASE+index → NFQUEUE index
          2. Запускает временный ss-local на порту TEST_SOCKS_BASE+index
          3. Делает curl через этот ss-local
          4. Убирает правило и процесс
        Возвращает {"ok": bool, "rc": int, "output": str}
        """
        if _SS_SERVER_PORT is None:
            return {"ok": False, "rc": -1, "output": "SS_SERVER_PORT не задан"}

        test_port = TEST_SOCKS_BASE + index
        qnum      = QNUM_BASE + index

        # 1. Временное iptables правило: пакеты от test_port → строго NFQUEUE qnum
        #    Ставим с наивысшим приоритетом (INSERT) чтобы перекрыть random правила
        ipt_rule = [
            "POSTROUTING", "-t", "mangle",
            "-p", "tcp",
            "--sport", str(test_port),
            "-j", "NFQUEUE", "--queue-num", str(qnum), "--queue-bypass"
        ]
        def ipt(op):
            for cmd in (["iptables"], ["ip6tables"]):
                subprocess.run(cmd + [op] + ipt_rule,
                               capture_output=True, timeout=5)

        ipt("-I")

        # 2. Временный ss-local
        ss_proc = None
        if _SS_PASSWORD and _SS_METHOD:
            ss_cmd = [
                "ss-local",
                "-b", "127.0.0.1",
                "-l", str(test_port),
                "-s", "127.0.0.1",
                "-p", str(_SS_SERVER_PORT),
                "-k", _SS_PASSWORD,
                "-m", _SS_METHOD,
                "-t", "10",
            ]
            try:
                ss_proc = subprocess.Popen(
                    ss_cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                time.sleep(1.5)   # ждём пока ss-local поднимется
            except Exception as e:
                ipt("-D")
                return {"ok": False, "rc": -1, "output": "ss-local: %s" % e}
        else:
            # ss параметры неизвестны — тестируем через основной SOCKS порт
            # (менее точно, но лучше чем ничего)
            ipt("-D")
            return {"ok": False, "rc": -1,
                    "output": "SS_PASSWORD/SS_METHOD не заданы — изолированный тест недоступен"}

        # 3. curl через временный ss-local
        cmd = [
            "curl", "-x", "socks5h://127.0.0.1:%d" % test_port,
            url, "-I",
            "--max-time", str(timeout),
            "--connect-timeout", "8",
            "-s", "-S",
        ]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            out = (p.stdout or "") + (p.stderr or "")
            ok  = p.returncode == 0 and bool(re.search(r"HTTP/\S+ [23]", p.stdout))
            result = {"ok": ok, "rc": p.returncode, "output": out.strip()}
        except subprocess.TimeoutExpired:
            result = {"ok": False, "rc": -1, "output": "Таймаут %dс" % timeout}
        except Exception as e:
            result = {"ok": False, "rc": -1, "output": str(e)}

        # 4. Cleanup
        if ss_proc:
            try:
                ss_proc.terminate()
                ss_proc.wait(timeout=3)
            except Exception:
                try: ss_proc.kill()
                except Exception: pass
        ipt("-D")

        return result

    def stop_all(self):
        with self._lock:
            for slot in self._slots:
                self._stop_slot_proc(slot)
            self._slots.clear()
            self._write_size()
        self._reload_fw()

    def watchdog(self):
        """Перезапускает упавшие процессы. Вызывать периодически."""
        with self._lock:
            for slot in self._slots:
                if not slot.is_alive() and slot.nfqws_opt:
                    self._log("warn", "Слот %d (qnum=%d) упал, перезапускаю" % (slot.index, slot.qnum))
                    self._start_slot_proc(slot)

    def active_count(self):
        with self._lock:
            return len(self._slots)

    # ── internals ─────────────────────────────────────────────────────────

    def _find(self, index):
        return next((s for s in self._slots if s.index == index), None)

    def _get_or_create(self, index):
        slot = self._find(index)
        if not slot:
            slot = Slot(index)
            self._slots.append(slot)
            self._slots.sort(key=lambda s: s.index)
        return slot

    def _start_slot_proc(self, slot):
        if not slot.nfqws_opt:
            return
        cmd = [
            NFQWS2_BIN,
            "--qnum=%d" % slot.qnum,
            "--user=%s" % WS_USER,
            "--fwmark=%s" % DESYNC_MARK,
        ] + LUAOPT.split() + slot.nfqws_opt.strip().split("\n")

        self._log("info", "Слот %d старт: qnum=%d strategy=%s" % (
            slot.index, slot.qnum, slot.strategy or "custom"))
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            slot.proc    = proc
            slot.started = time.strftime("%H:%M:%S")
            slot.healthy = None
        except Exception as e:
            self._log("error", "Слот %d не запустился: %s" % (slot.index, e))

    def _stop_slot_proc(self, slot):
        if slot.proc and slot.proc.poll() is None:
            try:
                slot.proc.terminate()
                slot.proc.wait(timeout=5)
            except Exception:
                try:
                    slot.proc.kill()
                except Exception:
                    pass
        slot.proc    = None
        slot.healthy = None

    def _write_size(self):
        """Записывает текущий размер пула для custom.d fw скрипта."""
        size = len(self._slots)
        path = os.path.join(POOL_RUN_DIR, "size")
        try:
            with open(path, "w") as f:
                f.write(str(size) + "\n")
        except Exception as e:
            self._log("warn", "write size: %s" % e)

    def _reload_fw(self):
        """Перегружает iptables правила пула (вызывает zapret2 restart-fw)."""
        try:
            r = subprocess.run(
                [ZAPRET_INIT, "restart-fw"],
                capture_output=True, text=True, timeout=30
            )
            if r.returncode != 0:
                self._log("warn", "restart-fw rc=%d: %s" % (r.returncode, r.stderr.strip()[:120]))
            else:
                self._log("info", "Firewall перегружен (пул: %d слотов)" % len(self._slots))
        except Exception as e:
            self._log("error", "reload_fw: %s" % e)