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

DESYNC_MARK = os.environ.get("DESYNC_MARK", "0x40000000")
WS_USER     = "nobody"

_SOCKS_PORT     = None   # выставляется из main()


class Slot:
    def __init__(self, index):
        self.index       = index
        self.qnum        = QNUM_BASE + index
        self.strategy    = None
        self.nfqws_opt   = None
        self.proc        = None
        self.healthy     = None
        self.started     = None
        self._fw_excluded = False   # временно исключён из iptables rotation

    def is_alive(self):
        return self.proc is not None and self.proc.poll() is None

    def to_dict(self):
        return {
            "index":       self.index,
            "qnum":        self.qnum,
            "strategy":    self.strategy,
            "healthy":     self.healthy,
            "alive":       self.is_alive(),
            "started":     self.started,
            "pid":         self.proc.pid if self.proc else None,
            "fw_excluded": self._fw_excluded,
        }


class PoolManager:

    def __init__(self, log_fn=None):
        self._lock   = threading.Lock()
        self._slots  = []
        self._log    = log_fn or (lambda lvl, msg: print("[pool][%s] %s" % (lvl, msg), flush=True))
        self._prev_counters     = {}   # qnum → (pkts, bytes)
        self._prev_counter_time = None
        os.makedirs(POOL_RUN_DIR, exist_ok=True)

    # ── public ────────────────────────────────────────────────────────────

    def get_status(self):
        with self._lock:
            return [s.to_dict() for s in self._slots]

    def get_traffic_stats(self):
        """
        Читает счётчики пакетов/байт из цепочки ZAPRET_POOL.
        Возвращает dict: qnum → {pkts, bytes, pkts_delta, bytes_delta}
        Дельта считается относительно предыдущего вызова.
        """
        raw = self._read_zapret_pool_counters()
        now = time.time()
        result = {}
        with self._lock:
            prev      = self._prev_counters
            prev_time = self._prev_counter_time
            dt = now - prev_time if prev_time else 1.0
            dt = max(dt, 0.1)
            for qnum, (pkts, byt) in raw.items():
                pp, pb = prev.get(qnum, (0, 0))
                dpkts = max(0, pkts - pp)
                dbyt  = max(0, byt  - pb)
                result[qnum] = {
                    "pkts":       pkts,
                    "bytes":      byt,
                    "pkts_delta": dpkts,
                    "bytes_delta": dbyt,
                    "kbps":       round(dbyt * 8 / 1024 / dt, 1),
                    "pps":        round(dpkts / dt, 1),
                }
            self._prev_counters    = raw
            self._prev_counter_time = now
        return result

    def _read_zapret_pool_counters(self):
        """Парсит `iptables -t mangle -L ZAPRET_POOL -n -v -x`."""
        result = {}
        try:
            p = subprocess.run(
                ["iptables", "-t", "mangle", "-L", "ZAPRET_POOL", "-n", "-v", "-x"],
                capture_output=True, text=True, timeout=5
            )
            for line in p.stdout.splitlines():
                # Строка вида:  pkts bytes target ... NFQUEUE num 300 bypass
                m = re.search(r"^\s*(\d+)\s+(\d+)\s+NFQUEUE.*?num\s+(\d+)", line)
                if m:
                    pkts  = int(m.group(1))
                    byt   = int(m.group(2))
                    qnum  = int(m.group(3))
                    # Суммируем если один qnum встречается несколько раз (ipv4+ipv6)
                    existing = result.get(qnum, (0, 0))
                    result[qnum] = (existing[0] + pkts, existing[1] + byt)
        except Exception:
            pass
        return result

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
        Изолированный тест слота через временный захват трафика.
        На время теста весь трафик направляется в NFQUEUE этого слота.
        Основной random распределитель временно перекрывается правилом с -I.
        Даунтайм ~(timeout) секунд — вызывать только при деградации пула.
        """
        qnum = QNUM_BASE + index

        # Временное правило с наивысшим приоритетом перекрывает random
        capture_rule = [
            "POSTROUTING", "-t", "mangle",
            "-m", "mark", "!", "--mark", "%s/%s" % (DESYNC_MARK, DESYNC_MARK),
            "-j", "NFQUEUE", "--queue-num", str(qnum), "--queue-bypass"
        ]

        def ipt(op):
            for cmd in (["iptables"], ["ip6tables"]):
                try:
                    subprocess.run(cmd + [op] + capture_rule,
                                   capture_output=True, timeout=5)
                except Exception:
                    pass

        ipt("-I")
        try:
            cmd = [
                "curl", "-x", "socks5h://127.0.0.1:%d" % (_SOCKS_PORT or 1080),
                url, "-I",
                "--max-time", str(timeout),
                "--connect-timeout", "8",
                "-s", "-S",
            ]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            out = (p.stdout or "") + (p.stderr or "")
            ok  = p.returncode == 0 and bool(re.search(r"HTTP/\S+ [23]", p.stdout))
            return {"ok": ok, "rc": p.returncode, "output": out.strip()}
        except subprocess.TimeoutExpired:
            return {"ok": False, "rc": -1, "output": "Таймаут %dс" % timeout}
        except Exception as e:
            return {"ok": False, "rc": -1, "output": str(e)}
        finally:
            ipt("-D")

    def test_pool(self, url, timeout=12):
        """Быстрый тест пула целиком через основной SOCKS."""
        port = _SOCKS_PORT or 1080
        self._log("info", "test_pool: socks5h://127.0.0.1:%d → %s" % (port, url))
        cmd = [
            "curl", "-x", "socks5h://127.0.0.1:%d" % port,
            url, "-I",
            "--max-time", str(timeout),
            "--connect-timeout", "8",
            "-s", "-S",
        ]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            out = (p.stdout or "") + (p.stderr or "")
            ok  = p.returncode == 0 and bool(re.search(r"HTTP/\S+ [23]", p.stdout))
            self._log("info", "test_pool: rc=%d ok=%s" % (p.returncode, ok))
            return {"ok": ok, "rc": p.returncode, "output": out.strip()}
        except subprocess.TimeoutExpired:
            return {"ok": False, "rc": -1, "output": "Таймаут %dс" % timeout}
        except Exception as e:
            return {"ok": False, "rc": -1, "output": str(e)}

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

    def remove_slots_from_fw(self, indices):
        """
        Убирает указанные слоты из iptables rotation немедленно.
        Процессы nfqws2 остаются живыми — только fw правила меняются.
        """
        with self._lock:
            # Помечаем слоты как временно исключённые
            for slot in self._slots:
                if slot.index in indices:
                    slot._fw_excluded = True
            self._write_size()
        self._reload_fw()
        self._log("info", "Слоты %s убраны из rotation" % indices)

    def restore_slot_to_fw(self, index):
        """Возвращает слот в iptables rotation."""
        with self._lock:
            slot = self._find(index)
            if slot:
                slot._fw_excluded = False
            self._write_size()
        self._reload_fw()
        self._log("info", "Слот %d возвращён в rotation" % index)

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

        # Базовые аргументы
        cmd = [
            NFQWS2_BIN,
            "--qnum=%d" % slot.qnum,
            "--user=%s" % WS_USER,
            "--fwmark=%s" % DESYNC_MARK,
            "--lua-init=@/opt/zapret2/lua/zapret-lib.lua",
            "--lua-init=@/opt/zapret2/lua/zapret-antidpi.lua",
            "--lua-init=@/opt/zapret2/lua/zapret-auto.lua",
        ]

        # nfqws_opt — многострочная строка, каждая строка = отдельный --new профиль
        # Внутри строки аргументы разделены пробелами, но значения с = не трогаем
        import shlex
        for line in slot.nfqws_opt.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                cmd.extend(shlex.split(line))
            except ValueError:
                cmd.extend(line.split())

        self._log("info", "Слот %d старт: qnum=%d strategy=%s" % (
            slot.index, slot.qnum, slot.strategy or "custom"))
        self._log("info", "CMD: %s" % " ".join(cmd))

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            # Даём секунду и проверяем не упал ли сразу
            time.sleep(0.5)
            rc = proc.poll()
            if rc is not None:
                err = proc.stderr.read() if proc.stderr else ""
                self._log("error", "Слот %d упал сразу (rc=%d): %s" % (
                    slot.index, rc, err.strip()[:200]))
                slot.proc    = None
                slot.healthy = False
                return
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
        """Записывает активные (не исключённые) qnum для fw скрипта."""
        os.makedirs(POOL_RUN_DIR, exist_ok=True)
        slots_path = os.path.join(POOL_RUN_DIR, "slots")
        try:
            qnums = [str(s.qnum) for s in self._slots
                     if s.is_alive() and not s._fw_excluded]
            with open(slots_path, "w") as f:
                f.write("\n".join(qnums) + "\n" if qnums else "")
        except Exception as e:
            self._log("warn", "write slots: %s" % e)

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