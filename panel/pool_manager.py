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

import os, re, signal, subprocess, threading, time

NFQWS2_BIN     = "/opt/zapret2/nfq2/nfqws2"
ZAPRET_INIT    = "/opt/zapret2/init.d/sysv/zapret2"
POOL_RUN_DIR   = "/run/zapret-pool"
QNUM_BASE      = 300
MAX_SLOTS      = 10

# Из functions: NFQWS2_OPT_BASE добавляется автоматически zapret2.
# Мы запускаем nfqws2 напрямую — берём те же базовые опции.
LUAOPT = (
    "--lua-init=@/opt/zapret2/lua/zapret-lib.lua "
    "--lua-init=@/opt/zapret2/lua/zapret-antidpi.lua "
    "--lua-init=@/opt/zapret2/lua/zapret-auto.lua"
)
DESYNC_MARK    = os.environ.get("DESYNC_MARK", "0x40000000")
WS_USER        = "nobody"


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