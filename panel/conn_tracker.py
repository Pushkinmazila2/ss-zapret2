#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LifetimeTracker — отслеживает время жизни исходящих TCP-соединений.

Детектирует три типа блокировки ТСПУ:

  1. RST-срез (cut_type="rst")
     Соединение прожило cut_min_sec..cut_max_sec, затем получило TCP RST
     (ss-server пишет "Connection reset by peer" или "server_recv_cb_recv").
     Это классический и самый быстрый срез ТСПУ.

  2. Тихий дроп / throttle (cut_type="idle")
     Соединение ESTABLISHED, но байт через него не шло больше idle_threshold_sec.
     ТСПУ просто дропает пакеты без RST — соединение «зависает» до SS_TIMEOUT.
     Детект: /proc/net/tcp не даёт счётчик байт напрямую; используем
     /proc/net/sockstat + per-socket /proc/self/net/tcp через inode-сопоставление
     со счётчиками в /proc/net/tcp_diag (если доступно), иначе — косвенно
     через отсутствие изменения tx_queue/rx_queue в /proc/net/tcp за N тиков.

  3. Деградация (delegated to ResetMonitor в server.py)
     Учитывается отдельно через ratio RST/close.

Архитектура:
  - _read_tcp_conns()  — снимок ESTABLISHED :443 (как раньше)
  - _read_queue_map()  — snимок (local_port, remote) → (tx_queue, rx_queue)
  - _tick()            — сравнивает очереди между тиками, детектирует idle
  - on_cut(lifetime, cut_type)  — единый колбэк для обоих типов среза
  - TspuLog            — пишет структурированные события в tspу.log
"""

import collections
import os
import threading
import time

try:
    from tspу_log import get_log as _get_tlog
except ImportError:
    _get_tlog = None


# ── константы ────────────────────────────────────────────────────────

# Через сколько тиков без изменения очередей считаем соединение «мёртвым»
IDLE_TICKS = 5   # 5 × poll_interval (по умолчанию 2с → 10с idle)

# Минимальное время жизни соединения перед тем как idle считается подозрительным.
# Короткие соединения (< idle_min_lifetime_sec) игнорируем — они могут быть
# просто keepalive или маленькие запросы, которые быстро закрылись.
IDLE_MIN_LIFETIME = 15.0   # сек


class LifetimeTracker:
    def __init__(self, ss_port, socks_port, panel_port=1888,
                 log_fn=None, poll_interval=2.0,
                 cut_min_sec=30, cut_max_sec=60,
                 require_reset=True, reset_window_sec=10.0,
                 idle_threshold_sec=None,
                 proc_root=""):
        self.ss_port       = int(ss_port)
        self.socks_port    = int(socks_port)
        self.panel_port    = int(panel_port)
        self._proc_root    = proc_root
        self._log = log_fn or (lambda lvl, msg: print(
            "[tracker][%s] %s" % (lvl, msg), flush=True))

        self.poll_interval    = float(poll_interval)
        self.cut_min_sec      = float(cut_min_sec)
        self.cut_max_sec      = float(cut_max_sec)
        self.require_reset    = bool(require_reset)
        self.reset_window_sec = float(reset_window_sec)

        # idle_threshold_sec: сколько секунд без изменения очередей → idle-дроп
        # None = автоматически: IDLE_TICKS × poll_interval
        self._idle_threshold  = (float(idle_threshold_sec)
                                 if idle_threshold_sec is not None
                                 else IDLE_TICKS * self.poll_interval)

        self._lock      = threading.RLock()
        self._conns     = {}   # key → first_seen
        self._queues    = {}   # key → {"tx": int, "rx": int, "idle_ticks": int,
                               #         "first_seen": float, "last_changed": float}
        self._reset_ts  = collections.deque(maxlen=50)
        self._thread    = None
        self._stop_evt  = threading.Event()

        # колбэки
        # on_cut(lifetime, cut_type) — cut_type: "rst" | "idle"
        self.on_cut = None

        # статистика для UI
        self.active_conns      = 0
        self.tracked           = 0
        self.last_cut_lifetime = None
        self.last_cut_ts       = None
        self.total_cuts        = 0
        self.total_idle_cuts   = 0   # отдельный счётчик idle-дропов
        self.total_rst_cuts    = 0

        # сессионный трекер (как раньше — для среза по сессии)
        self._session_start  = None
        self._last_activity  = None
        self._yt_active      = False
        self._yt_grace_sec   = 5

        # ТСПУ лог
        self._tlog = _get_tlog() if _get_tlog else None

    # ── public ───────────────────────────────────────────────────────

    def start(self):
        print("[DIAG] tracker.start() ss=%s socks=%s panel=%s" % (
            self.ss_port, self.socks_port, self.panel_port), flush=True)
        if self._thread and self._thread.is_alive():
            return
        self._stop_evt.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        print("[DIAG] tracker thread started", flush=True)
        self._log("info",
            "Tracker запущен (poll=%.1fс, cut %d-%dс, idle=%.1fс, require_reset=%s)" % (
                self.poll_interval, self.cut_min_sec, self.cut_max_sec,
                self._idle_threshold, self.require_reset))

    def stop(self):
        self._stop_evt.set()

    def note_reset(self):
        """Вызывается из ResetMonitor при событии reset в ss-server логе."""
        with self._lock:
            self._reset_ts.append(time.time())

    def configure(self, cfg):
        with self._lock:
            for k in ("cut_min_sec", "cut_max_sec", "require_reset",
                      "poll_interval", "reset_window_sec"):
                if k in cfg and cfg[k] is not None:
                    setattr(self, k,
                            bool(cfg[k]) if k == "require_reset"
                            else float(cfg[k]))
            if "idle_threshold_sec" in cfg and cfg["idle_threshold_sec"] is not None:
                self._idle_threshold = float(cfg["idle_threshold_sec"])
        return self.get_status()

    def get_status(self):
        with self._lock:
            return {
                "active_conns":      self.active_conns,
                "tracked":           self.tracked,
                "poll_interval":     self.poll_interval,
                "cut_min_sec":       self.cut_min_sec,
                "cut_max_sec":       self.cut_max_sec,
                "require_reset":     self.require_reset,
                "reset_window_sec":  self.reset_window_sec,
                "idle_threshold_sec": self._idle_threshold,
                "recent_resets":     len(self._reset_ts),
                "last_cut_lifetime": self.last_cut_lifetime,
                "last_cut_ts":       self.last_cut_ts,
                "total_cuts":        self.total_cuts,
                "total_rst_cuts":    self.total_rst_cuts,
                "total_idle_cuts":   self.total_idle_cuts,
                "yt_active":         self._yt_active,
                "session_start":     self._session_start,
                "last_activity":     self._last_activity,
            }

    # ── internals ────────────────────────────────────────────────────

    def _tcp_paths(self):
        if self._proc_root:
            return [os.path.join(self._proc_root, n)
                    for n in ("net/tcp", "net/tcp6")]
        return ["/proc/net/tcp", "/proc/net/tcp6"]

    def _read_tcp_conns(self):
        """
        Читает /proc/net/tcp и /proc/net/tcp6.
        Возвращает dict:
          (local_port, remote_ip, remote_port) → {"tx": int, "rx": int}
        для ESTABLISHED исходящих HTTPS (remote :443, не loopback).

        Колонки /proc/net/tcp:
          sl  local_addr  rem_addr  st  tx_queue:rx_queue  ...
          0   1           2         3   4                   ...
        tx_queue:rx_queue — hex, байт в буфере отправки/приёма ядра.
        """
        result = {}
        first_tick = not hasattr(self, "_diag_logged")
        if first_tick:
            self._diag_logged = True

        for path in self._tcp_paths():
            try:
                with open(path) as f:
                    lines = f.readlines()
            except (OSError, IOError) as e:
                if first_tick:
                    print("[DIAG] cannot read %s: %s" % (path, e), flush=True)
                continue

            if first_tick:
                print("[DIAG] read %s: %d lines" % (path, len(lines)), flush=True)

            for line in lines[1:]:
                parts = line.split()
                if len(parts) < 5:
                    continue
                if parts[3] != "01":   # 01 = ESTABLISHED
                    continue
                try:
                    local       = parts[1].split(":")
                    remote      = parts[2].split(":")
                    local_port  = int(local[1], 16)
                    remote_ip   = remote[0]
                    remote_port = int(remote[1], 16)
                    # tx_queue:rx_queue
                    qparts = parts[4].split(":")
                    tx_q = int(qparts[0], 16)
                    rx_q = int(qparts[1], 16) if len(qparts) > 1 else 0
                except (ValueError, IndexError):
                    continue

                if remote_port != 443:
                    continue
                # исключаем loopback и свои порты
                if remote_ip in ("00000000",
                                 "00000000000000000000000000000000",
                                 "0100007F",
                                 "00000000000000000000000001000000"):
                    continue
                if local_port in (self.ss_port, self.socks_port, self.panel_port):
                    continue

                key = (local_port, remote_ip, remote_port)
                result[key] = {"tx": tx_q, "rx": rx_q}

        return result

    def _loop(self):
        while not self._stop_evt.is_set():
            try:
                self._tick()
            except Exception as e:
                self._log("error", "tick: %s" % e)
            self._stop_evt.wait(timeout=self.poll_interval)

    def _tick(self):
        now     = time.time()
        conns   = self._read_tcp_conns()   # key → {tx, rx}
        yt_active = len(conns) > 0

        # ── обновляем очереди и детектим idle ────────────────────────

        idle_cuts = []   # [(key, lifetime, idle_sec)]

        with self._lock:
            new_queues = {}

            for key, qvals in conns.items():
                tx, rx = qvals["tx"], qvals["rx"]
                prev = self._queues.get(key)

                if prev is None:
                    # новое соединение
                    new_queues[key] = {
                        "tx":           tx,
                        "rx":           rx,
                        "idle_ticks":   0,
                        "first_seen":   now,
                        "last_changed": now,
                    }
                else:
                    # сравниваем очереди с предыдущим тиком
                    changed = (tx != prev["tx"] or rx != prev["rx"])
                    idle_ticks = 0 if changed else prev["idle_ticks"] + 1
                    last_changed = now if changed else prev["last_changed"]

                    new_queues[key] = {
                        "tx":           tx,
                        "rx":           rx,
                        "idle_ticks":   idle_ticks,
                        "first_seen":   prev["first_seen"],
                        "last_changed": last_changed,
                    }

                    # детект тихого дропа
                    lifetime  = now - prev["first_seen"]
                    idle_sec  = now - last_changed

                    if (idle_sec >= self._idle_threshold
                            and lifetime >= IDLE_MIN_LIFETIME
                            and idle_ticks == IDLE_TICKS):
                        # срабатываем ровно один раз при пересечении порога
                        idle_cuts.append((key, lifetime, idle_sec))

            # удалённые соединения — обработаем ниже через сессию
            self._queues = new_queues

            # ── сессия ───────────────────────────────────────────────
            if yt_active:
                if self._session_start is None:
                    self._session_start = now
                self._last_activity = now
                self._yt_active = True
            else:
                self._yt_active = False
                if (self._last_activity is not None
                        and self._session_start is not None):
                    idle_time        = now - self._last_activity
                    session_duration = self._last_activity - self._session_start

                    if idle_time >= self._yt_grace_sec:
                        if session_duration >= self.cut_min_sec:
                            # RST-срез: сессия прожила cut_min..cut_max и оборвалась
                            lifetime = session_duration + idle_time
                            if (not self.require_reset
                                    or self._has_recent_reset(now)):
                                self._do_cut(lifetime, cut_type="rst")
                        self._session_start = None
                        self._last_activity = None

            self.active_conns = len(conns)
            self.tracked      = len(conns)

        # ── idle-дропы вне лока ───────────────────────────────────────
        for key, lifetime, idle_sec in idle_cuts:
            self._do_idle_drop(lifetime, idle_sec)

    def _has_recent_reset(self, now):
        with self._lock:
            reset_ts = list(self._reset_ts)
        for rs in reset_ts:
            if -self.poll_interval * 2 - 5 <= (rs - now) <= self.reset_window_sec * 3:
                return True
        return False

    def _do_cut(self, lifetime, cut_type="rst"):
        """RST-срез: классический детект по времени сессии + TCP RST."""
        now = time.time()
        with self._lock:
            self.last_cut_lifetime = round(lifetime, 1)
            self.last_cut_ts       = now
            self.total_cuts       += 1
            self.total_rst_cuts   += 1
            cb = self.on_cut

        self._log("warn",
            "✂ RST-срез ТСПУ: сессия %.1fс" % lifetime)

        if self._tlog:
            self._tlog.cut(lifetime=lifetime, cut_type=cut_type)

        if cb:
            try:
                cb(lifetime)
            except Exception as e:
                self._log("error", "on_cut(rst): %s" % e)

    def _do_idle_drop(self, lifetime, idle_sec):
        """
        Тихий дроп: трафик встал на idle_sec при живом ESTABLISHED соединении.
        ТСПУ дропает пакеты без RST; соединение зависает до таймаута SS.
        """
        now = time.time()
        with self._lock:
            self.last_cut_lifetime = round(lifetime, 1)
            self.last_cut_ts       = now
            self.total_cuts       += 1
            self.total_idle_cuts  += 1
            cb = self.on_cut

        self._log("warn",
            "⏸ Тихий дроп ТСПУ: трафик встал на %.1fс (соединение живёт %.1fс)"
            % (idle_sec, lifetime))

        if self._tlog:
            self._tlog.idle_drop(lifetime=lifetime, idle_sec=idle_sec)

        if cb:
            try:
                cb(lifetime)
            except Exception as e:
                self._log("error", "on_cut(idle): %s" % e)