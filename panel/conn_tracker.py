#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LifetimeTracker — отслеживает время жизни исходящих TCP-соединений (YouTube).

Опрашивает /proc/net/tcp (и tcp6) каждые poll_interval секунд, запоминает
first_seen для каждого нового HTTPS-соединения (remote port 443, не loopback).

Когда соединение исчезает (state перестаёт быть ESTABLISHED):
  - живёт < cut_min_sec                 -> считаем, что клиент сам закрыл -> игнор
  - живёт в [cut_min_sec, cut_max_sec]  -> «подозрительный срез» (ТСПУ)
  - живёт > cut_max_sec                 -> здоровое -> игнор

Подозрительный срез подтверждается reset-событием в логе ss-server
(чтобы не реагировать на закрытие вкладки пользователем). При
подтверждённом срезе вызывается on_cut(lifetime_sec).

Ограничения:
  - «YouTube» определяется как произвольное исходящее TCP:443 соединение
    (точной привязки к домену в /proc/net/tcp нет).
  - Точность времени жизни ± poll_interval.
"""

import collections
import os
import threading
import time


class LifetimeTracker:
    def __init__(self, ss_port, socks_port, panel_port=1888,
                 log_fn=None, poll_interval=2.0,
                 cut_min_sec=30, cut_max_sec=60,
                 require_reset=True, reset_window_sec=10.0,
                 proc_root=""):
        self.ss_port       = int(ss_port)
        self.socks_port    = int(socks_port)
        self.panel_port    = int(panel_port)
        self._proc_root    = proc_root   # для тестов: корень с fake proc/
        self._log = log_fn or (lambda lvl, msg: print("[tracker][%s] %s" % (lvl, msg), flush=True))

        self.poll_interval    = float(poll_interval)
        self.cut_min_sec      = float(cut_min_sec)
        self.cut_max_sec      = float(cut_max_sec)
        self.require_reset    = bool(require_reset)
        self.reset_window_sec = float(reset_window_sec)

        self._lock      = threading.RLock()   # RLock: _tick вложенно вызывает _has_recent_reset
        self._conns    = {}           # (local_port, remote_ip, remote_port) -> first_seen
        self._reset_ts = collections.deque(maxlen=50)  # метки reset из ss-server лога
        self._thread   = None
        self._stop_evt = threading.Event()

        self.on_cut = None            # callback fn(lifetime_sec)

        # «сессия YouTube» — период с активными :443 соединениями
        self._session_start  = None   # когда сессия началась
        self._last_activity  = None   # время последнего :443 соединения
        self._yt_active      = False  # есть ли сейчас :443 соединения
        self._yt_grace_sec   = 5      # пауза без :443 перед объявлением «сессия кончилась»

        # статус для UI
        self.active_conns      = 0
        self.tracked           = 0
        self.last_cut_lifetime = None
        self.last_cut_ts       = None
        self.total_cuts        = 0

    # ── public ─────────────────────────────────────────────────────────

    def start(self):
        print("[DIAG] tracker.start() called, ss_port=%s, socks_port=%s, panel_port=%s" % (
            self.ss_port, self.socks_port, self.panel_port), flush=True)
        if self._thread and self._thread.is_alive():
            return
        self._stop_evt.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        print("[DIAG] tracker thread started", flush=True)
        self._log("info", "Tracker запущен (poll=%ss, cut %d-%ds, require_reset=%s)" % (
            self.poll_interval, self.cut_min_sec, self.cut_max_sec, self.require_reset))

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
                            bool(cfg[k]) if k == "require_reset" else float(cfg[k]))
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
                "recent_resets":     len(self._reset_ts),
                "last_cut_lifetime": self.last_cut_lifetime,
                "last_cut_ts":       self.last_cut_ts,
                "total_cuts":        self.total_cuts,
                "yt_active":         self._yt_active,
                "session_start":     self._session_start,
                "last_activity":     self._last_activity,
            }

    # ── internals ──────────────────────────────────────────────────────

    def _tcp_paths(self):
        if self._proc_root:
            return [os.path.join(self._proc_root, n) for n in ("net/tcp", "net/tcp6")]
        return ["/proc/net/tcp", "/proc/net/tcp6"]

    def _read_tcp_conns(self):
        """
        Читает /proc/net/tcp и /proc/net/tcp6.
        Возвращает set кортежей (local_port, remote_ip, remote_port)
        для ESTABLISHED исходящих HTTPS-соединений (remote :443, не loopback).
        """
        result = set()
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
                if len(parts) < 4:
                    continue
                if parts[3] != "01":   # 01 = ESTABLISHED
                    continue
                try:
                    local       = parts[1].split(":")
                    remote      = parts[2].split(":")
                    local_port  = int(local[1], 16)
                    remote_ip   = remote[0]
                    remote_port = int(remote[1], 16)
                except (ValueError, IndexError):
                    continue
                # только исходящие на внешние адреса:443
                if remote_port != 443:
                    continue
                if first_tick:
                    is_excluded = (
                        remote_ip in ("00000000", "00000000000000000000000000000000",
                                      "0100007F", "00000000000000000000000001000000") or
                        local_port in (self.ss_port, self.socks_port, self.panel_port)
                    )
                    print("[DIAG] :443 ESTABLISHED: local_port=%d remote=%s:%d (%s)" % (
                        local_port, remote_ip, remote_port,
                        "EXCLUDED" if is_excluded else "TRACKED"), flush=True)
                if remote_ip in ("00000000", "00000000000000000000000000000000",
                                 "0100007F", "00000000000000000000000001000000"):
                    continue
                if local_port in (self.ss_port, self.socks_port, self.panel_port):
                    continue   # входящие на наши слушающие порты
                result.add((local_port, remote_ip, remote_port))
        return result

    def _loop(self):
        while not self._stop_evt.is_set():
            try:
                self._tick()
            except Exception as e:
                self._log("error", "tick: %s" % e)
            self._stop_evt.wait(timeout=self.poll_interval)

    def _tick(self):
        now   = time.time()
        conns = self._read_tcp_conns()
        yt_active = len(conns) > 0
        
        print("[DIAG] tick: found %d :443 conns" % len(conns), flush=True)

        need_cut = False
        cut_lifetime = 0.0

        with self._lock:
            # Обновляем сессию YouTube
            if yt_active:
                if self._session_start is None:
                    self._session_start = now
                    print("[DIAG] YouTube session START", flush=True)
                self._last_activity = now
                self._yt_active = True
            else:
                self._yt_active = False
                # Проверяем: активность пропала на сколько секунд?
                if self._last_activity is not None and self._session_start is not None:
                    idle_time = now - self._last_activity
                    session_duration = self._last_activity - self._session_start
                    
                    if idle_time >= self._yt_grace_sec:
                        # Активность пропала на grace_sec — сессия может быть оборвана
                        print("[DIAG] YouTube inactive for %.1fs (session was %.1fs)" % (
                            idle_time, session_duration), flush=True)
                        
                        if session_duration >= self.cut_min_sec:
                            # Сессия длилась достаточно долго → потенциальный срез
                            cut_lifetime = session_duration + idle_time
                            if not self.require_reset or self._has_recent_reset(now):
                                need_cut = True
                            else:
                                print("[DIAG] Срез не подтверждён reset-ом (require_reset=True)", flush=True)
                        
                        # Сбрасываем сессию
                        self._session_start = None
                        self._last_activity = None
            
            self.active_conns = len(conns)
            self.tracked = len(conns)

        if need_cut:
            self._do_cut(cut_lifetime)

    def _has_recent_reset(self, now):
        """Проверяет, был ли reset в логе ss-server недавно."""
        with self._lock:
            reset_ts = list(self._reset_ts)
        for rs in reset_ts:
            # reset может прийти до исчезновения :443, или сразу после
            if -self.poll_interval * 2 - 5 <= (rs - now) <= self.reset_window_sec * 3:
                return True
        return False

    def _do_cut(self, lifetime):
        """Выполняет срез: обновляет статус и вызывает on_cut callback."""
        now = time.time()
        with self._lock:
            self.last_cut_lifetime = round(lifetime, 1)
            self.last_cut_ts = now
            self.total_cuts += 1
            cb = self.on_cut
        self._log("warn", "⚡ Срез сессии YouTube: активность была %.1fs — вызываю on_cut" % lifetime)
        if cb:
            try:
                cb(lifetime)
            except Exception as e:
                self._log("error", "on_cut: %s" % e)