#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Детектор блокировки ТСПУ.

Каждые poll_interval секунд читает /proc/net/tcp{,6} и следит за
исходящими HTTPS-соединениями (remote :443, не loopback).

Отличие «резкой смерти» (RST) от обычного закрытия (FIN):

  - FIN: уход из ESTABLISHED через FIN_WAIT*/CLOSE_WAIT/LAST_ACK/TIME_WAIT;
    такие закрытия считаются отдельно и НЕ являются срезом.
  - RST: соединение было ESTABLISHED в прошлом тике и исчезло,
    либо сразу перешло в CLOSE/CLOSING без FIN-промежуточных состояний.

Два триггера «среза ТСПУ»:
   1. Классический: одиночная RST-смерть с lifetime в [cut_min_sec, cut_max_sec].
   2. Эпидемия: за скользящее окно epidemic_window_sec набралось
       >= epidemic_min_events RST-смертей (живших >= short_min_sec)
       — ловит повторяющиеся обрывы, когда плеер сразу переподключается.

При срезе вызывается on_cut(event), где event — dict с полями:
    kind, lifetime_sec, conn, rst_deaths_window, fin_deaths_window, reset_confirmed.
"""

import collections
import os
import threading
import time


class LifetimeTracker:
    def __init__(self, ss_port, socks_port, panel_port=1888,
                 log_fn=None, poll_interval=2.0,
                 cut_min_sec=30, cut_max_sec=60,
                 require_reset=False, reset_window_sec=10.0,
                 epidemic_min_events=4, short_min_sec=5,
                 epidemic_window_sec=60, proc_root=""):
        self.ss_port       = int(ss_port)
        self.socks_port    = int(socks_port)
        self.panel_port    = int(panel_port)
        self._proc_root    = proc_root   # для тестов: корень с fake proc/
        self._log = log_fn or (lambda lvl, msg: print("[tracker][%s] %s" % (lvl, msg), flush=True))

        self.poll_interval       = float(poll_interval)
        self.cut_min_sec         = float(cut_min_sec)
        self.cut_max_sec         = float(cut_max_sec)
        self.require_reset       = bool(require_reset)
        self.reset_window_sec    = float(reset_window_sec)
        self.epidemic_min_events = max(2, int(epidemic_min_events))
        self.short_min_sec       = max(2, float(short_min_sec))
        self.epidemic_window_sec = max(20, int(epidemic_window_sec))

        self._lock       = threading.RLock()
        self._conns      = {}               # conn -> {"first":ts,"last":ts,"state":st}
        self._deaths     = collections.deque(maxlen=300)  # RST-смерти: (ts,lifetime,conn)
        self._fin_deaths = collections.deque(maxlen=300)  # FIN-закрытия: ts
        self._reset_ts   = collections.deque(maxlen=50)
        self._thread     = None
        self._stop_evt   = threading.Event()
        self._last_death_ts = None   # ts последней RST-смерти, обработанной классическим триггером

        self.on_cut = None            # callback fn(event_dict)

        # статус для UI
        self.active_conns       = 0
        self.tracked           = 0
        self.rst_deaths_window = 0
        self.fin_deaths_window = 0
        self.last_cut_lifetime = None
        self.last_cut_ts       = None
        self.last_cut_conn     = None
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
        self._log("info", "Детектор ТСПУ запущен (poll=%ss, cut %s-%ss, epi>=%s/%ss, require_reset=%s)" % (
            self.poll_interval, self.cut_min_sec, self.cut_max_sec,
            self.epidemic_min_events, self.epidemic_window_sec, self.require_reset))

    def stop(self):
        self._stop_evt.set()

    def note_reset(self):
        """Вызывается из ResetMonitor при событии reset в ss-server логе."""
        with self._lock:
            self._reset_ts.append(time.time())

    def configure(self, cfg):
        with self._lock:
            for k in ("cut_min_sec", "cut_max_sec", "require_reset",
                      "poll_interval", "reset_window_sec",
                      "epidemic_min_events", "short_min_sec",
                      "epidemic_window_sec"):
                if k in cfg and cfg[k] is not None:
                    if k == "require_reset":
                        setattr(self, k, bool(cfg[k]))
                    elif k == "epidemic_min_events":
                        setattr(self, k, max(2, int(cfg[k])))
                    elif k == "epidemic_window_sec":
                        setattr(self, k, max(20, int(cfg[k])))
                    elif k == "short_min_sec":
                        setattr(self, k, max(2, float(cfg[k])))
                    else:
                        setattr(self, k, float(cfg[k]))
            # защитная нормализация границ среза (swap + клампы)
            lo = min(self.cut_min_sec, self.cut_max_sec)
            hi = max(self.cut_min_sec, self.cut_max_sec)
            self.cut_min_sec = max(5.0, lo)
            self.cut_max_sec = max(max(10.0, hi), self.cut_min_sec)
        return self.get_status()

    def get_status(self):
        with self._lock:
            return {
                "active_conns":        self.active_conns,
                "tracked":             self.tracked,
                "poll_interval":       self.poll_interval,
                "cut_min_sec":        self.cut_min_sec,
                "cut_max_sec":        self.cut_max_sec,
                "require_reset":      self.require_reset,
                "reset_window_sec":   self.reset_window_sec,
                "epidemic_min_events": self.epidemic_min_events,
                "short_min_sec":        self.short_min_sec,
                "epidemic_window_sec": self.epidemic_window_sec,
                "recent_resets":       len(self._reset_ts),
                "rst_deaths_window":   self.rst_deaths_window,
                "fin_deaths_window":   self.fin_deaths_window,
                "last_cut_lifetime":   self.last_cut_lifetime,
                "last_cut_ts":         self.last_cut_ts,
                "last_cut_conn":       self.last_cut_conn,
                "total_cuts":          self.total_cuts,
            }

    # ── internals ────────────────────────────────────────────────────────

    def _tcp_paths(self):
        if self._proc_root:
            return [os.path.join(self._proc_root, n) for n in ("net/tcp", "net/tcp6")]
        return ["/proc/net/tcp", "/proc/net/tcp6"]

    def _read_tcp_conns(self):
        """
        Читает /proc/net/tcp и /proc/net/tcp6.

        Возвращает dict: conn -> state hex для всех состояний.
        conn=(local_port, remote_ip, remote_port). Оставляет только
        исходящие на внешние адреса:443, исключая наши слушающие порты.
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
                if len(parts) < 4:
                    continue
                try:
                    local        = parts[1].split(":")
                    remote       = parts[2].split(":")
                    local_port   = int(local[1], 16)
                    remote_ip    = remote[0]
                    remote_port  = int(remote[1], 16)
                    st           = parts[3]
                except (ValueError, IndexError):
                    continue
                if remote_port != 443:
                    continue
                if remote_ip in ("00000000", "00000000000000000000000000000000",
                                "0100007F", "00000000000000000000000001000000"):
                    continue
                if local_port in (self.ss_port, self.socks_port, self.panel_port):
                    continue
                result[(local_port, remote_ip, remote_port)] = st
        return result

    def _loop(self):
        while not self._stop_evt.is_set():
            try:
                self._tick()
            except Exception as e:
                self._log("error", "tick: %s" % e)
            self._stop_evt.wait(timeout=self.poll_interval)

    def _tick(self):
        now    = time.time()
        states = self._read_tcp_conns()
        est_now = sum(1 for st in states.values() if st == "01")

        need_cut  = False
        cut_event = None

        with self._lock:
            prev_ = {c: dict(v) for c, v in self._conns.items()}
            self._analyze_transitions(prev_, states, now)

            # скользящее окно RST-смертей: чистим старые
            cutoff = now - self.epidemic_window_sec
            while self._deaths and self._deaths[0][0] < cutoff:
                self._deaths.popleft()
            while self._fin_deaths and self._fin_deaths[0] < cutoff:
                self._fin_deaths.popleft()
            self.rst_deaths_window = len(self._deaths)
            self.fin_deaths_window = len(self._fin_deaths)

            # 1. классический триггер: свежая одиночная RST-смерть в нужном диапазоне
            new_death = None
            if self._deaths and self._deaths[-1][0] != self._last_death_ts:
                ts, lt, dc = self._deaths[-1]
                self._last_death_ts = ts
                if self.cut_min_sec <= lt <= self.cut_max_sec:
                    new_death = (lt, dc)

            # 2. эпидемия: много RST-смертей за окно
            epi = (self.rst_deaths_window >= self.epidemic_min_events)

            # подтверждение reset-событием (опционально)
            confirmed = (not self.require_reset) or self._has_recent_reset(now)
            if confirmed:
                if new_death is not None:
                    lt, dc = new_death
                    need_cut = True
                    cut_event = {
                        "kind": "classic",
                        "lifetime_sec": round(lt, 1),
                        "conn": dc,
                        "rst_deaths_window": self.rst_deaths_window,
                        "fin_deaths_window": self.fin_deaths_window,
                        "reset_confirmed": True,
                    }
                elif epi:
                    ts, lt, dc = self._deaths[-1]
                    need_cut = True
                    cut_event = {
                        "kind": "epidemic",
                        "lifetime_sec": round(lt, 1),
                        "conn": dc,
                        "rst_deaths_window": self.rst_deaths_window,
                        "fin_deaths_window": self.fin_deaths_window,
                        "reset_confirmed": True,
                    }
                    self._deaths.clear()      # один срез на эпизод
                    self._last_death_ts = None
            else:
                if new_death is not None:
                    self._log("info", "Классический срез(%.1fs) не подтверждён reset-событием"
                             % new_death[0])

            # обновить известные соединения
            for c, st in states.items():
                if c in self._conns:
                    v = self._conns[c]
                    v["last"]  = now
                    v["state"] = st
                else:
                    self._conns[c] = {"first": now, "last": now, "state": st}
            for c in list(self._conns):
                if c not in states:
                    self._conns.pop(c, None)

            self.active_conns = est_now
            self.tracked      = len(self._conns)

        if need_cut and cut_event is not None:
            self._do_cut(cut_event)

    def _analyze_transitions(self, prev_states, states, now):
        """
        Переходы из ESTABLISHED в другие состояния.

        RST-смерть: соединение исчезло совсем или ушло сразу в CLOSE(07)/
        CLOSING(0B) без FIN-промежуточных состояний (04/05/06/08/09).
        FIN-закрытия считаются отдельно и не являются срезом.
        """
        for c, info in prev_states.items():
            prev_state = info["state"]
            if prev_state != "01":
                continue
            cur_state = states.get(c)
            if cur_state == "01":
                continue
            lifetime = now - info["first"]
            if (cur_state is None) or (cur_state in ("07", "0B")):
                if lifetime >= self.short_min_sec:
                    self._deaths.append((now, lifetime, c))
            elif cur_state in ("04", "05", "06", "08", "09"):
                self._fin_deaths.append(now)
            # прочие (SYN_SENT и т.п.) — игнор

    def _has_recent_reset(self, now):
        """Было ли reset-событие из ss-server лога недавно."""
        with self._lock:
            for rs in self._reset_ts:
                if now - rs <= self.reset_window_sec:
                    return True
        return False

    def _do_cut(self, event):
        """Выполняет срез: обновляет статус и вызывает on_cut callback."""
        now = time.time()
        with self._lock:
            self.last_cut_lifetime = event["lifetime_sec"]
            self.last_cut_ts       = now
            self.last_cut_conn     = event.get("conn")
            self.total_cuts       += 1
            cb = self.on_cut
        self._log("warn", "⚡ Срез ТСПУ(%s): соединение прожило %.1fs — вызываю on_cut" % (
            event["kind"], event["lifetime_sec"]))
        if cb:
            try:
                cb(event)
            except Exception as e:
                self._log("error", "on_cut: %s" % e)


if __name__ == "__main__":
    # быстрый самопроверочный запуск (без реального /proc — только статус)
    t = LifetimeTracker(8388, 1080, 1888)
    print("status OK" if "total_cuts" in t.get_status() else "status FAIL")