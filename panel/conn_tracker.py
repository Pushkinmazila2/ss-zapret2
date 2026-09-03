#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
conn_tracker.py  -  LifetimeTracker

Detects two TSPУ block patterns:

  1. RST drop (cut_type="rst")
     Connection lived cut_min_sec..cut_max_sec, then received TCP RST.
     Detected via: session lifetime tracking + ResetMonitor.note_reset().

  2. Silent drop / throttle (cut_type="idle")
     Connection stays ESTABLISHED but tx_queue and rx_queue in /proc/net/tcp
     do not change for idle_threshold_sec.  TSPУ drops packets without RST.

Both types call  on_cut(lifetime, cut_type)  and write to tspу_log with
full context (tx_queue, rx_queue, idle_sec, active_conns).
"""

import collections
import os
import threading
import time

try:
    from tspу_log import get_log as _get_tlog, conn_ctx, slot_ctx, monitor_ctx
except ImportError:
    _get_tlog = None
    def conn_ctx(**kw): return kw
    def slot_ctx(**kw): return kw
    def monitor_ctx(**kw): return kw

# How many consecutive ticks with unchanged queues = silent drop.
IDLE_TICKS = 5

# Connections younger than this are not considered for idle detection.
IDLE_MIN_LIFETIME = 15.0


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
        self._idle_threshold  = (float(idle_threshold_sec)
                                 if idle_threshold_sec is not None
                                 else IDLE_TICKS * self.poll_interval)

        self._lock      = threading.RLock()
        self._queues    = {}   # key -> {tx, rx, idle_ticks, first_seen, last_changed}
        self._reset_ts  = collections.deque(maxlen=50)
        self._thread    = None
        self._stop_evt  = threading.Event()

        # on_cut(lifetime, cut_type)  -  cut_type: "rst" | "idle"
        self.on_cut = None

        # stats
        self.active_conns      = 0
        self.tracked           = 0
        self.last_cut_lifetime = None
        self.last_cut_ts       = None
        self.total_cuts        = 0
        self.total_rst_cuts    = 0
        self.total_idle_cuts   = 0

        # session tracking (for RST detection)
        self._session_start  = None
        self._last_activity  = None
        self._yt_active      = False
        self._yt_grace_sec   = 5

        self._tlog = _get_tlog() if _get_tlog else None

        # pool_manager reference - set by server.py after init
        # used to enrich idle events with slot context
        self.pool_ref   = None
        self.monitor_ref = None

    # ------------------------------------------------------------------ #
    # Public                                                               #
    # ------------------------------------------------------------------ #

    def start(self):
        print("[tracker] start ss=%s socks=%s panel=%s idle_thresh=%.1fs" % (
            self.ss_port, self.socks_port, self.panel_port, self._idle_threshold),
            flush=True)
        if self._thread and self._thread.is_alive():
            return
        self._stop_evt.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self._log("info",
            "tracker started poll=%.1fs cut=%d-%ds idle=%.1fs require_reset=%s" % (
                self.poll_interval, self.cut_min_sec, self.cut_max_sec,
                self._idle_threshold, self.require_reset))

    def stop(self):
        self._stop_evt.set()

    def note_reset(self):
        """Called by ResetMonitor on each reset event from ss-server log."""
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
                "active_conns":       self.active_conns,
                "tracked":            self.tracked,
                "poll_interval":      self.poll_interval,
                "cut_min_sec":        self.cut_min_sec,
                "cut_max_sec":        self.cut_max_sec,
                "require_reset":      self.require_reset,
                "reset_window_sec":   self.reset_window_sec,
                "idle_threshold_sec": self._idle_threshold,
                "recent_resets":      len(self._reset_ts),
                "last_cut_lifetime":  self.last_cut_lifetime,
                "last_cut_ts":        self.last_cut_ts,
                "total_cuts":         self.total_cuts,
                "total_rst_cuts":     self.total_rst_cuts,
                "total_idle_cuts":    self.total_idle_cuts,
                "yt_active":          self._yt_active,
                "session_start":      self._session_start,
                "last_activity":      self._last_activity,
            }

    # ------------------------------------------------------------------ #
    # Internal                                                             #
    # ------------------------------------------------------------------ #

    def _tcp_paths(self):
        if self._proc_root:
            return [os.path.join(self._proc_root, n)
                    for n in ("net/tcp", "net/tcp6")]
        return ["/proc/net/tcp", "/proc/net/tcp6"]

    def _read_tcp_conns(self):
        """
        Read /proc/net/tcp{,6}.
        Returns dict: (local_port, remote_ip, remote_port) -> {tx, rx}
        tx/rx = tx_queue:rx_queue from column 4 (hex kernel socket buffers).
        Only ESTABLISHED (state=01), remote port 443, non-loopback.
        """
        result = {}
        first = not hasattr(self, "_diag_logged")
        if first:
            self._diag_logged = True

        for path in self._tcp_paths():
            try:
                with open(path) as f:
                    lines = f.readlines()
            except (OSError, IOError) as e:
                if first:
                    print("[tracker] cannot read %s: %s" % (path, e), flush=True)
                continue
            if first:
                print("[tracker] read %s: %d lines" % (path, len(lines)), flush=True)

            for line in lines[1:]:
                parts = line.split()
                if len(parts) < 5:
                    continue
                if parts[3] != "01":
                    continue
                try:
                    local       = parts[1].split(":")
                    remote      = parts[2].split(":")
                    local_port  = int(local[1], 16)
                    remote_ip   = remote[0]
                    remote_port = int(remote[1], 16)
                    qparts      = parts[4].split(":")
                    tx_q        = int(qparts[0], 16)
                    rx_q        = int(qparts[1], 16) if len(qparts) > 1 else 0
                except (ValueError, IndexError):
                    continue

                if remote_port != 443:
                    continue
                if remote_ip in ("00000000",
                                 "00000000000000000000000000000000",
                                 "0100007F",
                                 "00000000000000000000000001000000"):
                    continue
                if local_port in (self.ss_port, self.socks_port, self.panel_port):
                    continue

                result[(local_port, remote_ip, remote_port)] = {
                    "tx": tx_q, "rx": rx_q}
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

        idle_events = []   # list of (key, lifetime, idle_sec, tx_q, rx_q)

        with self._lock:
            new_queues = {}
            for key, qv in conns.items():
                tx, rx = qv["tx"], qv["rx"]
                prev = self._queues.get(key)
                if prev is None:
                    new_queues[key] = {
                        "tx": tx, "rx": rx,
                        "idle_ticks": 0,
                        "first_seen": now,
                        "last_changed": now,
                    }
                else:
                    changed    = (tx != prev["tx"] or rx != prev["rx"])
                    idle_ticks = 0 if changed else prev["idle_ticks"] + 1
                    last_chg   = now if changed else prev["last_changed"]
                    new_queues[key] = {
                        "tx": tx, "rx": rx,
                        "idle_ticks":   idle_ticks,
                        "first_seen":   prev["first_seen"],
                        "last_changed": last_chg,
                    }
                    lifetime = now - prev["first_seen"]
                    idle_sec = now - last_chg
                    # fire exactly once when ticks threshold is crossed
                    if (idle_ticks == IDLE_TICKS
                            and lifetime >= IDLE_MIN_LIFETIME
                            and idle_sec >= self._idle_threshold):
                        idle_events.append((key, lifetime, idle_sec, tx, rx))

            self._queues = new_queues

            # RST session tracking
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
                            if (not self.require_reset
                                    or self._has_recent_reset(now)):
                                self._do_rst_cut(session_duration + idle_time)
                        self._session_start = None
                        self._last_activity = None

            self.active_conns = len(conns)
            self.tracked      = len(conns)

        for (key, lifetime, idle_sec, tx_q, rx_q) in idle_events:
            self._do_idle_cut(lifetime, idle_sec, tx_q, rx_q, len(conns))

    def _has_recent_reset(self, now):
        with self._lock:
            ts_list = list(self._reset_ts)
        for rs in ts_list:
            if -self.poll_interval * 2 - 5 <= (rs - now) <= self.reset_window_sec * 3:
                return True
        return False

    def _get_top_slot_ctx(self):
        """Return slot_ctx for the most active pool slot (best-effort)."""
        try:
            if self.pool_ref is None:
                return {}
            stats = self.pool_ref.get_traffic_stats()
            slots = self.pool_ref.get_status()
            candidates = [s for s in slots
                          if s.get("alive") and not s.get("fw_excluded")]
            if not candidates:
                return {}
            top = max(candidates,
                      key=lambda s: (stats.get(s["qnum"]) or {}).get("pkts_delta", 0))
            tstat = stats.get(top["qnum"]) or {}
            return slot_ctx(
                index=top.get("index"),
                qnum=top.get("qnum"),
                strategy=top.get("strategy"),
                pid=top.get("pid"),
                pkts_delta=tstat.get("pkts_delta"),
                bytes_delta=tstat.get("bytes_delta"),
                kbps=tstat.get("kbps"),
            )
        except Exception:
            return {}

    def _get_monitor_ctx(self):
        """Return monitor_ctx from ResetMonitor (best-effort)."""
        try:
            if self.monitor_ref is None:
                return {}
            st = self.monitor_ref.get_status()
            return monitor_ctx(
                ratio=st.get("ratio"),
                resets=st.get("resets_window"),
                closes=st.get("closes_window"),
                window_sec=st.get("window_sec"),
                ss_lines=list(getattr(self.monitor_ref, "_recent_ss_lines", [])),
            )
        except Exception:
            return {}

    def _do_rst_cut(self, lifetime):
        now = time.time()
        with self._lock:
            self.last_cut_lifetime = round(lifetime, 1)
            self.last_cut_ts       = now
            self.total_cuts       += 1
            self.total_rst_cuts   += 1
            cb = self.on_cut

        self._log("warn", "[CUT/RST] conn lived %.1fs" % lifetime)

        if self._tlog:
            try:
                self._tlog.cut(
                    conn=conn_ctx(
                        lifetime_sec=lifetime,
                        active_conns=self.active_conns,
                    ),
                    slot=self._get_top_slot_ctx(),
                    monitor=self._get_monitor_ctx(),
                )
            except Exception as e:
                print("[tracker] tspу_log.cut error: %s" % e, flush=True)

        if cb:
            try:
                cb(lifetime, "rst")
            except TypeError:
                try:
                    cb(lifetime)
                except Exception as e:
                    self._log("error", "on_cut(rst): %s" % e)

    def _do_idle_cut(self, lifetime, idle_sec, tx_q, rx_q, active_conns):
        now = time.time()
        with self._lock:
            self.last_cut_lifetime = round(lifetime, 1)
            self.last_cut_ts       = now
            self.total_cuts       += 1
            self.total_idle_cuts  += 1
            cb = self.on_cut

        self._log("warn",
            "[CUT/IDLE] traffic stalled %.1fs  lifetime=%.1fs  tx_q=%d rx_q=%d"
            % (idle_sec, lifetime, tx_q, rx_q))

        if self._tlog:
            try:
                self._tlog.idle(
                    conn=conn_ctx(
                        lifetime_sec=lifetime,
                        idle_sec=idle_sec,
                        active_conns=active_conns,
                        tx_queue=tx_q,
                        rx_queue=rx_q,
                    ),
                    slot=self._get_top_slot_ctx(),
                    monitor=self._get_monitor_ctx(),
                )
            except Exception as e:
                print("[tracker] tspу_log.idle error: %s" % e, flush=True)

        if cb:
            try:
                cb(lifetime, "idle")
            except TypeError:
                try:
                    cb(lifetime)
                except Exception as e:
                    self._log("error", "on_cut(idle): %s" % e)