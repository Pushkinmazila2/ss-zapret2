#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tspу_log.py  -  structured TSPУ block event log.

Writes to /run/zapret-pool/tspу.log  (configurable via TSPУ_LOG env var).
Each event = one JSON line + one human-readable line, so the file works
both for machine parsing and for  tail -f.

Design goals:
  - Every event carries FULL context: who, what slot, what strategy,
    what the connection looked like, what nfqws2 was doing.
  - Two sources are merged per event:
      [PANEL]    - PoolSwitcher / PoolManager state at the moment of the event
      [SS-SERVER]- raw line(s) from ss-server.log that triggered the event
  - No emojis, English only, no color codes in the human line
    (use  grep / awk / jq  to filter).

Event types:
  cut       RST drop: connection got TCP RST after N seconds
  idle      Silent drop: traffic stalled on an ESTABLISHED connection
  rotation  Strategy swap on a slot (with before/after context)
  degraded  RST ratio exceeded threshold
  test_fail Shadow test failed for a strategy
  test_ok   Shadow test passed
  info      Generic panel event worth recording
  ok        Pool recovered
"""

import collections
import json
import os
import threading
import time

LOG_PATH  = os.environ.get("TSPУ_LOG", "/run/zapret-pool/tspу.log")
MAX_BYTES = 10 * 1024 * 1024   # rotate at 10 MB


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _fmt_bytes(n):
    if n is None:
        return "?"
    if n < 1024:
        return "%dB" % n
    if n < 1024 * 1024:
        return "%.1fKB" % (n / 1024)
    return "%.1fMB" % (n / 1024 / 1024)

def _ts():
    return time.strftime("%Y-%m-%dT%H:%M:%S")

def _now():
    return time.time()


# ---------------------------------------------------------------------------
# Context dataclasses (plain dicts for simplicity)
# ---------------------------------------------------------------------------

def conn_ctx(lifetime_sec=None, idle_sec=None, active_conns=None,
             tx_queue=None, rx_queue=None, remote_ip=None):
    """Connection-level context at the moment of the event."""
    return {k: v for k, v in {
        "lifetime_sec":  round(lifetime_sec, 1) if lifetime_sec is not None else None,
        "idle_sec":      round(idle_sec, 1)     if idle_sec is not None else None,
        "active_conns":  active_conns,
        "tx_queue":      tx_queue,
        "rx_queue":      rx_queue,
        "remote_ip":     remote_ip,
    }.items() if v is not None}


def slot_ctx(index=None, qnum=None, strategy=None, nfqws_opt=None,
             pid=None, pkts_delta=None, bytes_delta=None, kbps=None,
             healthy=None):
    """Pool slot context at the moment of the event."""
    return {k: v for k, v in {
        "index":       index,
        "qnum":        qnum,
        "strategy":    strategy,
        "nfqws_opt":   nfqws_opt,
        "pid":         pid,
        "pkts_delta":  pkts_delta,
        "bytes_delta": bytes_delta,
        "kbps":        kbps,
        "healthy":     healthy,
    }.items() if v is not None}


def monitor_ctx(ratio=None, resets=None, closes=None, window_sec=None,
                ss_lines=None):
    """ResetMonitor state + raw ss-server lines that triggered the event."""
    return {k: v for k, v in {
        "ratio":      round(ratio, 3) if ratio is not None else None,
        "resets":     resets,
        "closes":     closes,
        "window_sec": window_sec,
        # ss_lines: list of raw strings from ss-server.log
        "ss_lines":   ss_lines,
    }.items() if v is not None}


# ---------------------------------------------------------------------------
# Main logger
# ---------------------------------------------------------------------------

class TspuLog:
    def __init__(self, path=None):
        self._path = path or LOG_PATH
        self._lock = threading.Lock()
        try:
            os.makedirs(os.path.dirname(self._path), exist_ok=True)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Public API - one method per event type                               #
    # ------------------------------------------------------------------ #

    def cut(self, conn=None, slot=None, monitor=None):
        """
        RST drop: connection received TCP RST.

        Args:
            conn:    conn_ctx(lifetime_sec=..., active_conns=..., ...)
            slot:    slot_ctx(index=..., strategy=..., nfqws_opt=..., ...)
            monitor: monitor_ctx(ratio=..., ss_lines=[...])
        """
        c = conn    or {}
        s = slot    or {}
        m = monitor or {}
        lifetime = c.get("lifetime_sec", "?")
        human = (
            "[CUT/RST] conn lifetime=%.1fs"
            "  slot=%s strategy=%s"
            "  active_conns=%s  reset_ratio=%s"
            "  ss=%s" % (
                float(lifetime) if lifetime != "?" else 0,
                s.get("index", "?"),
                s.get("strategy", "?"),
                c.get("active_conns", "?"),
                "%.0f%%" % (m["ratio"] * 100) if "ratio" in m else "?",
                "; ".join(m.get("ss_lines", [])) or "none",
            )
        )
        self._write("cut", human, conn=c, slot=s, monitor=m)

    def idle(self, conn=None, slot=None, monitor=None):
        """
        Silent drop: traffic stalled on an ESTABLISHED connection.
        TSPУ is dropping packets without RST.

        Args:
            conn:    conn_ctx(lifetime_sec=..., idle_sec=..., tx_queue=..., rx_queue=...)
            slot:    slot_ctx(index=..., strategy=..., kbps=..., pkts_delta=...)
            monitor: monitor_ctx(ratio=..., ss_lines=[...])
        """
        c = conn    or {}
        s = slot    or {}
        m = monitor or {}
        human = (
            "[CUT/IDLE] traffic stalled  idle=%.1fs  lifetime=%.1fs"
            "  slot=%s strategy=%s  kbps=%s pkts_delta=%s"
            "  tx_q=%s rx_q=%s  reset_ratio=%s" % (
                c.get("idle_sec", 0),
                c.get("lifetime_sec", 0),
                s.get("index", "?"),
                s.get("strategy", "?"),
                s.get("kbps", "?"),
                s.get("pkts_delta", "?"),
                c.get("tx_queue", "?"),
                c.get("rx_queue", "?"),
                "%.0f%%" % (m["ratio"] * 100) if "ratio" in m else "?",
            )
        )
        self._write("idle", human, conn=c, slot=s, monitor=m)

    def rotation(self, old_slot=None, new_strategy=None, reason=None, monitor=None):
        """
        Strategy swap on a slot.

        Args:
            old_slot:     slot_ctx() for the slot being replaced
            new_strategy: strategy name that will be installed
            reason:       "cut_rst" | "cut_idle" | "check_fail" | "manual"
            monitor:      monitor_ctx()
        """
        s = old_slot or {}
        m = monitor  or {}
        human = (
            "[ROTATION] slot=%s  %s -> %s  reason=%s"
            "  pkts_delta=%s kbps=%s  reset_ratio=%s" % (
                s.get("index", "?"),
                s.get("strategy", "?"),
                new_strategy or "?",
                reason or "?",
                s.get("pkts_delta", "?"),
                s.get("kbps", "?"),
                "%.0f%%" % (m["ratio"] * 100) if "ratio" in m else "?",
            )
        )
        self._write("rotation", human,
                    old_slot=s, new_strategy=new_strategy,
                    reason=reason, monitor=m)

    def test_fail(self, slot_index=None, strategy=None, nfqws_opt=None,
                  attempt=None, max_attempts=None, reason=None):
        """Shadow slot test failed for a strategy."""
        human = (
            "[TEST/FAIL] slot=%s  strategy=%s  attempt=%s/%s  reason=%s"
            "  nfqws_opt=%s" % (
                slot_index if slot_index is not None else "?",
                strategy or "?",
                attempt  if attempt  is not None else "?",
                max_attempts if max_attempts is not None else "?",
                reason or "no traffic / curl failed",
                (nfqws_opt or "")[:120],
            )
        )
        self._write("test_fail", human,
                    slot=slot_index, strategy=strategy,
                    attempt=attempt, max_attempts=max_attempts,
                    nfqws_opt=nfqws_opt, reason=reason)

    def test_ok(self, slot_index=None, strategy=None, nfqws_opt=None,
                pkts=None, via_curl=False):
        """Shadow slot test passed."""
        human = (
            "[TEST/OK]  slot=%s  strategy=%s  pkts=%s  via_curl=%s"
            "  nfqws_opt=%s" % (
                slot_index if slot_index is not None else "?",
                strategy or "?",
                pkts if pkts is not None else "?",
                via_curl,
                (nfqws_opt or "")[:120],
            )
        )
        self._write("test_ok", human,
                    slot=slot_index, strategy=strategy,
                    pkts=pkts, via_curl=via_curl, nfqws_opt=nfqws_opt)

    def degraded(self, ratio=None, resets=None, closes=None,
                 window_sec=None, ss_lines=None):
        """RST ratio exceeded threshold - pool is degraded."""
        human = (
            "[DEGRADED] reset_ratio=%.0f%%  resets=%s closes=%s  window=%ss"
            "  ss=%s" % (
                (ratio or 0) * 100,
                resets or "?",
                closes or "?",
                window_sec or "?",
                "; ".join(ss_lines or []) or "none",
            )
        )
        self._write("degraded", human,
                    ratio=round(ratio, 3) if ratio is not None else None,
                    resets=resets, closes=closes,
                    window_sec=window_sec, ss_lines=ss_lines)

    def ok(self, msg=None, pool_size=None, healthy_count=None):
        """Pool recovered."""
        human = "[OK] %s  pool_size=%s healthy=%s" % (
            msg or "pool operational",
            pool_size if pool_size is not None else "?",
            healthy_count if healthy_count is not None else "?",
        )
        self._write("ok", human,
                    msg=msg, pool_size=pool_size, healthy_count=healthy_count)

    def info(self, msg, source="panel", **extra):
        """
        Generic panel or ss-server event.
        source: "panel" | "ss-server"
        """
        human = "[INFO/%s] %s" % (source.upper(), msg)
        if extra:
            human += "  " + "  ".join(
                "%s=%s" % (k, v) for k, v in extra.items() if v is not None)
        self._write("info", human, source=source, msg=msg, **{
            k: v for k, v in extra.items() if v is not None})

    # ------------------------------------------------------------------ #
    # Panel API endpoint helper                                            #
    # ------------------------------------------------------------------ #

    def get_recent(self, n=200, event_type=None):
        """
        Return last n JSON events from log file.
        Optionally filter by event_type ("cut", "idle", "rotation", ...).
        Used by GET /api/tspу-log.
        """
        try:
            with self._lock:
                with open(self._path, "r", errors="replace") as f:
                    lines = f.readlines()
        except (OSError, IOError):
            return []

        result = []
        for line in lines:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event_type and rec.get("event") != event_type:
                continue
            result.append(rec)

        return result[-n:]

    # ------------------------------------------------------------------ #
    # Internal                                                             #
    # ------------------------------------------------------------------ #

    def _write(self, event_type, human_line, **fields):
        now = _now()
        record = {
            "ts":    now,
            "iso":   _ts(),
            "event": event_type,
        }
        # flatten non-None fields
        for k, v in fields.items():
            if v is not None:
                record[k] = v

        json_line   = json.dumps(record, ensure_ascii=False, default=str)
        plain_line  = "%s  %s" % (_ts(), human_line)

        with self._lock:
            try:
                try:
                    if os.path.getsize(self._path) > MAX_BYTES:
                        os.rename(self._path, self._path + ".1")
                except OSError:
                    pass
                with open(self._path, "a", encoding="utf-8") as f:
                    f.write(json_line + "\n")
                    f.write(plain_line + "\n")
                    f.flush()
            except Exception as e:
                print("[tspу_log] write error: %s" % e, flush=True)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_instance  = None
_inst_lock = threading.Lock()

def get_log() -> TspuLog:
    global _instance
    if _instance is None:
        with _inst_lock:
            if _instance is None:
                _instance = TspuLog()
    return _instance