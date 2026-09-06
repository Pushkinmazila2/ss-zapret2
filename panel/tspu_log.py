#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tspu_log.py — единый журнал событий TSPU в JSONL.

Собирает в один файл всю историю, которую раньше размазывало по нескольким
журналам: срезы (RST / silent-idle), деградацию reset-монитора, теневые
тесты кандидатов, ротации слотов и служебные info-сообщения пула.

Актуально для восстановления скоринга стратегий/векторов после рестарта
панели (VectorScorer.seed_from_journal) и для UI (/api/tspu-log).

API (используется panel/server.py и panel/conn_tracker.py):

    from tspu_log import get_log, conn_ctx, slot_ctx, monitor_ctx
    log = get_log()

    log.cut(conn=conn_ctx(...), slot=slot_ctx(...), monitor=monitor_ctx(...))
    log.idle(conn=..., slot=..., monitor=...)
    log.degraded(ratio=..., resets=..., closes=..., window_sec=..., ss_lines=...)
    log.info(msg, source=..., level=...)
    log.test_ok (slot_index=..., strategy=..., nfqws_opt=..., pkts=...)
    log.test_fail(slot_index=..., strategy=..., nfqws_opt=...,
                  attempt=..., max_attempts=..., reason=...)
    log.rotation(old_slot=..., new_strategy=..., reason=..., monitor=...)
    log.get_recent(n=200, event_type=None)

Формат события:
    {"ts": <unix float>, "ts_iso": "...", "event": "cut|idle|degraded|info|test_ok|test_fail|rotation",
     ...payload...}

Потокобезопасно (threading.Lock), с ротацией по размеру (как cut_logger).
"""

import collections
import datetime
import io
import json
import logging
import os
import threading
import time


def _default_path():
    """TSPU_LOG_PATH > CUT_LOG_DIR/tspu.log > /opt/zapret2/logs > /run/zapret-pool."""
    env = os.environ.get("TSPU_LOG_PATH")
    if env:
        return env
    base = os.environ.get("CUT_LOG_DIR") or ""
    if base and os.path.isdir(base):
        return os.path.join(base, "tspu.log")
    for cand in ("/opt/zapret2/logs", "/run/zapret-pool"):
        if os.path.isdir(cand):
            return os.path.join(cand, "tspu.log")
    return "/run/zapret-pool/tspu.log"


def _iso(ts):
    try:
        return datetime.datetime.fromtimestamp(ts).isoformat(timespec="seconds")
    except Exception:
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts))


# контексты-строители: нормализуют kwargs в словарь (все поля опциональны).
def conn_ctx(**kw):
    return dict(kw)


def slot_ctx(**kw):
    return dict(kw)


def monitor_ctx(**kw):
    return dict(kw)
class TspuLog:
    """Кольцевой буфер + JSONL-файл последних TSPU-событий."""

    def __init__(self, path=None, max_file=2 * 1024 * 1024, keep=3,
                 max_buffered=10000):
        self.path = path or _default_path()
        self.max_file = int(max_file)
        self.keep = max(1, int(keep))
        self._lock = threading.Lock()
        self._buf = collections.deque(maxlen=int(max_buffered))
        self._seq = 0
        try:
            parent = os.path.dirname(self.path) or "."
            os.makedirs(parent, exist_ok=True)
        except Exception:
            pass
        self._count = self._read_tail_count()

    # ── события ──────────────────────────────────────────────────────────

    def cut(self, conn=None, slot=None, monitor=None, **kw):
        """Соединение оборвано ТСПУ (RST / классический срез)."""
        self._record("cut", conn=conn, slot=slot, monitor=monitor, **kw)

    def idle(self, conn=None, slot=None, monitor=None, **kw):
        """Соединение заглохло (silent drop / throttle) без RST."""
        self._record("idle", conn=conn, slot=slot, monitor=monitor, **kw)

    def degraded(self, **kw):
        """Reset-монитор перешёл в деградацию."""
        self._record("degraded", **kw)

    def info(self, msg, source=None, level=None, **kw):
        """Служебное сообщение пула (level: warn/error/ok/info)."""
        self._record("info", msg=msg, source=source, level=level, **kw)

    def test_ok(self, **kw):
        """Теневой тест стратегии прошёл успешно."""
        self._record("test_ok", **kw)

    def test_fail(self, **kw):
        """Теневой тест стратегии провалился."""
        self._record("test_fail", **kw)

    def rotation(self, old_slot=None, new_strategy=None,
                 new_slot=None, reason=None, monitor=None, **kw):
        """Слот заменён (отказ/срез → новая стратегия)."""
        self._record("rotation", old_slot=old_slot, new_slot=new_slot,
                     new_strategy=new_strategy, reason=reason,
                     monitor=monitor, **kw)

    # ── чтение ───────────────────────────────────────────────────────────

    def get_recent(self, n=200, event_type=None):
        """Последние события, новые сверху. event_type — фильтр по event."""
        with self._lock:
            buf = list(self._buf)
        buf.reverse()
        items = buf[:int(n)]
        if event_type:
            items = [e for e in items if e.get("event") == event_type]
        return items

    def status(self):
        with self._lock:
            return {"path": self.path, "count": self._count,
                    "buffered": len(self._buf)}

    # ── internals ────────────────────────────────────────────────────────

    def _record(self, event, **kw):
        entry = {
            "ts": round(time.time(), 3),
            "ts_iso": _iso(time.time()),
            "event": event,
        }
        for k, v in kw.items():
            if v is not None:
                entry[k] = v
        line = json.dumps(entry, ensure_ascii=False, default=str)
        with self._lock:
            self._seq += 1
            self._buf.append(entry)
            try:
                self._rotate_if_needed()
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                self._count += 1
            except Exception as e:
                logging.getLogger("tspu_log").warning("write: %s", e)
        return entry

    def _rotate_if_needed(self):
        if not os.path.exists(self.path):
            return
        try:
            if os.path.getsize(self.path) < self.max_file:
                return
            base, ext = os.path.splitext(self.path)
            for i in range(self.keep, 0, -1):
                src = "%s.%d%s" % (base, i, ext)
                dst = "%s.%d%s" % (base, i + 1, ext)
                if os.path.exists(src):
                    os.replace(src, dst)
            if os.path.exists(self.path):
                os.replace(self.path, "%s.1%s" % (base, ext))
            self._count = 0
        except Exception:
            pass

    def _read_tail_count(self):
        n = 0
        try:
            with io.open(self.path, "r", encoding="utf-8") as f:
                for _line in f:
                    n += 1
            self._seq = n
        except Exception:
            pass
        return n


_log_singleton = None


def get_log():
    """Единственный экземпляр журнала (как reset_monitor/cut_logger в глобалах)."""
    global _log_singleton
    if _log_singleton is None:
        _log_singleton = TspuLog()
    return _log_singleton


if __name__ == "__main__":
    import sys
    log = get_log()
    log.cut(conn=conn_ctx(lifetime_sec=42.0, active_conns=3),
            slot=slot_ctx(index=1, qnum=50, strategy="smoke_s1"),
            monitor=monitor_ctx(ratio=0.0))
    log.info("smoke info", source="panel", level="info")
    print(json.dumps(log.get_recent(5), ensure_ascii=False, default=str,
                     indent=2))
    print(json.dumps(log.status(), ensure_ascii=False))
    sys.exit(0)