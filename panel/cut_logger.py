#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CutLogger — отдельный журнал «оборванных» соединений (срезов ТСПУ).

Пишет JSONL-файл с максимально расширенным контекстом:
данные детектора, соединение, слот/стратегия, трафик, reset-монитор и
хвосты логов (панель, nfqws2, ss-server). Поддерживает ротацию по размеру,
thread-safe append, кольцевой буфер для UI, экспорт и очистку.
"""

import io
import json
import logging
import os
import threading
import time


class CutLogger:
    def __init__(self, path="/run/zapret-pool/cuts.log", max_file=2 * 1024 * 1024,
                 keep=3, max_buffered=500):
        self.path     = path
        self.max_file = int(max_file)
        self.keep     = max(1, int(keep))
        self._lock    = threading.Lock()
        self._buf     = []            # последние записи (json dict)
        self._max_buf = int(max_buffered)
        self._seq     = 0
        self._count   = 0
        # idempotent init: создаём каталог, буфер с прошлых записей
        try:
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            self._count = self._read_tail_count()
        except Exception:
            pass

    # ── public ─────────────────────────────────────────────────────────

    def record(self, payload):
        """Записывает событие. payload — dict; добавляет id/ts/count."""
        entry = {
            "id":   self._next_id(),
            "ts":   _iso(time.time()),
            "unix_ts": round(time.time(), 3),
        }
        entry.update(payload)
        line = json.dumps(entry, ensure_ascii=False, default=str)
        with self._lock:
            self._append(entry, line)
        return entry

    def list(self, limit=50):
        """Последние записи (новые сверху) для UI."""
        with self._lock:
            return list(reversed(self._buf[-int(limit):]))

    def export(self):
        """Полный текст JSONL-файла (для скачивания)."""
        with self._lock:
            if os.path.exists(self.path):
                try:
                    with io.open(self.path, "r", encoding="utf-8") as f:
                        return f.read()
                except Exception:
                    return ""
            return ""

    def clear(self):
        """Очищает файл и буфер."""
        with self._lock:
            self._buf = []
            try:
                with open(self.path, "w") as f:
                    f.write("")
            except Exception:
                pass
            self._count = 0
        return {"ok": True}

    def status(self):
        with self._lock:
            return {"path": self.path, "count": self._count, "buffered": len(self._buf)}

    # ── internals ───────────────────────────────────────────────────────

    def _next_id(self):
        self._seq += 1
        return self._seq

    def _append(self, entry, line):
        self._buf.append(entry)
        if len(self._buf) > self._max_buf:
            self._buf = self._buf[-self._max_buf:]
        try:
            self._rotate_if_needed()
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            self._count += 1
        except Exception as e:
            logging.getLogger("cut_logger").warning("write: %s", e)

    def _rotate_if_needed(self):
        try:
            if os.path.exists(self.path) and os.path.getsize(self.path) >= self.max_file:
                base, ext = os.path.splitext(self.path)
                # сдвигаем backups: .3 -> .4, .2 -> .3, ... (не обязателен exact порядок)
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
        """Подсчёт существующих записей (для сквозной нумерации после рестарта)."""
        n = 0
        try:
            with io.open(self.path, "r", encoding="utf-8") as f:
                for _line in f:
                    n += 1
            self._seq = n
        except Exception:
            pass
        return n


def _iso(ts):
    try:
        import datetime
        return datetime.datetime.fromtimestamp(ts).isoformat(timespec="seconds")
    except Exception:
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts))