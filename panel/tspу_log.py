#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tspу_log.py — структурированный лог событий блокировки ТСПУ.

Пишет в /run/zapret-pool/tspу.log отдельно от общего stdout-потока.
Каждое событие — одна строка JSON + читаемый дамп для tail -f.

Использование:
    from tspу_log import TspuLog
    tlog = TspuLog()
    tlog.cut(lifetime=47.3, slot=2, strategy="my-strat", cut_type="rst")
    tlog.idle_drop(lifetime=92.1, idle_sec=38.0, slot=1, strategy="other")
    tlog.rotation(old_strategy="a", new_strategy="b", slot=2, reason="cut")
    tlog.degraded(ratio=0.72, resets=18, total=25)
    tlog.ok(msg="пул восстановлен")
"""

import json
import os
import threading
import time

LOG_PATH  = os.environ.get("TSPУ_LOG", "/run/zapret-pool/tspу.log")
MAX_BYTES = 5 * 1024 * 1024   # ротация по 5 МБ

# Цвета для tail -f (только когда пишем в файл, ANSI читается в большинстве терминалов)
_C = {
    "cut":       "\033[91m",   # красный   — жёсткий срез (RST)
    "idle":      "\033[93m",   # жёлтый    — тихий дроп (нет трафика)
    "rotation":  "\033[96m",   # голубой   — смена стратегии
    "degraded":  "\033[95m",   # пурпурный — деградация (ratio > threshold)
    "ok":        "\033[92m",   # зелёный   — восстановление
    "info":      "\033[0m",    # сброс
}
_RESET = "\033[0m"

_ICONS = {
    "cut":      "✂",
    "idle":     "⏸",
    "rotation": "↻",
    "degraded": "⚠",
    "ok":       "✓",
    "info":     "·",
}


class TspuLog:
    def __init__(self, path=None):
        self._path  = path or LOG_PATH
        self._lock  = threading.Lock()
        os.makedirs(os.path.dirname(self._path), exist_ok=True)

    # ── публичный API ─────────────────────────────────────────────────

    def cut(self, lifetime: float, slot: int = None,
            strategy: str = None, cut_type: str = "rst"):
        """
        Жёсткий срез: соединение прожило lifetime сек и получило RST.
        cut_type: "rst" | "timeout"
        """
        self._write("cut", {
            "lifetime_sec": round(lifetime, 1),
            "cut_type":     cut_type,
            "slot":         slot,
            "strategy":     strategy,
        }, human=(
            "Срез (%s): соединение прожило %.1f с"
            " [слот=%s стратегия=%s]" % (
                cut_type, lifetime,
                slot if slot is not None else "?",
                strategy or "?")
        ))

    def idle_drop(self, lifetime: float, idle_sec: float,
                  slot: int = None, strategy: str = None):
        """
        Тихий дроп: трафик встал на idle_sec, соединение всё ещё числится.
        Признак ТСПУ-throttle или silent drop без RST.
        """
        self._write("idle", {
            "lifetime_sec": round(lifetime, 1),
            "idle_sec":     round(idle_sec, 1),
            "slot":         slot,
            "strategy":     strategy,
        }, human=(
            "Тихий дроп: трафик встал на %.1f с"
            " (соединение живёт %.1f с)"
            " [слот=%s стратегия=%s]" % (
                idle_sec, lifetime,
                slot if slot is not None else "?",
                strategy or "?")
        ))

    def rotation(self, old_strategy: str, new_strategy: str,
                 slot: int = None, reason: str = "cut"):
        """Смена стратегии в слоте пула."""
        self._write("rotation", {
            "slot":         slot,
            "old_strategy": old_strategy,
            "new_strategy": new_strategy,
            "reason":       reason,
        }, human=(
            "Ротация слот=%s: «%s» → «%s» (причина: %s)" % (
                slot if slot is not None else "?",
                old_strategy, new_strategy, reason)
        ))

    def degraded(self, ratio: float, resets: int, total: int,
                 window_sec: int = 60):
        """Соотношение RST/total превысило порог."""
        self._write("degraded", {
            "ratio":      round(ratio, 3),
            "resets":     resets,
            "total":      total,
            "window_sec": window_sec,
        }, human=(
            "Деградация: reset/total=%.0f%% (%d/%d за %dс)" % (
                ratio * 100, resets, total, window_sec)
        ))

    def ok(self, msg: str = "пул работает"):
        """Восстановление / всё хорошо."""
        self._write("ok", {}, human=msg)

    def info(self, msg: str, **extra):
        """Произвольное информационное событие."""
        self._write("info", extra or {}, human=msg)

    def get_recent(self, n: int = 100):
        """
        Читает последние n строк из лог-файла.
        Возвращает список dict (распарсенный JSON).
        Используется панелью для /api/tspу-log.
        """
        try:
            with self._lock:
                with open(self._path, "r", errors="replace") as f:
                    lines = f.readlines()
            result = []
            for line in lines[-n:]:
                line = line.strip()
                if not line:
                    continue
                # строки бывают двух форматов — JSON и human-readable
                if line.startswith("{"):
                    try:
                        result.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            return result
        except (OSError, IOError):
            return []

    # ── internals ─────────────────────────────────────────────────────

    def _write(self, event_type: str, data: dict, human: str = ""):
        now     = time.time()
        ts_iso  = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now))
        icon    = _ICONS.get(event_type, "·")
        color   = _C.get(event_type, _C["info"])

        # JSON строка для машинной обработки
        record  = {"ts": now, "iso": ts_iso, "event": event_type}
        record.update(data)
        json_line = json.dumps(record, ensure_ascii=False)

        # Человекочитаемая строка для tail -f
        human_line = "%s%s %s  %s%s" % (
            color, ts_iso, icon, human, _RESET)

        with self._lock:
            try:
                # ротация если файл вырос
                try:
                    if os.path.getsize(self._path) > MAX_BYTES:
                        os.rename(self._path, self._path + ".1")
                except OSError:
                    pass

                with open(self._path, "a", encoding="utf-8") as f:
                    f.write(json_line + "\n")
                    f.write(human_line + "\n")
                    f.flush()
            except Exception as e:
                print("[tspу_log] write error: %s" % e, flush=True)


# ── синглтон для импорта ──────────────────────────────────────────────
_instance = None
_inst_lock = threading.Lock()


def get_log() -> TspuLog:
    global _instance
    if _instance is None:
        with _inst_lock:
            if _instance is None:
                _instance = TspuLog()
    return _instance