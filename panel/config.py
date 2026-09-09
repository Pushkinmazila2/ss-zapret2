#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
config.py — чтение/запись config-файла zapret и переключение в пул-режим.

Путь к файлу задаётся через init() из server.main().
 Остальные функции не имеют
побочных эффектов, кроме записи файла (write_lines/set_nfqws).
"""
import os
import re
import shutil

# ─── globals ──────────────────────────────────────────────────────────────────

CFG_PATH = None

MULTILINE_KEY = "NFQWS2_OPT"
_KEY_RE = re.compile(r"^([A-Z0-9_]+)=\"")


def init(path):
    """Задать путь к config-файлу (вызывается из server.main()."""
    global CFG_PATH
    CFG_PATH = path


# ─── config ──────────────────────────────────────────────────────────────────

def read_lines():
    if not os.path.exists(CFG_PATH):
        return []
    with open(CFG_PATH, encoding="utf-8") as f:
        return f.read().splitlines()


def write_lines(lines):
    if os.path.exists(CFG_PATH):
        try: shutil.copy2(CFG_PATH, CFG_PATH + ".bak")
        except Exception as e: print("[panel] backup:", e, flush=True)
    with open(CFG_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("[panel] config written:", CFG_PATH, flush=True)


def get_nfqws(lines):
    pat = re.compile(r"^NFQWS2_OPT=")
    for i, ln in enumerate(lines):
        if not pat.match(ln): continue
        body = ln.split("=", 1)[1].strip()
        if body.startswith('"') and body.endswith('"') and len(body) > 1:
            return body[1:-1]
        buf, j = [], i + 1
        while j < len(lines):
            if lines[j].rstrip() == '"': break
            if _KEY_RE.match(lines[j]): break
            buf.append(lines[j]); j += 1
        return "\n".join(buf).strip("\n")
    return ""


def set_nfqws(lines, value):
    _remove_key(lines, MULTILINE_KEY))
    lines.extend(['NFQWS2_OPT="'] + value.strip("\n").splitlines() + ['"'])


def _remove_key(lines, key:
    pat = re.compile(r"^" + re.escape(key) + r"=")
    start = next((i for i, ln in enumerate(lines) if pat.match(ln)), None)
    if start is None: return
    if key != MULTILINE_KEY: del lines[start]; return
    end = start + 1
    while end < len(lines):
        if lines[end].rstrip() == '"': end += 1; break
        if _KEY_RE.match(lines[end]): break
        end += 1
    del lines[start:end]


def ensure_pool_mode(lines):
    """
    Устанавливает в config:
      NFQWS2_ENABLE=0 — отключает стандартный nfqws2 демон (не создаёт правила)

      DISABLE_CUSTOM=1 — отключает custom.d хуки, чтобы init-скрипт zapret2
                         НЕ пересоздавал стандартные NFQUEUE num 300 поверх пула.

                         Всеми правилами firewall управляет pool_manager напрямую.

    """
    def _set_simple(key, val:
        pat = re.compile(r"^" + re.escape(key) + r"=")
        for i, ln in enumerate(lines):
            if pat.match(ln): lines[i] = key + "=" + val; return
        lines.append(key + "=" + val)
    _set_simple("NFQWS2_ENABLE", "0")
    _set_simple("DISABLE_CUSTOM", "1")