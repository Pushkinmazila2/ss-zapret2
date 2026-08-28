#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Веб-панель управления zapret2 с пулом nfqws2 и авто-переключением.
"""
import argparse, collections, json, os, re, shutil, subprocess
import sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pool_manager import PoolManager, MAX_SLOTS

# ── globals ────────────────────────────────────────────────────────────────

CFG_PATH    = None
STRAT_DIR   = None
RESTART_CMD = None
SOCKS_PORT  = None
SS_PORT     = None

MULTILINE_KEY = "NFQWS2_OPT"
_KEY_RE = re.compile(r"^([A-Z0-9_]+)=")

# ── config ──────────────────────────────────────────────────────────────────

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
    _remove_key(lines, MULTILINE_KEY)
    lines.extend(['NFQWS2_OPT="'] + value.strip("\n").splitlines() + ['"'])

def _remove_key(lines, key):
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
    """Устанавливает NFQWS2_ENABLE=0 и DISABLE_CUSTOM=0 в config."""
    def _set_simple(key, val):
        pat = re.compile(r"^" + re.escape(key) + r"=")
        for i, ln in enumerate(lines):
            if pat.match(ln): lines[i] = key + "=" + val; return
        lines.append(key + "=" + val)
    _set_simple("NFQWS2_ENABLE", "0")
    _set_simple("DISABLE_CUSTOM", "0")

# ── strategies ──────────────────────────────────────────────────────────────

def list_strategies():
    if not os.path.isdir(STRAT_DIR): return []
    result = []
    for fn in sorted(os.listdir(STRAT_DIR)):
        if not fn.endswith(".conf"): continue
        fpath = os.path.join(STRAT_DIR, fn)
        with open(fpath, encoding="utf-8") as f:
            flines = f.read().splitlines()
        desc = next((ln.lstrip("#").strip() for ln in flines if ln.strip().startswith("#")), "")
        result.append({
            "name": os.path.splitext(fn)[0],
            "file": fn,
            "description": desc,
            "nfqws_opt": get_nfqws(flines),
        })
    return result

def load_strategy_nfqws(name):
    path = os.path.join(STRAT_DIR, name + ".conf")
    if not os.path.isfile(path): return None
    with open(path, encoding="utf-8") as f:
        return get_nfqws(f.read().splitlines())

# ── system ──────────────────────────────────────────────────────────────────

def restart_zapret():
    print("[panel] restart:", RESTART_CMD, flush=True)
    try:
        p = subprocess.run(RESTART_CMD, shell=True, capture_output=True, text=True, timeout=120)
        print("[panel] restart rc=%d" % p.returncode, flush=True)
        return {"rc": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}
    except Exception as e:
        return {"rc": -1, "stdout": "", "stderr": str(e)}

def run_curl(port, url, timeout=15):
    cmd = ["curl", "-x", "socks5h://127.0.0.1:%d" % port,
           url, "-I", "--max-time", str(timeout), "--connect-timeout", "8", "-s", "-S"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        out = (p.stdout or "") + (p.stderr or "")
        ok  = p.returncode == 0 and bool(re.search(r"HTTP/\S+ [23]", p.stdout))
        return {"ok": ok, "rc": p.returncode, "output": out.strip()}
    except FileNotFoundError:
        return {"ok": False, "rc": -1, "output": "curl не найден"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "rc": -1, "output": "Таймаут %dс" % timeout}
    except Exception as e:
        return {"ok": False, "rc": -1, "output": str(e)}

def _hex_to_ip(h):
    try: return ".".join(str(int(h[i:i+2], 16)) for i in (6, 4, 2, 0))
    except: return None

def get_connections(ss_port, socks_port):
    ss_ips, socks_ips = set(), set()
    ss_hex, socks_hex = "%04X" % ss_port, "%04X" % socks_port
    try:
        with open("/proc/net/tcp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) < 4 or parts[3] != "01": continue
                lph = parts[1].split(":")[1]
                rip = _hex_to_ip(parts[2].split(":")[0])
                if not rip or rip.startswith("127."): continue
                if lph == ss_hex: ss_ips.add(rip)
                elif lph == socks_hex: socks_ips.add(rip)
    except Exception as e:
        return {"error": str(e), "ss": [], "socks": []}
    return {"ss_port": ss_port, "socks_port": socks_port,
            "ss": sorted(ss_ips), "socks": sorted(socks_ips)}

# ── PoolSwitcher ─────────────────────────────────────────────────────────────

class PoolSwitcher:
    """
    Управляет пулом nfqws2 слотов и авто-заменой нерабочих стратегий.

    Режимы:
      pool  — N слотов работают параллельно, трафик распределяется случайно.
              Каждый слот тестируется независимо. Нерабочий слот заменяется
              следующей стратегией из списка (graceful replace без даунтайма).
      single — классический режим: один nfqws2, авто-переключение при сбое.
    """

    MAX_LOG = 300

    def __init__(self, pool: PoolManager):
        self._pool      = pool
        self._lock      = threading.Lock()
        self._stop_evt  = threading.Event()
        self._thread    = None

        # настройки
        self.enabled         = False
        self.mode            = "pool"   # "pool" | "single"
        self.pool_size       = 3        # сколько слотов держать
        self.check_interval  = 60
        self.fail_threshold  = 2        # провалов на слот до замены
        self.settle_time     = 6        # сек после старта нового nfqws2
        self.test_url        = "https://www.youtube.com"

        # состояние
        self.state           = "idle"
        self._slot_fails     = {}       # index → consecutive fails
        self._strategy_idx   = 0       # указатель в списке стратегий
        self._used           = set()   # имена уже назначенных стратегий
        self._log            = collections.deque(maxlen=self.MAX_LOG)

    # ── public ────────────────────────────────────────────────────────────

    def get_status(self):
        with self._lock:
            pool_status = self._pool.get_status()
            return {
                "enabled":        self.enabled,
                "mode":           self.mode,
                "pool_size":      self.pool_size,
                "state":          self.state,
                "check_interval": self.check_interval,
                "fail_threshold": self.fail_threshold,
                "settle_time":    self.settle_time,
                "test_url":       self.test_url,
                "slots":          pool_status,
                "strategy_idx":   self._strategy_idx,
            }

    def get_log(self):
        with self._lock:
            return list(self._log)

    def configure(self, cfg):
        with self._lock:
            for k in ("mode", "pool_size", "check_interval", "fail_threshold",
                      "settle_time", "test_url"):
                if k in cfg:
                    setattr(self, k, cfg[k])
        return self.get_status()

    def set_enabled(self, enabled):
        with self._lock:
            self.enabled = bool(enabled)
        if self.enabled:
            self._ensure_pool_filled()
            self._ensure_running()
        else:
            self._stop_evt.set()
        self._log_event("info", "Пул %s (режим: %s)" % (
            "запущен" if self.enabled else "остановлен", self.mode))
        return self.get_status()

    def force_check(self):
        threading.Thread(target=self._check_all_slots, daemon=True).start()

    def set_slot_strategy(self, index, strategy_name):
        """Ручная смена стратегии в конкретном слоте."""
        nfqws = load_strategy_nfqws(strategy_name)
        if not nfqws:
            return {"error": "стратегия не найдена: " + strategy_name}
        self._pool.replace_slot(index, strategy_name, nfqws)
        with self._lock:
            self._slot_fails[index] = 0
        self._log_event("info", "Слот %d: ручная замена → «%s»" % (index, strategy_name))
        return {"ok": True}

    def add_slot(self):
        """Добавить ещё один слот в пул."""
        with self._lock:
            current = self._pool.active_count()
            if current >= MAX_SLOTS:
                return {"error": "максимум %d слотов" % MAX_SLOTS}
            idx = current
        name, nfqws = self._next_strategy()
        if not name:
            return {"error": "нет доступных стратегий"}
        self._pool.start_slot(idx, name, nfqws)
        self._log_event("info", "Добавлен слот %d → «%s»" % (idx, name))
        return {"ok": True}

    def remove_slot(self, index):
        """Убрать слот из пула."""
        self._pool.stop_slot(index)
        self._log_event("info", "Слот %d остановлен" % index)
        return {"ok": True}

    # ── internals ─────────────────────────────────────────────────────────

    def _log_event(self, level, msg):
        entry = {"ts": time.strftime("%H:%M:%S"), "level": level, "msg": msg}
        with self._lock:
            self._log.append(entry)
        print("[switcher][%s] %s" % (level.upper(), msg), flush=True)

    def _ensure_running(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_evt.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        self._log_event("info", "Мониторинг запущен (интервал %dс)" % self.check_interval)
        while not self._stop_evt.is_set():
            self._pool.watchdog()
            if self.enabled:
                self._check_all_slots()
            self._stop_evt.wait(timeout=self.check_interval)

    def _ensure_pool_filled(self):
        """Заполняет пул до pool_size слотов стратегиями."""
        strategies = list_strategies()
        if not strategies:
            self._log_event("warn", "Нет стратегий для заполнения пула")
            return
        current = self._pool.active_count()
        target  = min(self.pool_size, MAX_SLOTS, len(strategies))
        for i in range(current, target):
            name, nfqws = self._next_strategy()
            if not name:
                self._log_event("warn", "Стратегии закончились при заполнении пула")
                break
            self._pool.start_slot(i, name, nfqws)
            self._log_event("info", "Слот %d → «%s»" % (i, name))
            time.sleep(0.5)

    def _next_strategy(self):
        """Возвращает (name, nfqws_opt) следующей неиспользованной стратегии."""
        strategies = list_strategies()
        if not strategies:
            return None, None
        with self._lock:
            # Обход по кругу; если все использованы — сбрасываем
            total = len(strategies)
            for _ in range(total):
                s = strategies[self._strategy_idx % total]
                self._strategy_idx += 1
                if s["name"] not in self._used:
                    self._used.add(s["name"])
                    return s["name"], s["nfqws_opt"]
            # Все использованы — начинаем сначала
            self._used.clear()
            s = strategies[self._strategy_idx % total]
            self._strategy_idx += 1
            self._used.add(s["name"])
            return s["name"], s["nfqws_opt"]

    def _check_all_slots(self):
        """Тестирует каждый активный слот и заменяет нерабочие."""
        pool_status = self._pool.get_status()
        if not pool_status:
            return

        with self._lock:
            url       = self.test_url
            port      = SOCKS_PORT or 1181
            threshold = self.fail_threshold
            enabled   = self.enabled

        if not enabled:
            return

        with self._lock:
            self.state = "checking"

        all_ok = True
        for slot_info in pool_status:
            if not slot_info["alive"]:
                continue
            idx  = slot_info["index"]
            name = slot_info["strategy"] or "slot%d" % idx

            result = run_curl(port, url, timeout=12)
            self._pool.set_slot_health(idx, result["ok"])

            if result["ok"]:
                with self._lock:
                    self._slot_fails[idx] = 0
                self._log_event("ok", "✓ Слот %d «%s»" % (idx, name))
            else:
                with self._lock:
                    self._slot_fails[idx] = self._slot_fails.get(idx, 0) + 1
                    fails = self._slot_fails[idx]
                self._log_event("warn",
                    "✗ Слот %d «%s» (rc=%d, провалов: %d/%d)" % (
                        idx, name, result["rc"], fails, threshold))
                all_ok = False
                if fails >= threshold:
                    self._replace_slot(idx, name)

        with self._lock:
            self.state = "ok" if all_ok else "degraded"

    def _replace_slot(self, index, old_name):
        """Тихо заменяет стратегию в слоте без остановки трафика."""
        self._log_event("warn",
            "Слот %d «%s»: заменяю стратегию…" % (index, old_name))

        with self._lock:
            self.state = "replacing"

        new_name, new_nfqws = self._next_strategy()
        if not new_name:
            self._log_event("error", "Нет стратегий для замены слота %d" % index)
            return

        # Graceful replace: новый стартует, потом убивается старый
        self._pool.replace_slot(index, new_name, new_nfqws)

        with self._lock:
            self._slot_fails[index] = 0

        # Проверяем новую стратегию
        with self._lock:
            settle = self.settle_time
        time.sleep(settle)

        result = run_curl(SOCKS_PORT or 1080, self.test_url, timeout=12)
        if result["ok"]:
            self._log_event("ok",
                "✓ Слот %d: «%s» → «%s» — работает" % (index, old_name, new_name))
        else:
            self._log_event("warn",
                "✗ Слот %d: «%s» тоже не работает (rc=%d)" % (
                    index, new_name, result["rc"]))

        with self._lock:
            self.state = "ok"


# ── globals init ─────────────────────────────────────────────────────────────

_pool    = None
_switcher = None

# ── HTTP ─────────────────────────────────────────────────────────────────────

_HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("[panel] %s %s" % (self.address_string(), fmt % args), flush=True)

    def _send(self, code, ct, body):
        b = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _json(self, obj, code=200):
        self._send(code, "application/json; charset=utf-8",
                   json.dumps(obj, ensure_ascii=False))

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n)) if n else {}

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/":
            with open(_HTML, encoding="utf-8") as f:
                self._send(200, "text/html; charset=utf-8", f.read())
        elif p == "/api/config":
            lines = read_lines()
            self._json({"path": CFG_PATH, "raw": "\n".join(lines),
                        "nfqws_opt": get_nfqws(lines)})
        elif p == "/api/strategies":
            self._json({"strategies": list_strategies()})
        elif p == "/api/connections":
            self._json(get_connections(SS_PORT or 8388, SOCKS_PORT or 1080))
        elif p == "/api/pool/status":
            self._json(_switcher.get_status())
        elif p == "/api/pool/log":
            self._json({"log": _switcher.get_log()})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        p    = self.path.split("?")[0]
        body = self._body()

        # ── применить пресет (классический режим) ───────────────────────────
        if p == "/api/apply":
            name = body.get("preset")
            if not name:
                return self._json({"error": "нет поля preset"}, 400)
            nfqws = load_strategy_nfqws(name)
            if nfqws is None:
                return self._json({"error": "пресет не найден: " + name}, 404)
            lines = read_lines()
            set_nfqws(lines, nfqws)
            write_lines(lines)
            r = restart_zapret()
            written = read_lines()
            ok = r["rc"] == 0
            msg = ("Применён «%s» + zapret перезапущен" % name) if ok else \
                  ("restart ошибка rc=%d: %s" % (r["rc"], r.get("stderr", "")))
            return self._json({"ok": ok, "message": msg,
                               "raw": "\n".join(written),
                               "nfqws_opt": get_nfqws(written), "restart": r})

        # ── pool: вкл/выкл ───────────────────────────────────────────────────
        elif p == "/api/pool/enable":
            return self._json(_switcher.set_enabled(body.get("enabled", True)))

        # ── pool: настройки ──────────────────────────────────────────────────
        elif p == "/api/pool/configure":
            return self._json(_switcher.configure(body))

        # ── pool: ручная смена стратегии в слоте ────────────────────────────
        elif p == "/api/pool/slot/set":
            idx      = body.get("index")
            strategy = body.get("strategy")
            if idx is None or not strategy:
                return self._json({"error": "нужны index и strategy"}, 400)
            return self._json(_switcher.set_slot_strategy(int(idx), strategy))

        # ── pool: добавить слот ──────────────────────────────────────────────
        elif p == "/api/pool/slot/add":
            return self._json(_switcher.add_slot())

        # ── pool: убрать слот ────────────────────────────────────────────────
        elif p == "/api/pool/slot/remove":
            idx = body.get("index")
            if idx is None:
                return self._json({"error": "нужен index"}, 400)
            return self._json(_switcher.remove_slot(int(idx)))

        # ── pool: проверить все слоты ────────────────────────────────────────
        elif p == "/api/pool/check":
            _switcher.force_check()
            return self._json({"ok": True, "message": "Проверка запущена"})

        # ── сохранить NFQWS2_OPT вручную ────────────────────────────────────
        elif p == "/api/save-nfqws":
            value      = body.get("value", "")
            do_restart = body.get("restart", False)
            lines = read_lines()
            set_nfqws(lines, value)
            write_lines(lines)
            r = restart_zapret() if do_restart else None
            written = read_lines()
            return self._json({"ok": True, "raw": "\n".join(written),
                               "nfqws_opt": get_nfqws(written), "restart": r})

        # ── перезапуск zapret ────────────────────────────────────────────────
        elif p == "/api/restart":
            return self._json(restart_zapret())

        # ── curl тест ────────────────────────────────────────────────────────
        elif p == "/api/test-curl":
            url  = body.get("url", "https://google.com")
            port = int(body.get("socks_port", SOCKS_PORT or 1080))
            return self._json(run_curl(port, url))

        # ── импорт JSON ──────────────────────────────────────────────────────
        elif p == "/api/import-json":
            raw_str = body.get("raw")
            parsed  = json.loads(raw_str) if isinstance(raw_str, str) else body
            slist   = parsed.get("strategies")
            if not isinstance(slist, list) or not slist:
                return self._json({"error": "поле 'strategies' пустое"}, 400)
            domain = parsed.get("domain", "imported")
            prefix = body.get("name_prefix") or domain.replace(".", "_")
            saved, errors = [], []
            for i, s in enumerate(slist):
                args = s.get("args", "").strip()
                if not args: errors.append("#%d: args пустые" % i); continue
                if "--filter-tcp" not in args and "--filter-udp" not in args:
                    args = "--filter-tcp=443 --filter-l7=tls " + args
                proto   = s.get("protocol", "")
                rate    = s.get("success_rate", 0)
                latency = s.get("median_latency_ms", 0)
                speed   = s.get("median_speed_kbps", 0)
                fname   = "%s_%03d.conf" % (prefix, i + 1)
                fpath   = os.path.join(STRAT_DIR, fname)
                comment = "# domain=%s proto=%s rate=%.0f%% latency=%dms speed=%.0fkbps" % (
                    domain, proto, rate * 100, latency, speed)
                conf = '%s\nNFQWS2_OPT="\n%s\n"\n' % (comment, args)
                try:
                    os.makedirs(STRAT_DIR, exist_ok=True)
                    with open(fpath, "w", encoding="utf-8") as f:
                        f.write(conf)
                    saved.append(os.path.splitext(fname)[0])
                except Exception as e:
                    errors.append("%s: %s" % (fname, e))
            return self._json({"ok": True, "saved": saved, "errors": errors,
                               "message": "Сохранено %d, ошибок %d" % (len(saved), len(errors))})

        # ── бэкап ────────────────────────────────────────────────────────────
        elif p == "/api/backup":
            bak = CFG_PATH + ".bak"
            if os.path.exists(bak):
                return self._json({"ok": True, "raw": open(bak).read()})
            return self._json({"ok": False, "error": "бэкап отсутствует"})

        return self._json({"error": "not found"}, 404)


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config",       required=True)
    ap.add_argument("--strategies",   required=True)
    ap.add_argument("--port",         type=int, default=1888)
    ap.add_argument("--host",         default="0.0.0.0")
    ap.add_argument("--ss-port",      type=int, default=8388)
    ap.add_argument("--socks-port",   type=int, default=1080)
    ap.add_argument("--restart-cmd",
                    default="/opt/zapret2/init.d/sysv/zapret2 restart-daemons")
    args = ap.parse_args()

    global CFG_PATH, STRAT_DIR, RESTART_CMD, SOCKS_PORT, SS_PORT
    global _pool, _switcher
    CFG_PATH    = args.config
    STRAT_DIR   = args.strategies
    RESTART_CMD = args.restart_cmd
    SOCKS_PORT  = args.socks_port
    SS_PORT     = args.ss_port

    def _log(lvl, msg):
        print("[pool][%s] %s" % (lvl.upper(), msg), flush=True)

    _pool     = PoolManager(log_fn=_log)
    _switcher = PoolSwitcher(_pool)

    print("[panel] config=%s  strategies=%s  ss=%d  socks=%d" % (
        CFG_PATH, STRAT_DIR, SS_PORT, SOCKS_PORT), flush=True)

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print("[panel] http://%s:%d" % (args.host, args.port), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()