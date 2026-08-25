#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Веб-панель управления zapret2.

python3 /opt/zapret2/panel/server.py \
    --config /opt/zapret2/config \
    --strategies /opt/zapret2/strategies \
    --port 1888 \
    --socks-port 1080

Только стандартная библиотека Python 3.
"""
import argparse, json, os, re, shutil, subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CFG_PATH    = None
STRAT_DIR   = None
RESTART_CMD = None
SOCKS_PORT  = None

MULTILINE_KEY = "NFQWS2_OPT"
_KEY_RE = re.compile(r"^([A-Z0-9_]+)=")


# ── config helpers ─────────────────────────────────────────────────────────

def read_lines():
    if not os.path.exists(CFG_PATH):
        return []
    with open(CFG_PATH, encoding="utf-8") as f:
        return f.read().splitlines()


def write_lines(lines):
    if os.path.exists(CFG_PATH):
        try:
            shutil.copy2(CFG_PATH, CFG_PATH + ".bak")
        except Exception as e:
            print("[panel] backup warning:", e, flush=True)
    with open(CFG_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("[panel] config written:", CFG_PATH, flush=True)


def get_nfqws(lines):
    """Вернуть тело NFQWS2_OPT без кавычек-оберток."""
    pat = re.compile(r"^NFQWS2_OPT=")
    for i, ln in enumerate(lines):
        if not pat.match(ln):
            continue
        body = ln.split("=", 1)[1].strip()
        # однострочный: NFQWS2_OPT="..."
        if body.startswith('"') and body.endswith('"') and len(body) > 1:
            return body[1:-1]
        # многострочный открывается кавычкой на этой же строке или следующих
        buf = []
        j = i + 1
        while j < len(lines):
            raw = lines[j]
            if raw.rstrip() == '"':      # закрывающая кавычка
                break
            if _KEY_RE.match(raw):       # начало следующего ключа — без кавычек
                break
            buf.append(raw)
            j += 1
        return "\n".join(buf).strip("\n")
    return ""


def set_nfqws(lines, value):
    """Записать NFQWS2_OPT как многострочный блок, удалив старый."""
    _remove_key(lines, MULTILINE_KEY)
    block = ['NFQWS2_OPT="'] + value.strip("\n").splitlines() + ['"']
    lines.extend(block)


def _remove_key(lines, key):
    pat = re.compile(r"^" + re.escape(key) + r"=")
    start = next((i for i, ln in enumerate(lines) if pat.match(ln)), None)
    if start is None:
        return
    if key != MULTILINE_KEY:
        del lines[start]
        return
    end = start + 1
    while end < len(lines):
        if lines[end].rstrip() == '"':
            end += 1
            break
        if _KEY_RE.match(lines[end]):
            break
        end += 1
    del lines[start:end]


# ── strategies ─────────────────────────────────────────────────────────────

def list_strategies():
    if not os.path.isdir(STRAT_DIR):
        return []
    result = []
    for fn in sorted(os.listdir(STRAT_DIR)):
        if not fn.endswith(".conf"):
            continue
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
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        return get_nfqws(f.read().splitlines())


# ── zapret ─────────────────────────────────────────────────────────────────

def restart_zapret():
    cmd = RESTART_CMD
    print("[panel] restart:", cmd, flush=True)
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        print("[panel] restart rc=%d" % p.returncode, flush=True)
        return {"rc": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}
    except Exception as e:
        return {"rc": -1, "stdout": "", "stderr": str(e)}


def run_curl(port, url):
    cmd = ["curl", "-x", "socks5h://127.0.0.1:%d" % port,
           url, "-I", "--max-time", "15", "--connect-timeout", "8", "-s", "-S"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        out = (p.stdout or "") + (p.stderr or "")
        ok = p.returncode == 0 and bool(re.search(r"HTTP/\S+ [23]", p.stdout))
        return {"ok": ok, "rc": p.returncode, "output": out.strip()}
    except FileNotFoundError:
        return {"ok": False, "rc": -1, "output": "curl не найден"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "rc": -1, "output": "Таймаут 20с"}
    except Exception as e:
        return {"ok": False, "rc": -1, "output": str(e)}


# ── HTTP ───────────────────────────────────────────────────────────────────

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
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        p = self.path.split("?")[0]
        body = self._body()

        if p == "/api/apply":
            name = body.get("preset")
            if not name:
                return self._json({"error": "нет поля preset"}, 400)
            nfqws = load_strategy_nfqws(name)
            if nfqws is None:
                return self._json({"error": "пресет не найден: " + name}, 404)
            if not nfqws.strip():
                return self._json({"error": "пресет не содержит NFQWS2_OPT"}, 400)
            lines = read_lines()
            set_nfqws(lines, nfqws)
            write_lines(lines)
            r = restart_zapret()
            written = read_lines()
            ok = r["rc"] == 0
            msg = ("Применён «%s» + zapret перезапущен" % name) if ok else \
                  ("Применён «%s» | restart ошибка rc=%d: %s" % (name, r["rc"], r.get("stderr", "")))
            return self._json({"ok": ok, "message": msg,
                               "raw": "\n".join(written),
                               "nfqws_opt": get_nfqws(written),
                               "restart": r})

        elif p == "/api/save-nfqws":
            value = body.get("value", "")
            do_restart = body.get("restart", False)
            lines = read_lines()
            set_nfqws(lines, value)
            write_lines(lines)
            r = restart_zapret() if do_restart else None
            written = read_lines()
            return self._json({"ok": True, "raw": "\n".join(written),
                               "nfqws_opt": get_nfqws(written), "restart": r})

        elif p == "/api/restart":
            return self._json(restart_zapret())

        elif p == "/api/test-curl":
            url  = body.get("url", "https://google.com")
            port = int(body.get("socks_port", SOCKS_PORT or 1080))
            return self._json(run_curl(port, url))

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
                if not args:
                    errors.append("#%d: args пустые" % i); continue
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

        elif p == "/api/backup":
            bak = CFG_PATH + ".bak"
            if os.path.exists(bak):
                return self._json({"ok": True, "raw": open(bak).read()})
            return self._json({"ok": False, "error": "бэкап отсутствует"})

        return self._json({"error": "not found"}, 404)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config",      required=True)
    ap.add_argument("--strategies",  required=True)
    ap.add_argument("--port",        type=int, default=1888)
    ap.add_argument("--host",        default="0.0.0.0")
    ap.add_argument("--socks-port",  type=int, default=1080)
    ap.add_argument("--restart-cmd",
                    default="/opt/zapret2/init.d/sysv/zapret2 restart-daemons")
    args = ap.parse_args()

    global CFG_PATH, STRAT_DIR, RESTART_CMD, SOCKS_PORT
    CFG_PATH    = args.config
    STRAT_DIR   = args.strategies
    RESTART_CMD = args.restart_cmd
    SOCKS_PORT  = args.socks_port

    print("[panel] config=%s  strategies=%s  socks=%d" % (CFG_PATH, STRAT_DIR, SOCKS_PORT), flush=True)
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print("[panel] http://%s:%d" % (args.host, args.port), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
