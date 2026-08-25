#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Веб-панель управления стратегиями zapret2.

Запуск (внутри контейнера):
    python3 /opt/zapret2/panel/server.py \
        --config /opt/zapret2/config \
        --strategies /opt/zapret2/strategies \
        --port 1888

Только стандартная библиотека Python 3. Внешних зависимостей нет.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CFG_PATH = None
STRAT_DIR = None
RESTART_CMD = None
SOCKS_PORT = None

# --------------------------------------------------------------------------
# Схема (поля стратегии)
# --------------------------------------------------------------------------

def load_schema():
    path = os.path.join(STRAT_DIR, "schema.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)

SCHEMA = None
FIELD_KEYS = []
STRATEGY_KEYS = []
MULTILINE_KEYS = set()

def init_schema():
    global SCHEMA, FIELD_KEYS, STRATEGY_KEYS, MULTILINE_KEYS
    SCHEMA = load_schema()
    FIELD_KEYS = [f["key"] for f in SCHEMA["fields"]]
    STRATEGY_KEYS = SCHEMA["strategyKeys"]
    MULTILINE_KEYS = set(f["key"] for f in SCHEMA["fields"] if f.get("type") == "multiline")

KEY_RE = re.compile(r"^([A-Za-z0-9_]+)=(.*)$")

# --------------------------------------------------------------------------
# Чтение / запись файла config (key=value, .conf стиль)
# --------------------------------------------------------------------------

def read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return f.read().splitlines()


def read_value(lines, key):
    """Возвращает значение ключа (для многострочных — соединённых '\n'), либо None."""
    pat = re.compile("^" + re.escape(key) + "=")
    for i, ln in enumerate(lines):
        if not pat.match(ln):
            continue
        body = ln.split("=", 1)[1].strip()
        if key not in MULTILINE_KEYS:
            return body
        # Многострочное значение в кавычках
        if not body.startswith('"'):
            buf = []
            j = i + 1
            while j < len(lines) and not KEY_RE.match(lines[j]):
                buf.append(lines[j])
                j += 1
            return "\n".join(buf).strip("\n")
        if body.count('"') >= 2 and body.endswith('"'):
            return body[1:-1]
        buf = []
        j = i + 1
        while j < len(lines) and not lines[j].rstrip().endswith('"'):
            buf.append(lines[j])
            j += 1
        if j < len(lines):
            closing = lines[j].rstrip()
            content = closing[:-1] if closing != '"' else ""
            if content:
                buf.append(content)
        return "\n".join(buf)
    return None


def set_value(lines, key, value):
    if key in MULTILINE_KEYS:
        _set_multiline(lines, key, value)
    else:
        _set_simple(lines, key, value)


def _set_simple(lines, key, value):
    pat = re.compile("^" + re.escape(key) + "=")
    for i, ln in enumerate(lines):
        if pat.match(ln):
            lines[i] = key + "=" + value
            return
    lines.append(key + "=" + value)


def _set_multiline(lines, key, value):
    pat = re.compile("^" + re.escape(key) + "=")
    start = None
    for i, ln in enumerate(lines):
        if pat.match(ln):
            start = i
            break

    if start is not None:
        body = lines[start].split("=", 1)[1].strip()
        if body.count('"') >= 2 and not any(c in body for c in "\\"):
            if body.endswith('"'):
                del lines[start]
            else:
                del lines[start]
        else:
            end = start
            while end < len(lines) and not (end > start and lines[end].rstrip().endswith('"')):
                end += 1
            if end < len(lines):
                del lines[start:end + 1]
            else:
                del lines[start:]

    block = [key + '="']
    if value:
        block += value.rstrip("\n").split("\n")
    block.append('"')
    lines.extend(block)


def parse_preset(text):
    kv = {}
    open_key = None
    for raw in text.splitlines():
        line = raw.rstrip()
        m = KEY_RE.match(line)
        if m and not line.startswith(("--", "-")):
            key, val = m.group(1), m.group(2).strip()
            kv[key] = val
            open_key = key
        elif line.lstrip().startswith("#") or line.strip() == "":
            open_key = None
        elif open_key is not None and open_key in MULTILINE_KEYS:
            kv[open_key] = (kv.get(open_key, "") + "\n" + line).strip("\n")
        else:
            open_key = None
    return kv


def current_fields(lines):
    out = {}
    for f in SCHEMA["fields"]:
        key = f["key"]
        val = read_value(lines, key)
        out[key] = val if val is not None else f.get("default", "")
    return out


# --------------------------------------------------------------------------
# Стратегии (пресеты)
# --------------------------------------------------------------------------

def list_strategies():
    out = []
    if not os.path.isdir(STRAT_DIR):
        logging.warning("Директория стратегий не найдена или не является папкой: %s", STRAT_DIR)
        return out
        
    logging.info("Сканирование директории стратегий: %s", STRAT_DIR)
    try:
        files = sorted(os.listdir(STRAT_DIR))
    except Exception as e:
        logging.error("Не удалось прочитать содержимое директории %s: %s", STRAT_DIR, str(e))
        return out

    for fn in files:
        if not fn.endswith(".conf"):
            continue
        path = os.path.join(STRAT_DIR, fn)
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read()
            kv = parse_preset(text)
            desc = ""
            for line in text.splitlines():
                if line.lstrip().startswith("#"):
                    desc = line.lstrip("#").strip()
                    break
            out.append({
                "name": os.path.splitext(fn)[0],
                "file": fn,
                "description": desc,
                "values": kv,
                "contains_nfqws": "NFQWS2_OPT" in kv,
            })
        except Exception as e:
            logging.error("Ошибка при чтении или парсинге файла стратегии %s: %s", fn, str(e))
            
    logging.info("Успешно загружено стратегий: %d", len(out))
    return out


def load_strategy(name):
    path = os.path.join(STRAT_DIR, name + ".conf")
    if not os.path.isfile(path):
        logging.warning("Запрошенная стратегия не найдена на диске: %s", path)
        return None
        
    logging.info("Загрузка параметров стратегии: %s", name)
    try:
        with open(path, encoding="utf-8") as f:
            return parse_preset(f.read())
    except Exception as e:
        logging.error("Не удалось прочитать файл стратегии %s: %s", name, str(e))
        return None


def load_text(name):
    return load_strategy(name)


def write_config(lines):
    # Бэкап
    if os.path.exists(CFG_PATH):
        try:
            shutil.copy2(CFG_PATH, CFG_PATH + ".bak")
            logging.info("Создан бэкап конфигурации: %s.bak", CFG_PATH)
        except Exception as e:
            logging.warning("Ошибка создания бэкапа: %s", str(e))
    try:
        with open(CFG_PATH, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        logging.info("Конфигурация успешно перезаписана: %s", CFG_PATH)
    except Exception as e:
        logging.error("Критическая ошибка записи конфигурации: %s", str(e))
        raise e


def restart_zapret():
    if not RESTART_CMD:
        logging.warning("Запрос на перезапуск отклонен: команда не задан (--restart-cmd)")
        return {"rc": 0, "stdout": "Перезапуск не задан (--restart-cmd)", "stderr": ""}
        
    logging.info("Запуск перезапуска службы zapret: %s", RESTART_CMD)
    try:
        p = subprocess.run(RESTART_CMD, shell=True, capture_output=True, text=True, timeout=120)
        
        if p.returncode == 0:
            logging.info("Служба zapret успешно перезапущена (rc=0)")
        else:
            logging.error("Ошибка перезапуска zapret (rc=%d). Stderr: %s", p.returncode, p.stderr.strip())
            
        return {"rc": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}
    except subprocess.TimeoutExpired:
        logging.error("Таймаут выполнения команды перезапуска (120с)")
        return {"rc": -1, "stdout": "", "stderr": "Таймаут выполнения команды"}
    except Exception as e:
        logging.error("Исключение при перезапуске службы: %s", str(e))
        return {"rc": -1, "stdout": "", "stderr": str(e)}



def run_curl_test(socks_port, url="https://google.com"):
    """curl через SOCKS5 прокси, возвращает заголовки ответа."""
    cmd = [
        "curl", "-x", "socks5h://127.0.0.1:%d" % socks_port,
        url, "-I",
        "--max-time", "15",
        "--connect-timeout", "8",
        "-s", "-S",
    ]
    logging.info("Проверка связи")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        output = (p.stdout or "") + (p.stderr or "")
        ok = p.returncode == 0 and ("200" in p.stdout or "301" in p.stdout or "302" in p.stdout)
        if ok:
            logging.info("Проверка связи: УСПЕШНО (Код %d)", p.returncode)
        else:
            logging.warning("Проверка связи: ОШИБКА (Код %d). Вывод: %s", p.returncode, output.strip())
            
        return {"ok": ok, "rc": p.returncode, "output": output.strip()}

    except FileNotFoundError:
        logging.error("Проверка связи: curl не найден в PATH")
        return {"ok": False, "rc": -1, "output": "curl не найден в PATH"}
    except subprocess.TimeoutExpired:
        logging.error("Проверка связи: Таймаут (20с)")
        return {"ok": False, "rc": -1, "output": "Таймаут (20с)"}
    except Exception as e:
        logging.error("Проверка связи: Неизвестная ошибка: %s", str(e))
        return {"ok": False, "rc": -1, "output": str(e)}


INDEX_HTML = open(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html"),
    encoding="utf-8",
).read()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("[panel] %s - - %s" % (self.address_string(), fmt % args), flush=True)

    def _send(self, code, content_type, body_bytes):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def _json(self, obj, code=200):
        self._send(code, "application/json; charset=utf-8",
                   json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        client_ip = self.address_string()
        logging.info("GET %s от %s", path, client_ip)

        if path == "/":
            self._send(200, "text/html; charset=utf-8", INDEX_HTML.encode("utf-8"))
        elif path == "/api/schema":
            self._json(SCHEMA)
        elif path == "/api/config":
            lines = read_lines(CFG_PATH)
            self._json({
                "config_path": CFG_PATH,
                "raw": "\n".join(lines),
                "fields": current_fields(lines),
            })
        elif path == "/api/strategies":
            self._json({"strategies": list_strategies()})
        else:
            logging.warning("GET %s - Маршрут не найден (404) для %s", path, client_ip)
            self._json({"error": "Not found"}, 404)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        client_ip = self.address_string()
        body = self._read_body()
        lines = read_lines(CFG_PATH)
        logging.info("POST %s от %s", path, client_ip)

        if path == "/api/apply":
            preset = body.get("preset")
            fields = body.get("fields")
            do_restart = body.get("restart", False)
            
            if isinstance(preset, str):
                logging.info("Запрос на применение пресета: %s", preset)
                kv = load_text(preset)
                if kv is None:
                    logging.warning("Пресет «%s» не обнаружен на диске", preset)
                    return self._json({"error": "Пресет не найден"}, 404)
                msg = "Применён пресет «%s»" % preset
                do_restart = True
            elif isinstance(fields, dict):
                logging.info("Запрос на ручное обновление полей конфигурации")
                kv = {k: v for k, v in fields.items() if k in FIELD_KEYS}
                msg = "Применены поля вручную"
            else:
                logging.warning("Некорректный формат тела запроса /api/apply")
                return self._json({"error": "Ожидается preset или fields"}, 400)

            for key, value in kv.items():
                value = str(value).strip()
                if not value and key not in MULTILINE_KEYS:
                    continue
                set_value(lines, key, value)
            write_config(lines)

            restart_result = None
            if do_restart:
                restart_result = restart_zapret()
                if restart_result["rc"] != 0:
                    msg += " (перезапуск: ошибка — %s)" % (restart_result.get("stderr") or "rc=%d" % restart_result["rc"])
                else:
                    msg += " + zapret перезапущен"

            written_lines = read_lines(CFG_PATH)
            return self._json({
                "ok": True, "message": msg,
                "raw": "\n".join(written_lines),
                "fields": current_fields(written_lines),
                "restart": restart_result,
            })

        elif path == "/api/restart":
            logging.info("Принудительный запрос на ручной перезапуск zapret")
            return self._json(restart_zapret())

        elif path == "/api/test-curl":
            url = body.get("url", "https://google.com")
            port = int(body.get("socks_port", SOCKS_PORT or 1080))
            logging.info("Запрос curl-теста для URL: %s через SOCKS-порт: %d", url, port)
            result = run_curl_test(port, url)
            return self._json(result)

        elif path == "/api/import-json":
            logging.info("Запрос на импорт стратегий из JSON")
            raw_str = body.get("raw")
            if isinstance(raw_str, str):
                try:
                    parsed = json.loads(raw_str)
                except Exception as e:
                    logging.error("Сбой парсинга входящего JSON при импорте: %s", str(e))
                    return self._json({"error": "Невалидный JSON: %s" % str(e)}, 400)
            else:
                parsed = body

            strategies_list = parsed.get("strategies")
            if not isinstance(strategies_list, list) or not strategies_list:
                logging.warning("Импорт отклонен: массив 'strategies' пуст или отсутствует")
                return self._json({"error": "Поле 'strategies' отсутствует или пустое"}, 400)

            domain = parsed.get("domain", "imported")
            name_prefix = body.get("name_prefix") or domain.replace(".", "_")
            saved = []
            errors = []
            
            for i, s in enumerate(strategies_list):
                args = s.get("args", "").strip()
                if not args:
                    errors.append("Стратегия #%d: поле args пустое" % i)
                    continue
                protocol = s.get("protocol", "")
                success_rate = s.get("success_rate", 0)
                latency = s.get("median_latency_ms", 0)
                speed = s.get("median_speed_kbps", 0)

                nfqws_opt = "--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello %s" % args
                fname_base = "%s_%03d" % (name_prefix, i + 1)
                fname = fname_base + ".conf"
                fpath = os.path.join(STRAT_DIR, fname)

                conf_lines = [
                    "# Авто-импорт: domain=%s proto=%s rate=%.0f%% latency=%dms speed=%.0fkbps" % (
                        domain, protocol, success_rate * 100, latency, speed),
                    "NFQWS2_OPT=",
                    nfqws_opt,
                ]
                try:
                    with open(fpath, "w", encoding="utf-8") as f:
                        f.write("\n".join(conf_lines) + "\n")
                    saved.append(fname_base)
                except Exception as e:
                    logging.error("Не удалось сохранить файл импортированной стратегии %s: %s", fname, str(e))
                    errors.append("%s: %s" % (fname, str(e)))

            logging.info("Импорт завершен. Сохранено стратегий: %d, ошибок: %d", len(saved), len(errors))
            return self._json({
                "ok": True,
                "saved": saved,
                "errors": errors,
                "message": "Сохранено %d strategies, ошибок %d" % (len(saved), len(errors)),
            })

        elif path == "/api/backup":
            bak_path = CFG_PATH + ".bak"
            if os.path.exists(bak_path):
                logging.info("Запрошено чтение бэкапа конфигурации: %s", bak_path)
                try:
                    with open(bak_path, encoding="utf-8") as f:
                        data = f.read()
                    return self._json({"ok": True, "raw": data})
                except Exception as e:
                    logging.error("Не удалось прочитать существующий файл бэкапа: %s", str(e))
                    return self._json({"ok": False, "error": str(e)})
            
            logging.warning("Запрос бэкапа отклонен: файл %s отсутствует", bak_path)
            return self._json({"ok": False, "error": "Бэкап отсутствует"})

        logging.warning("POST %s - Маршрут не найден (404) для %s", path, client_ip)
        return self._json({"error": "Not found"}, 404)


import argparse
import sys
import logging
from http.server import ThreadingHTTPServer

def main():
    ap = argparse.ArgumentParser(description="zapret web panel")
    ap.add_argument("--config", required=True)
    ap.add_argument("--strategies", required=True)
    ap.add_argument("--port", type=int, default=1888)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--socks-port", type=int, default=1080,
                    help="Порт SOCKS5 прокси для теста curl")
    ap.add_argument("--restart-cmd",
                    default="/opt/zapret2/init.d/sysv/zapret2 restart-daemons")
    args = ap.parse_args()

    logging.basicConfig(
        stream=sys.stdout,
        level=logging.INFO,
        format='[panel] %(message)s'
    )

    global CFG_PATH, STRAT_DIR, RESTART_CMD, SOCKS_PORT
    CFG_PATH = args.config
    STRAT_DIR = args.strategies
    RESTART_CMD = args.restart_cmd
    SOCKS_PORT = args.socks_port
    
    logging.info("Инициализация схемы данных...")
    init_schema()

    logging.info("Параметры запуска: config=%s | strategies=%s | socks_port=%d", CFG_PATH, STRAT_DIR, SOCKS_PORT)

    try:
        server = ThreadingHTTPServer((args.host, args.port), Handler)
        logging.info("Веб-панель успешно запущена и доступна по адресу: http://%s:%d", args.host, args.port)
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Получен сигнал остановки (Ctrl+C). Завершение работы веб-панели...")
        server.server_close()
    except Exception as e:
        logging.critical("Критическая ошибка при работе веб-сервера панели: %s", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
