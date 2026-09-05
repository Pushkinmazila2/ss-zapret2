#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Веб-панель управления zapret2 с пулом nfqws2 и авто-переключением.
"""
import argparse, collections, json, os, re, shutil, subprocess
import sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pool_manager as _pm
from pool_manager import PoolManager, MAX_SLOTS
from conn_tracker import LifetimeTracker
from cut_logger import CutLogger
try:
    import tspu_intel as _ti
    from tspu_intel import build_tspu_intel_from_env
except Exception as _tie:
    _ti = None
    build_tspu_intel_from_env = None
    print("[panel] tspu_intel unavailable: %s" % _tie, flush=True)

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
    """
    Устанавливает в config:
      NFQWS2_ENABLE=0  — отключает стандартный nfqws2 демон (не создаёт правила)
      DISABLE_CUSTOM=1 — отключает custom.d хуки, чтобы init-скрипт zapret2
                         НЕ пересоздавал стандартные NFQUEUE num 300 поверх пула.
                         Всеми правилами firewall управляет pool_manager напрямую.
    """
    def _set_simple(key, val):
        pat = re.compile(r"^" + re.escape(key) + r"=")
        for i, ln in enumerate(lines):
            if pat.match(ln): lines[i] = key + "=" + val; return
        lines.append(key + "=" + val)
    _set_simple("NFQWS2_ENABLE", "0")
    _set_simple("DISABLE_CUSTOM", "1")

# ── strategies ──────────────────────────────────────────────────────────────

def list_strategies():
    if not STRAT_DIR or not os.path.isdir(STRAT_DIR): return []
    result = []
    for fn in sorted(os.listdir(STRAT_DIR)):
        if not fn.endswith(".conf"): continue
        fpath = os.path.join(STRAT_DIR, fn)
        with open(fpath, encoding="utf-8") as f:
            flines = f.read().splitlines()
        desc = next((ln.lstrip("#").strip() for ln in flines if ln.strip().startswith("#")), "")
        nfqws_opt = get_nfqws(flines)
        result.append({
            "name": os.path.splitext(fn)[0],
            "file": fn,
            "description": desc,
            "nfqws_opt": nfqws_opt,
            "has_nfqws": bool((nfqws_opt or "").strip()),
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

# ── ResetMonitor ─────────────────────────────────────────────────────────────

SS_LOG_PATH = "/run/zapret-pool/ss-server.log"

class ResetMonitor:
    """
    Читает лог ss-server в реальном времени.
    Считает соотношение reset / (reset + normal_close) за скользящее окно.
    Если ratio > threshold — сигнализирует о деградации.

    Строки которые считаем:
      reset:  "Connection reset by peer"
      close:  "close a connection"  (нормальное закрытие)
    """

    MAX_EVENTS = 500   # максимум событий в скользящем окне

    def __init__(self):
        self._lock          = threading.Lock()
        # настройки
        self.window_sec     = 60
        self.threshold      = 0.4
        self.min_events     = 5
        # состояние
        self._events        = collections.deque()
        self._file_pos      = 0
        self._thread        = None
        self._stop_evt      = threading.Event()
        self.degraded       = False
        self._was_degraded  = False   # edge-trigger: срабатываем только при переходе
        self.last_ratio     = 0.0
        self.total_resets   = 0
        self.total_closes   = 0
        self.on_degraded    = None    # callback fn() при переходе ok → degraded
        self.on_reset       = None    # callback fn() на каждое reset-событие
        self.last_reset_ts  = None    # метка последнего reset (для трекера срезов)
        self._ss_tail       = collections.deque(maxlen=60)   # хвост сырых строк ss-server лога

    def ss_log_tail(self, limit=40):
        """Последние строки ss-server лога (для журнала срезов)."""
        with self._lock:
            return list(self._ss_tail)[-int(limit):]

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_evt.clear()
        self._thread = threading.Thread(target=self._tail_loop, daemon=True)
        self._thread.start()
        print("[monitor] Started tailing %s" % SS_LOG_PATH, flush=True)

    def get_status(self):
        with self._lock:
            now = time.time()
            win = self._window_events(now)
            resets = sum(1 for _, t in win if t == "reset")
            closes = sum(1 for _, t in win if t == "close")
            total  = resets + closes
            ratio  = resets / total if total >= self.min_events else 0.0
            return {
                "degraded":      ratio >= self.threshold and total >= self.min_events,
                "ratio":         round(ratio, 3),
                "resets_window": resets,
                "closes_window": closes,
                "total_window":  total,
                "total_resets":  self.total_resets,
                "total_closes":  self.total_closes,
                "last_reset_ts": self.last_reset_ts,
                "window_sec":    self.window_sec,
                "threshold":     self.threshold,
                "min_events":    self.min_events,
            }

    def configure(self, cfg):
        with self._lock:
            for k in ("window_sec", "threshold", "min_events"):
                if k in cfg:
                    setattr(self, k, cfg[k])
        return self.get_status()

    # ── internals ─────────────────────────────────────────────────────────

    def _tail_loop(self):
        """Бесконечно читает новые строки из лог файла."""
        while not self._stop_evt.is_set():
            try:
                if not os.path.exists(SS_LOG_PATH):
                    self._stop_evt.wait(2)
                    continue
                with open(SS_LOG_PATH, "r", errors="replace") as f:
                    f.seek(self._file_pos)
                    while not self._stop_evt.is_set():
                        line = f.readline()
                        if not line:
                            self._file_pos = f.tell()
                            self._stop_evt.wait(0.5)
                            continue
                        self._parse_line(line)
                        try:
                            with self._lock:
                                self._ss_tail.append(line.rstrip())
                        except Exception:
                            pass
            except Exception as e:
                print("[monitor] tail error: %s" % e, flush=True)
                self._stop_evt.wait(2)

    def _parse_line(self, line):
        now = time.time()
        event = None
        if "Connection reset by peer" in line or "server_recv_cb_recv" in line:
            event = "reset"
        elif "close a connection" in line:
            event = "close"
        if not event:
            return
        with self._lock:
            self._events.append((now, event))
            if event == "reset":
                self.total_resets += 1
                self.last_reset_ts = now
            else:
                self.total_closes += 1
            # Чистим старые события
            while self._events and now - self._events[0][0] > self.window_sec * 2:
                self._events.popleft()
            # Ограничиваем размер
            while len(self._events) > self.MAX_EVENTS:
                self._events.popleft()
            # Обновляем статус деградации
            win    = self._window_events(now)
            resets = sum(1 for _, t in win if t == "reset")
            closes = sum(1 for _, t in win if t == "close")
            total  = resets + closes
            self.last_ratio = resets / total if total > 0 else 0.0
            self.degraded   = (self.last_ratio >= self.threshold
                               and total >= self.min_events)
            fire = self.degraded and not self._was_degraded
            self._was_degraded = self.degraded
            if event == "reset":
                print("[monitor] reset ratio=%.2f (%d/%d)" % (
                    self.last_ratio, resets, total), flush=True)

        if fire and self.on_degraded:
            print("[monitor] degraded edge — triggering immediate check", flush=True)
            threading.Thread(target=self.on_degraded, daemon=True).start()

        if event == "reset" and self.on_reset:
            try:
                self.on_reset()
            except Exception as e:
                print("[monitor] on_reset: %s" % e, flush=True)

    def _window_events(self, now):
        cutoff = now - self.window_sec
        return [(ts, t) for ts, t in self._events if ts >= cutoff]


# глобальный экземпляр
reset_monitor = ResetMonitor()

# отдельный журнал «оборванных» соединений (срезы ТСПУ).
# Путь: CUT_LOG_PATH, иначе — /opt/zapret2/logs/cuts.log, если каталог
# смонтирован (переживает рестарт контейнера), иначе /run/zapret-pool/cuts.log
_log_dir = os.environ.get("CUT_LOG_DIR", "/opt/zapret2/logs")
if os.path.isdir(_log_dir):
    CUT_LOG_DEFAULT = os.path.join(_log_dir, "cuts.log")
else:
    CUT_LOG_DEFAULT = "/run/zapret-pool/cuts.log"
CUT_LOG_PATH = os.environ.get("CUT_LOG_PATH") or CUT_LOG_DEFAULT
cut_logger = CutLogger(path=CUT_LOG_PATH)
_tspu_intel = None
_tspu_intel_log = lambda lvl, msg: print("[tspu-intel][%s] %s" % (lvl, msg), flush=True)
if _ti is not None:
    _tspu_intel = build_tspu_intel_from_env(log_fn=_tspu_intel_log)
    try:
        _parent = os.path.dirname(CUT_LOG_PATH) or "/opt/zapret2/logs"
        os.makedirs(_parent, exist_ok=True)
        _tspu_intel.intel_log.path = os.path.join(_parent, "tspu_intel.jsonl")
    except Exception:
        pass
    _tspu_intel.register_cut_logger_callback(
        lambda rec: cut_logger.record({"kind": "tspu_intel","cut_id": rec.get("cut_id"),"vector": rec.get("vector")}))

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

        # ротация при срезе ТСПУ (соединение умерло, прожив 30-60с)
        self.cut_rotate_enabled = True
        self.cut_min_sec        = 30
        self.cut_max_sec        = 60
        self.cut_cooldown       = 30     # мин. пауза между ротациями по срезу
        self.cut_require_reset  = False  # подтверждать срез reset-событием из лога
        # эпидемия: >= N коротких RST-смертей за окно
        self.epidemic_min_events  = 4
        self.short_min_sec        = 5
        self.epidemic_window_sec  = 60

        # Fail-Fast замена при срезе ТСПУ (события classic / epidemic)
        self.shadow_test_enabled = False  # теневой curl-тест ВЫКЛЮЧЕН: пока ТСПУ
                                          # рвёт соединения, долгие тесты только
                                          # мешают (включается через configure)
        self.shadow_window       = 10     # окно наблюдения теневого слота, сек
        self.shadow_min_pkts     = 2      # мин. пакетов через теневую очередь

        # состояние
        self.state           = "idle"
        self._slot_fails     = {}       # index → consecutive fails
        self._strategy_idx   = 0       # указатель в списке стратегий
        self._used           = set()   # имена уже назначенных стратегий
        self._demoted        = set()   # стратегии, отправленные в конец пула резерва
        self._cut_last_ts    = None    # метка последней ротации по срезу
        self.strategy_scores = {}   # name → score: +1.0 успех, −2.0 провал, ×0.98 старение
        self._log            = collections.deque(maxlen=self.MAX_LOG)

    # ── public ────────────────────────────────────────────────────────────

    def get_status(self):
        with self._lock:
            pool_status = self._pool.get_status()
            tstat = _tracker.get_status() if _tracker is not None else {}
            return {
                "enabled":        self.enabled,
                "mode":           self.mode,
                "pool_size":      self.pool_size,
                "state":          self.state,
                "check_interval": self.check_interval,
                "fail_threshold": self.fail_threshold,
                "settle_time":    self.settle_time,
                "test_url":       self.test_url,
                # ротация при срезе ТСПУ
                "cut_rotate_enabled": self.cut_rotate_enabled,
                "cut_min_sec":        self.cut_min_sec,
                "cut_max_sec":        self.cut_max_sec,
                "cut_cooldown":       self.cut_cooldown,
                "cut_require_reset":  self.cut_require_reset,
                "epidemic_min_events":  self.epidemic_min_events,
                "short_min_sec":        self.short_min_sec,
                "epidemic_window_sec":  self.epidemic_window_sec,
                # fail-fast замена при срезе
                "shadow_test_enabled": self.shadow_test_enabled,
                "shadow_window":       self.shadow_window,
                "shadow_min_pkts":     self.shadow_min_pkts,
                # статус трекера соединений
                "tracker": tstat,
                "active_conns": tstat.get("active_conns", 0),
                "total_cuts":   tstat.get("total_cuts", 0),
                "last_cut_ts":  tstat.get("last_cut_ts"),
                "last_cut_lifetime": tstat.get("last_cut_lifetime"),
                "slots":          pool_status,
                "healthy_count": sum(1 for s in pool_status if s.get("healthy") is True),
                "strategy_scores": dict(self.strategy_scores),
                "strategy_idx":   self._strategy_idx,
            }

    def get_log(self):
        with self._lock:
            return list(self._log)

    def configure(self, cfg):
        with self._lock:
            valid = ("mode", "pool_size", "check_interval", "fail_threshold",
                     "settle_time", "test_url",
                     "cut_rotate_enabled", "cut_min_sec", "cut_max_sec",
                     "cut_cooldown", "cut_require_reset",
                     "epidemic_min_events", "short_min_sec", "epidemic_window_sec",
                     "shadow_test_enabled", "shadow_window", "shadow_min_pkts")
            for k in valid:
                if k in cfg:
                    setattr(self, k, cfg[k])
            # сопоставление сокращённого имени из UI
            if "cut_epidemic" in cfg:
                self.epidemic_min_events = cfg["cut_epidemic"]
            self.cut_rotate_enabled  = bool(self.cut_rotate_enabled)
            lo = min(self.cut_min_sec, self.cut_max_sec)
            hi = max(self.cut_min_sec, self.cut_max_sec)
            self.cut_min_sec  = max(5, lo)
            self.cut_max_sec  = max(max(10, hi), self.cut_min_sec)
            self.cut_cooldown = max(0, self.cut_cooldown)
            self.epidemic_min_events = max(2, int(self.epidemic_min_events))
            self.epidemic_window_sec = max(20, int(self.epidemic_window_sec))
            self.short_min_sec       = max(2, float(self.short_min_sec))
            # fail-fast: теневой тест опционален (по умолчанию выключен)
            self.shadow_test_enabled = bool(self.shadow_test_enabled)
            self.shadow_window       = max(2, int(self.shadow_window))
            self.shadow_min_pkts     = max(0, int(self.shadow_min_pkts))
        # синхронизируем лимиты среза с трекером соединений
        if _tracker is not None:
            _tracker.configure({
                "cut_min_sec":   self.cut_min_sec,
                "cut_max_sec":   self.cut_max_sec,
                "require_reset": self.cut_require_reset,
                "epidemic_min_events": self.epidemic_min_events,
                "short_min_sec":       self.short_min_sec,
                "epidemic_window_sec": self.epidemic_window_sec,
            })
        if _tspu_intel is not None:
            _tspu_intel.configure({"cooldown": max(0.0, float(self.cut_cooldown))})
        return self.get_status()

    def set_enabled(self, enabled):
        with self._lock:
            self.enabled = bool(enabled)
        if self.enabled:
            # 1. Пишем в config: отключаем стандартный nfqws2, включаем custom.d
            lines = read_lines()
            ensure_pool_mode(lines)
            write_lines(lines)

            # 2. Убиваем все nfqws2 процессы запущенные от tpws (стандартный демон)
            r = subprocess.run("pkill -u tpws nfqws2", shell=True, timeout=5)
            self._log_event("info", "pkill tpws nfqws2 rc=%d" % r.returncode)

            # 3. Заполняем пул — slots файл записывается при старте каждого слота
            self._ensure_pool_filled()

            # 4. Только теперь reload fw — slots файл уже содержит актуальные qnum
            subprocess.run(
                "/opt/zapret2/init.d/sysv/zapret2 restart-fw",
                shell=True, capture_output=True, timeout=30)
            self._log_event("info", "Firewall перезагружен, перепривязываю ZAPRET_POOL")
            # restart-fw восстанавливает стандартные правила NFQUEUE num 300.
            # Поэтому после него ОБЯЗАТЕЛЬНО ещё раз перепривязываем пул,
            # чтобы стандартная очередь не «забрала» трафик.
            self._pool._reload_fw()
            self._log_event("info", "Firewall: ZAPRET_POOL перепривязана после restart-fw")

            self._ensure_running()
        else:
            self._stop_evt.set()
            self._pool.stop_all()
            # Возвращаем стандартный режим
            lines = read_lines()
            def _set(key, val):
                pat = re.compile(r"^" + re.escape(key) + r"=")
                for i, ln in enumerate(lines):
                    if pat.match(ln): lines[i] = key + "=" + val; return
                lines.append(key + "=" + val)
            _set("NFQWS2_ENABLE", "1")
            # custom.d отключаем и здесь: стандартный zapret сам создаст свои правила,
            # а наш пул должен полностью уйти из цепочки POSTROUTING.
            _set("DISABLE_CUSTOM", "1")
            write_lines(lines)
            restart_zapret()
            self._log_event("info", "Стандартный режим zapret2 восстановлен")

        self._log_event("info", "Пул %s" % ("запущен" if self.enabled else "остановлен"))
        return self.get_status()

    def force_check(self):
        threading.Thread(target=self._check_all_slots, daemon=True).start()

    # ── ротация при срезе ТСПУ (соединение срезано через 30-60с) ───────

    def _traffic_for_qnum(self, qnum):
        """Агрегат очереди NFQUEUE для qnum ({} — если недоступен)."""
        if qnum is None:
            return {}
        try:
            t = (self._pool.get_traffic_stats().get(qnum)) or {}
            return {
                "qnum": qnum, "pkts_delta": t.get("pkts_delta"),
                "bytes_delta": t.get("bytes_delta"), "kbps": t.get("kbps"),
                "share": t.get("share"), "active": t.get("active"),
                "source": t.get("source"),
            }
        except Exception:
            return {}

    def on_connection_cut(self, event):
        """
        Колбэк от LifetimeTracker: соединение срезано ТСПУ.

        event — dict от детектора (см. conn_tracker._tick). Собираем максимально
        полный контекст (соединение, слот/стратегия, трафик, reset-монитор,
        хвосты логов панели/nfqws2/ss-server) и пишем отдельную запись в журнал
        срезов (cut_logger). Если пул включён — дополнительно запускаем ротацию.
        """
        if not isinstance(event, dict):
            # совместимость со старым вызовом on_cut(lifetime_sec)
            event = {"kind": "classic",
                     "lifetime_sec": float(event or 0.0), "conn": None}

        lifetime = event.get("lifetime_sec", 0) or 0.0
        conn     = event.get("conn")

        skip_reason = None
        trigger     = False
        with self._lock:
            if self.enabled and self.cut_rotate_enabled:
                if self.state in ("checking", "replacing"):
                    skip_reason = "идёт %s" % self.state
                else:
                    now = time.time()
                    if self._cut_last_ts and (now - self._cut_last_ts) < self.cut_cooldown:
                        skip_reason = "cooldown %ds" % self.cut_cooldown
                    else:
                        self._cut_last_ts = now
                        trigger = True
            else:
                skip_reason = "пул выключен / ротация отключена"

        if not trigger:
            self._log_event("info", "Срез пропущен (%s)" % (skip_reason or "—"))
        else:
            self._log_event("warn",
                "⚡ Срез ТСПУ: соединение прожило %.1fs — ротация стратегий" % lifetime)

        # ── собираем контекст для журнала ─────────────────────────────────
        local_port = remote_hex = remote_ip = remote_port = None
        slot_info  = None
        resolve_reason = None
        if isinstance(conn, (tuple, list)) and len(conn) == 3:
            local_port, remote_hex, remote_port = conn
            remote_ip = (_pm.PoolManager._hexip_to_str(remote_hex) if remote_hex else None)

            try:
                slot_info, resolve_reason = self._pool.slot_for_conn(conn)
            except Exception as e:
                slot_info = None
                resolve_reason = "slot_for_conn error: %s" % e

        qnum = slot_info.get("qnum") if isinstance(slot_info, dict) else None
        traffic = self._traffic_for_qnum(qnum)

        try:
            reset_st = reset_monitor.get_status()
        except Exception:
            reset_st = {}
        try:
            pool_log_tail = list(self._log)[-20:]
        except Exception:
            pool_log_tail = []
        try:
            ss_tail = reset_monitor.ss_log_tail(30)
        except Exception:
            ss_tail = []
        nfqws_tail = []
        nfqws_all  = {}
        try:
            alive_slots = [s for s in self._pool.get_status()
                           if s.get("alive") and s.get("index") is not None]
        except Exception:
            alive_slots = []
        if isinstance(slot_info, dict) and slot_info.get("index") is not None:
            try:
                nfqws_tail = self._pool.slot_log_tail(slot_info["index"], 40)
            except Exception:
                nfqws_tail = []
        else:
            # conntrack не смог определить слот — берём самый активный живой
            try:
                stats = self._pool.get_traffic_stats()

                def _act(s):
                    st = stats.get(s.get("qnum")) or {}
                    return st.get("pkts_delta", 0)
                best = max(alive_slots, key=_act) if alive_slots else None
                if best is not None:
                    slot_info = {
                        "index": best["index"], "qnum": best.get("qnum"),
                        "strategy": best.get("strategy"),
                        "nfqws_pid": best.get("pid"),
                        "fw_excluded": best.get("fw_excluded"),
                        "guessed": True,
                    }
                    nfqws_tail = self._pool.slot_log_tail(best["index"], 40)
            except Exception:
                pass
        # guessed-фолбэк мог подставить слот ПОСЛЕ первичного вычисления qnum —
        # пересобираем qnum/traffic, иначе в tspu_intel уходят qnum=null и
        # bytes_delta=null при полностью рабочем слоте
        if isinstance(slot_info, dict) and qnum is None:
            qnum = slot_info.get("qnum")
            if qnum is not None:
                traffic = self._traffic_for_qnum(qnum)
                self._log_event("info",
                                "Слот угадан (conntrack не ответил): "
                                "index=%s qnum=%s" % (slot_info.get("index"), qnum))
        # хвосты всех живых слотов — контекст есть даже без определения слота
        for s in alive_slots:
            try:
                t = self._pool.slot_log_tail(s["index"], 15)
                if t:
                    nfqws_all[str(s["index"])] = t
            except Exception:
                pass

        try:
            pool_status = self._pool.get_status()
            healthy_count = sum(1 for s in pool_status if s.get("healthy") is True)
        except Exception:
            healthy_count = 0

        payload = {
            "kind": "cut",
            "event_kind": event.get("kind", "classic"),
            "lifetime_sec": round(lifetime, 1),
            "rst_deaths_window": event.get("rst_deaths_window"),
            "fin_deaths_window": event.get("fin_deaths_window"),
            "reset_confirmed": event.get("reset_confirmed"),
            "connection": {
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_ip_hex": remote_hex,
                "remote_port": remote_port,
            },
            "slot": slot_info,
            "slot_resolved": bool(slot_info and not slot_info.get("guessed")),
            "slot_resolve_reason": resolve_reason,
            "traffic": traffic,
            "pool": {
                "enabled": self.enabled,
                "state": self.state,
                "healthy_count": healthy_count,
                "cut_rotate_enabled": self.cut_rotate_enabled,
                "cut_min_sec": self.cut_min_sec,
                "cut_max_sec": self.cut_max_sec,
                "cut_cooldown": self.cut_cooldown,
                "skip_reason": skip_reason,
                "rotation_triggered": trigger,
            },
            "reset_monitor": {
                "resets_window": reset_st.get("resets_window"),
                "closes_window": reset_st.get("closes_window"),
                "ratio": reset_st.get("ratio"),
                "degraded": reset_st.get("degraded"),
                "total_resets": reset_st.get("total_resets"),
            },
            "strategy_scores": dict(self.strategy_scores),
            "traces": {
                "panel_log_tail": pool_log_tail,
                "ss_server_tail": ss_tail,
                "nfqws2_log_tail": nfqws_tail,
                "nfqws2_all_slots": nfqws_all,
            },
        }
        recorded_payload = None
        try:
            recorded_payload = cut_logger.record(payload)
        except Exception as e:
            self._log_event("error", "Журнал срезов: %s" % e)

        if _tspu_intel is not None:
            # 1. Забираем ID, который сгенерировал cut_logger
            resolved_cut_id = None
            if recorded_payload and isinstance(recorded_payload, dict):
                resolved_cut_id = recorded_payload.get("id")
            if not resolved_cut_id and isinstance(payload, dict):
                resolved_cut_id = payload.get("id")
            if not resolved_cut_id:
                resolved_cut_id = int(time.time())

            # 2. Пытаемся вытащить IP/порты из event детектора, если распаковка conn выше не сработала
            _ev_conn = event.get("connection") or event.get("conn") or {}
            _r_ip = remote_ip
            _r_port = remote_port
            _l_port = local_port

            if not _r_ip and isinstance(_ev_conn, dict):
                _r_ip = _ev_conn.get("remote_ip") or _ev_conn.get("ip") or _ev_conn.get("dst")
                _r_port = _ev_conn.get("remote_port") or _ev_conn.get("dport")
                _l_port = _ev_conn.get("local_port") or _ev_conn.get("sport")

            # 3. Определяем тип завершения сессии
            _term_type = "RST" if event.get("reset_confirmed") or event.get("rst_deaths_window") else "FIN"

            _ti_ctx = {
                "cut_id": resolved_cut_id,
                "event_kind": event.get("kind", "classic"),
                "lifetime_sec": lifetime,
                "reset_confirmed": bool(event.get("reset_confirmed")),
                "remote_ip": _r_ip,
                "remote_port": _r_port,
                "local_port": _l_port,
                "qnum": qnum,
                "slot_index": (slot_info.get("index") if isinstance(slot_info, dict) else None),
                "strategy_name": (slot_info.get("strategy") if isinstance(slot_info, dict) else None),
                "nfqws_opt": None,
                "strategy_score_before": 0.0,
                "bytes_delta": (traffic or {}).get("bytes_delta"),
                "termination_type": _term_type,
            }
            
            _sname = _ti_ctx["strategy_name"]
            if _sname:
                _ti_ctx["nfqws_opt"] = load_strategy_nfqws(_sname)
                # None если истории нет — не маскируем отсутствующий скор
                # нулём, иначе в датасете неотличимо от реального 0.0
                _ti_ctx["strategy_score_before"] = (
                    float(self.strategy_scores[_sname])
                    if _sname in self.strategy_scores else None)
            
            threading.Thread(target=_tspu_intel.on_cut_async, args=(_ti_ctx,), daemon=True).start()


        if trigger:
            threading.Thread(target=self._rotate_on_cut, args=(lifetime, slot_info), daemon=True).start()

    def _rotate_on_cut(self, lifetime, slot_info=None):
        """
        Fail-Fast ротация после среза ТСПУ (события classic / epidemic).

        Слот-виновник берём ТОЧНО из conntrack (SLOT-N / QNUM-N), если он
        определён, иначе — самый активный живой слот. Дальше мгновенно:
          1) слот убирается из rotation, его стратегия уходит в конец пула;
          2) из резерва (700+) берётся первая свежая стратегия;
          3) точечный перезапуск ОДНОГО nfqws2 (kill PID + старт с тем же
             QNUM и новыми args) — никакой restart-daemons;
          4) штрафы сбрасываются в 0 — без «degraded» и без долгих
             теневых curl-тестов (они опциональны и по умолчанию выключены).
        """
        try:
            slots = self._pool.get_status()
            with self._lock:
                self.state = "replacing"

            # 1. Определяем слот-виновник
            target = None
            if isinstance(slot_info, dict) and slot_info.get("index") is not None:
                idx = slot_info["index"]
                target = next((s for s in slots
                               if s["index"] == idx and s["alive"]), None)
            if target is None:
                # conntrack не смог определить слот — берём самый активный живой
                stats = self._pool.get_traffic_stats()
                candidates = [s for s in slots if s["alive"] and not s["fw_excluded"]]
                if not candidates:
                    self._log_event("warn", "Нет живых слотов для ротации по срезу")
                    with self._lock:
                        self.state = "ok"
                    return
                def _w(s):
                    st = stats.get(s["qnum"]) or {}
                    return st.get("pkts_delta", 0)
                target = max(candidates, key=_w)

            idx      = target["index"]
            qnum     = target.get("qnum")
            pid      = target.get("pid")
            old_name = target["strategy"] or ("slot%d" % idx)
            self._log_event("warn",
                "⚡ Fail-Fast: срез ТСПУ на SLOT-%d (QNUM-%s, pid=%s) «%s» — "
                "точечная замена одного nfqws2" % (idx, qnum, pid, old_name))

            self._replace_slot(idx, old_name)
        except Exception as e:
            self._log_event("error", "Ротация по срезу упала: %s" % e)
            with self._lock:
                self.state = "ok"

    def _demote_strategy(self, name):
        """
        Отправляет стратегию в САМЫЙ КОНЕЦ пула резерва (700+).

        Рейтинг падает до минимума (−20.0), имя попадает в чёрный список
        _demoted: стратегия больше не выбирается из резерва, пока есть
        свежие. Когда пул исчерпывается (сброс _used/_demoted), она снова
        может быть испытана — но уже последней. Т.е. мёртвая стратегия
        НИКОГДА не возвращается обратно в rotation.
        """
        if not name or name.startswith("slot"):
            return
        with self._lock:
            self.strategy_scores[name] = -20.0
            self._demoted.add(name)

    def set_slot_strategy(self, index, strategy_name):
        """Ручная смена стратегии в конкретном слоте."""
        nfqws = load_strategy_nfqws(strategy_name)
        if not nfqws:
            return {"error": "стратегия не найдена: " + strategy_name}
        if not nfqws.strip():
            return {"error": "стратегия без NFQWS2_OPT (старый формат): " + strategy_name}
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
        strategies = [s for s in list_strategies() if (s.get("nfqws_opt") or "").strip()]
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
        """Возвращает (name, nfqws_opt) лучшей стратегии по скорингу.
        Скор: +1.0 за успех, −2.0 за провал, ×0.98 старение за каждую попытку."""
        strategies = [s for s in list_strategies() if (s.get("nfqws_opt") or "").strip()]
        if not strategies:
            return None, None
        with self._lock:
            # старение скоров
            for k in list(self.strategy_scores):
                self.strategy_scores[k] = max(-20.0, min(20.0, self.strategy_scores[k] * 0.98))
            unused = [s for s in strategies
                      if s["name"] not in self._used and s["name"] not in self._demoted]
            if not unused:
                # пул исчерпан — сбрасываем и назначенные, и отброшенные:
                # демотированные стратегии снова в игре (но последними)
                self._used.clear()
                self._demoted.clear()
                unused = strategies
            best = max(unused, key=lambda s: self.strategy_scores.get(s["name"], 0.0))
            self._used.add(best["name"])
            return best["name"], best["nfqws_opt"]

    def _next_strategy_batch(self, n):
        """Возвращает до n уникальных (name, nfqws) кандидатов по скорингу."""
        strategies = [s for s in list_strategies() if (s.get("nfqws_opt") or "").strip()]
        out, taken = [], set()
        with self._lock:
            for k in list(self.strategy_scores):
                self.strategy_scores[k] = max(-20.0, min(20.0, self.strategy_scores[k] * 0.98))
        while len(out) < n and len(taken) < len(strategies):
            remaining = [s for s in strategies if s["name"] not in taken and s["name"] not in self._demoted]
            if not remaining:
                # пул исчерпан — демотированные стратегии снова в игре
                self._demoted.clear()
                remaining = [s for s in strategies if s["name"] not in taken]
            if not remaining:
                break
            best = max(remaining, key=lambda s: self.strategy_scores.get(s["name"], 0.0))
            out.append((best["name"], best["nfqws_opt"]))
            taken.add(best["name"])
            with self._lock:
                self._used.add(best["name"])
        return out

    def _bump_score(self, name, ok):
        with self._lock:
            cur = self.strategy_scores.get(name, 0.0)
            self.strategy_scores[name] = max(-20.0, min(20.0, cur + (1.0 if ok else -2.0)))

    def _probe_curl_ok(self, timeout=6):
        """Короткий curl через SOCKS (может попасть на теневой слот при random)."""
        try:
            cmd = [
                "curl", "-x", "socks5h://127.0.0.1:%d" % (SOCKS_PORT or 1080),
                self.test_url, "-I",
                "--max-time", str(timeout), "--connect-timeout", "6", "-s", "-S",
            ]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
            return p.returncode == 0 and bool(re.search(r"HTTP/\S+ [23]", p.stdout or ""))
        except Exception:
            return False

    def _probe_shadow(self, shadow, window=10, min_pkts=2):
        """
        Проверяет теневой слот: получил ли он реальный трафик (pkts) за окно,
        либо прошёл ли хотя бы один curl-проб. НЕ захватывает весь трафик —
        случайные соединения сами попадают на теневой qnum.
        """
        qnum = shadow["qnum"]
        time.sleep(1.2)   # дать nfqws2 подняться и попасть в random
        p0 = self._pool.shadow_pkts(qnum)
        end = time.time() + window
        while time.time() < end:
            p1 = self._pool.shadow_pkts(qnum)
            if (p1 - p0) >= min_pkts:
                return True
            if self._probe_curl_ok():
                return True
            time.sleep(1)
        return False

    def _check_all_slots(self):
        """
        Двухфазная проверка:
          1. Быстрый тест пула целиком — если OK, все слоты помечаем healthy.
          2. При провале — последовательный захват трафика на каждый слот,
             точно определяем кто не работает, заменяем.
        """
        pool_status = self._pool.get_status()
        if not pool_status:
            return

        with self._lock:
            url       = self.test_url
            threshold = self.fail_threshold
            enabled   = self.enabled
        if not enabled:
            return

        # Не мешаем идущей ротации по срезу ТСПУ
        with self._lock:
            if self.state == "replacing":
                return

        # ── Фаза 1: быстрый тест пула целиком ─────────────────────────────
        with self._lock:
            self.state = "checking"

        # Если монитор уже видит деградацию — сразу к диагностике без curl
        mon = reset_monitor.get_status()
        if mon["degraded"]:
            self._log_event("warn",
                "⚠ ResetMonitor: ratio=%.0f%% (%d reset/%d total за %ds) — сразу диагностика" % (
                    mon["ratio"] * 100, mon["resets_window"],
                    mon["total_window"], mon["window_sec"]))
            result = {"ok": False, "rc": -2, "output": "reset ratio high"}
        else:
            result = self._pool.test_pool(url)

        if result["ok"]:
            # Всё работает — помечаем все живые слоты healthy, сбрасываем счётчики
            for slot_info in pool_status:
                if slot_info["alive"]:
                    self._pool.set_slot_health(slot_info["index"], True)
                    with self._lock:
                        self._slot_fails[slot_info["index"]] = 0
            self._log_event("ok", "✓ Пул работает (%d слотов)" % len(pool_status))
            with self._lock:
                self.state = "ok"
            return

        # ── Фаза 2: диагностика подозрительных слотов (не всех подряд) ─────
        # Только слоты с накопленными провалами или помеченные нездоровыми.
        suspects = [s for s in pool_status
                    if s["alive"] and not s["fw_excluded"] and (
                        s["healthy"] is False
                        or (self._slot_fails.get(s["index"], 0) > 0))]
        self._log_event("warn",
            "Деградация — диагностирую %d подозрительных слотов…" % len(suspects))
        with self._lock:
            self.state = "checking"

        good_slots = []
        bad_slots  = []

        for slot_info in suspects:
            idx  = slot_info["index"]
            name = slot_info["strategy"] or "slot%d" % idx

            self._log_event("info", "Тестирую слот %d «%s»…" % (idx, name))
            r = self._pool.test_slot_isolated(idx, url)
            self._pool.set_slot_health(idx, r["ok"])

            if r["ok"]:
                with self._lock:
                    self._slot_fails[idx] = 0
                self._log_event("ok", "✓ Слот %d «%s» — работает" % (idx, name))
                good_slots.append(idx)
            else:
                with self._lock:
                    self._slot_fails[idx] = self._slot_fails.get(idx, 0) + 1
                    fails = self._slot_fails[idx]
                self._log_event("warn",
                    "✗ Слот %d «%s» — не работает (rc=%d, провалов: %d/%d)" % (
                        idx, name, r["rc"], fails, threshold))
                if fails >= threshold:
                    bad_slots.append((idx, name))

            # Пауза между изолированными тестами — не «избиваем» соединения серией
            if len(suspects) > 1 and bad_slots + good_slots < len(suspects):
                time.sleep(1)

        if not bad_slots:
            with self._lock:
                self.state = "ok"
            return

        # Сначала убираем нерабочие слоты из iptables rotation —
        # клиенты перестают попадать на них немедленно
        bad_indices = [idx for idx, _ in bad_slots]
        self._log_event("warn",
            "Убираю нерабочие слоты из rotation: %s" % bad_indices)
        self._pool.remove_slots_from_fw(bad_indices)

        # Заменяем нерабочие в фоне — клиенты уже на рабочих слотах
        for idx, name in bad_slots:
            self._replace_slot(idx, name)

        with self._lock:
            self.state = "ok" if good_slots else "degraded"

    def _replace_slot(self, index, old_name, max_attempts=3):
        """
        Fail-Fast замена стратегии слота.

        1. Слот мгновенно исключается из rotation (remove_slots_from_fw) —
           клиенты сразу уходят на здоровые слоты, nfqws2 остаётся жив.
        2. Погибшая стратегия отправляется в САМЫЙ КОНЕЦ пула резерва
           (_demote_strategy) — обратно в rotation она НЕ возвращается.
        3. Из резерва (700+) берётся первая свежая или высокорейтинговая
           стратегия (_next_strategy_batch).
        4. Тяжёлый restart-daemons НЕ вызывается: pool.replace_slot убивает
           только nfqws2-процесс ЭТОГО слота и запускает новый с тем же
           QNUM и новыми args.
        5. Штрафные очки (strategy_scores) новой стратегии и счётчик
           провалов слота сбрасываются в 0 — статус «degraded» не ставится.

        Теневой curl-тест выполняется только при shadow_test_enabled=True
        (по умолчанию ВЫКЛЮЧЕН — пока ТСПУ рвёт соединения, долгие тесты
        только усугубляют проблему).
        """
        with self._lock:
            self.state = "replacing"

        # 1. Мгновенно выпадаем из random-распределения
        self._pool.remove_slots_from_fw([index])
        # 2. Мёртвая стратегия — в конец пула резерва, не обратно в rotation
        self._demote_strategy(old_name)

        try:
            candidates = self._next_strategy_batch(max_attempts)
            chosen = None
            for name, nfqws in candidates:
                ok = True
                if self.shadow_test_enabled:
                    # опциональный теневой тест (по умолчанию выключен)
                    shadow = self._pool.start_shadow(name, nfqws)
                    if not shadow:
                        continue
                    try:
                        ok = self._probe_shadow(shadow,
                                                window=self.shadow_window,
                                                min_pkts=self.shadow_min_pkts)
                    finally:
                        self._pool.stop_shadow(shadow["qnum"])
                if not ok:
                    self._bump_score(name, False)
                    self._log_event("warn",
                        "✗ Слот %d: «%s» отброшена — беру следующую из резерва" % (
                            index, name))
                    continue
                chosen = (name, nfqws)
                break

            if not chosen:
                # Резерв пуст — НЕ возвращаем мёртвую стратегию в rotation:
                # слот остаётся вне iptables до следующей проверки
                self._pool.set_slot_health(index, False)
                self._log_event("error",
                    "Слот %d «%s»: резерв стратегий исчерпан — слот выведен из rotation" % (
                        index, old_name))
                with self._lock:
                    self.state = "ok"
                return

            name, nfqws = chosen
            # 3-4. Точечный перезапуск одного nfqws2: тот же QNUM, новые args
            self._pool.replace_slot(index, name, nfqws)
            self._pool.set_slot_health(index, True)
            self._pool.restore_slot_to_fw(index)
            # 5. Сброс штрафов: новая стратегия стартует с чистого листа
            with self._lock:
                self.strategy_scores[name] = 0.0
                self._slot_fails[index] = 0
                self.state = "ok"
            self._log_event("ok",
                "✓ Слот %d (fail-fast): «%s» → «%s» — QNUM сохранён, "
                "restart-daemons не нужен, штрафы сброшены" % (index, old_name, name))
        except Exception as e:
            self._log_event("error",
                "Слот %d: fail-fast замена упала: %s" % (index, e))
            with self._lock:
                self.state = "ok"


# ── globals init ─────────────────────────────────────────────────────────────

_pool     = None
_switcher = None
_tracker  = None

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
        elif p == "/api/pool/traffic":
            self._json(_pool.get_traffic_stats())
        elif p == "/api/monitor/status":
            self._json(reset_monitor.get_status())
        elif p == "/api/cuts":
            self._json({"entries": cut_logger.list(50),
                        "status": cut_logger.status()})
        elif p == "/api/cuts/export":
            self._send(200, "application/x-ndjson; charset=utf-8",
                       cut_logger.export())
        elif p == "/api/intel/status":
            if _tspu_intel is not None:
                self._json(_tspu_intel.status())
            else:
                self._json({"enabled": False, "error": "tspu_intel not loaded"})
        elif p == "/api/intel/list":
            if _tspu_intel is not None:
                from urllib.parse import urlparse, parse_qs
                limit = 50
                try:
                    _qs = parse_qs(urlparse(self.path).query)
                    limit = int(_qs.get("limit", ["50"])[0])
                except Exception:
                    limit = 50
                self._json({"entries": _tspu_intel.intel_log.list(limit),
                            "status": _tspu_intel.intel_log.status()})
            else:
                self._json({"error": "tspu_intel not loaded"})
        elif p == "/api/intel/export":
            if _tspu_intel is not None:
                self._send(200, "application/x-ndjson; charset=utf-8",
                           _tspu_intel.intel_log.export())
            else:
                self._send(404, "text/plain; charset=utf-8", "not loaded")
        elif p == "/api/intel/clear":
            if _tspu_intel is not None:
                self._json(_tspu_intel.intel_log.clear())
            else:
                self._json({"ok": False, "error": "tspu_intel not loaded"})
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

        elif p == "/api/monitor/configure":
            return self._json(reset_monitor.configure(body))

        elif p == "/api/cuts/clear":
            return self._json(cut_logger.clear())

        elif p == "/api/cuts/record":
            # ручная запись тестового события (для отладки из UI)
            return self._json(cut_logger.record(body.get("payload", {"kind": "manual"})))

        # ── сохранить NFQWS2_OPT вручную ────────────────────────────────────
        elif p == "/api/intel/probe":
            if _tspu_intel is None:
                return self._json({"ok": False, "error": "tspu_intel not loaded"})
            sname = body.get("strategy_name") or ""
            nfqws = body.get("nfqws_opt")
            if nfqws is None and sname:
                nfqws = load_strategy_nfqws(sname)
            _ctx = {"cut_id": -1, "event_kind": "manual",
                    "lifetime_sec": float(body.get("lifetime_sec", 0.0) or 0.0),
                    "reset_confirmed": bool(body.get("reset_confirmed", False)),
                    "remote_ip": body.get("remote_ip"),
                    "remote_port": body.get("remote_port", 443),
                    "local_port": body.get("local_port", 0),
                    "qnum": None, "strategy_name": sname,
                    "nfqws_opt": nfqws,
                    "strategy_score_before": float(body.get("strategy_score_before", 0.0) or 0.0),
                    "bytes_delta": body.get("bytes_delta"),
                    "termination_type": None}
            return self._json(_tspu_intel.on_cut_async(_ctx))
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
    global _pool, _switcher, _tracker
    CFG_PATH    = args.config
    STRAT_DIR   = args.strategies
    RESTART_CMD = args.restart_cmd
    SOCKS_PORT  = args.socks_port
    SS_PORT     = args.ss_port

    # Передаём SOCKS порт в pool_manager для тестов
    _pm._SOCKS_PORT = args.socks_port

    def _log(lvl, msg):
        print("[pool][%s] %s" % (lvl.upper(), msg), flush=True)

    _pool     = PoolManager(log_fn=_log)
    _switcher = PoolSwitcher(_pool)
    print("[DIAG] _switcher created, cut_min=%s, cut_max=%s, cut_require_reset=%s" % (
        _switcher.cut_min_sec, _switcher.cut_max_sec, _switcher.cut_require_reset), flush=True)

    # ── трекер времени жизни соединений (срезы ТСПУ 30-60с) ───────────
    _tracker = LifetimeTracker(
        ss_port=args.ss_port, socks_port=args.socks_port,
        panel_port=args.port, log_fn=_log,
        cut_min_sec=_switcher.cut_min_sec, cut_max_sec=_switcher.cut_max_sec,
        require_reset=_switcher.cut_require_reset,
        epidemic_min_events=_switcher.epidemic_min_events,
        short_min_sec=_switcher.short_min_sec,
        epidemic_window_sec=_switcher.epidemic_window_sec)
    print("[DIAG] _tracker created", flush=True)
    _tracker.on_cut = _switcher.on_connection_cut
    reset_monitor.on_reset = _tracker.note_reset
    print("[DIAG] callbacks wired", flush=True)
    print("[DIAG] reset_monitor type=%s, SS_LOG_PATH=%s, exists=%s" % (
        type(reset_monitor).__name__, SS_LOG_PATH,
        os.path.exists(SS_LOG_PATH)), flush=True)

    reset_monitor.start()
    print("[DIAG] reset_monitor.start() done", flush=True)
    reset_monitor.on_degraded = _switcher.force_check
    print("[DIAG] before _tracker.start()", flush=True)
    _tracker.start()
    print("[DIAG] after _tracker.start()", flush=True)

    # ── само-восстановление после перезапуска ───────────────────────────
    # Если конфиг остался в пул-режиме (NFQWS2_ENABLE=0), контейнер мог
    # перезапуститься с «грязными» правилами: стандартные NFQUEUE num 300
    # перехватывают трафик до ZAPRET_POOL. Поднимаем пул автоматически
    # и принудительно перепривязываем ZAPRET_POOL.
    _startup_lines = read_lines()
    _pool_cfg_on = any(ln.startswith("NFQWS2_ENABLE=0") for ln in _startup_lines)
    if _pool_cfg_on:
        print("[panel] Конфиг в пул-режиме — авто-восстановление пула и FW", flush=True)
        def _autostart():
            try:
                _switcher.set_enabled(True)
            except Exception as e:
                print("[panel] авто-старт пула упал: %s" % e, flush=True)
        threading.Thread(target=_autostart, daemon=True).start()
    else:
        print("[panel] Конфиг в стандартном режиме — пул не поднимаем", flush=True)

    print("[panel] config=%s  strategies=%s  ss=%d  socks=%d" % (
        CFG_PATH, STRAT_DIR, SS_PORT, SOCKS_PORT), flush=True)

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print("[panel] http://%s:%d" % (args.host, args.port), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()