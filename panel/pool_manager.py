#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoolManager — управляет пулом nfqws2 процессов.

Каждый слот пула:
  - свой QNUM (base + index)
  - свой nfqws2 процесс
  - своя стратегия (NFQWS2_OPT строка)

iptables правила (random connmark) пишутся через zapret2 custom.d хук.
PoolManager только перезаписывает /run/zapret-pool/size и перегружает fw
когда меняется размер пула.
"""

import collections, os, re, signal, subprocess, threading, time, socket

NFQWS2_BIN     = "/opt/zapret2/nfq2/nfqws2"
ZAPRET_INIT    = "/opt/zapret2/init.d/sysv/zapret2"
POOL_RUN_DIR   = "/run/zapret-pool"
QNUM_BASE      = 300
MAX_SLOTS      = 10

DESYNC_MARK = os.environ.get("DESYNC_MARK", "0x40000000")
WS_USER     = "nobody"

_SOCKS_PORT     = None   # выставляется из main()


class Slot:
    def __init__(self, index):
        self.index       = index
        self.qnum        = QNUM_BASE + index
        self.strategy    = None
        self.nfqws_opt   = None
        self.proc        = None
        self.healthy     = None
        self.started     = None
        self._fw_excluded = False   # временно исключён из iptables rotation
        self.log_tail     = collections.deque(maxlen=300)  # хвост вывода nfqws2

    def is_alive(self):
        return self.proc is not None and self.proc.poll() is None

    def to_dict(self):
        return {
            "index":       self.index,
            "qnum":        self.qnum,
            "strategy":    self.strategy,
            "healthy":     self.healthy,
            "alive":       self.is_alive(),
            "started":     self.started,
            "pid":         self.proc.pid if self.proc else None,
            "fw_excluded": self._fw_excluded,
        }


class PoolManager:

    def __init__(self, log_fn=None):
        self._lock   = threading.Lock()
        self._slots  = []
        self._shadows = []   # теневые слоты для безопасного подбора стратегий
        self._log    = log_fn or (lambda lvl, msg: print("[pool][%s] %s" % (lvl, msg), flush=True))
        self._prev_counters     = {}   # qnum → (pkts, bytes)
        self._prev_counter_time = None
        # путь procfs conntrack (переопределяется env NF_CONNTRACK_PROC)
        self._nf_conntrack_path = os.environ.get("NF_CONNTRACK_PROC",
                                                 "/proc/net/nf_conntrack")
        os.makedirs(POOL_RUN_DIR, exist_ok=True)

    # ── public ────────────────────────────────────────────────────────────

    def get_status(self):
        with self._lock:
            return [s.to_dict() for s in self._slots]

    def get_traffic_stats(self):
        """
        Счётчики активности слотов.
        Источник 1: iptables ZAPRET_POOL (pkts + bytes) — когда цепочка есть.
        Источник 2: /proc/net/netfilter/nfnetlink_queue (pkts total) — всегда доступен.
        Дельта считается относительно предыдущего вызова.

        Если байты недоступны (nfnetlink), оцениваем bytes ≈ pkts × 1500
        (средний размер пакета), чтобы панель могла показать kbps и долю трафика.
        """
        raw_ipt  = self._read_zapret_pool_counters()   # qnum → (pkts, bytes)
        raw_nfq  = self._read_nfnetlink_queue()         # qnum → pkts_total

        # Объединяем: предпочитаем iptables (есть bytes), fallback на nfnetlink
        raw = {}
        for q in set(raw_ipt) | set(raw_nfq):
            if q in raw_ipt:
                raw[q] = {"pkts": raw_ipt[q][0], "bytes": raw_ipt[q][1],
                          "bytes_estimated": False}
            else:
                raw[q] = {"pkts": raw_nfq[q], "bytes": 0,
                          "bytes_estimated": True}

        now = time.time()
        result = {}
        with self._lock:
            prev      = self._prev_counters
            prev_time = self._prev_counter_time
            dt = now - prev_time if prev_time else 1.0
            dt = max(dt, 0.1)

            total_dp = 0
            for qnum, r in raw.items():
                pp = prev.get(qnum, {}).get("pkts", 0)
                total_dp += max(0, r["pkts"] - pp)

            for qnum, r in raw.items():
                pp  = prev.get(qnum, {}).get("pkts", 0)
                pb  = prev.get(qnum, {}).get("bytes", 0)
                dpkts = max(0, r["pkts"] - pp)
                dbyt  = max(0, r["bytes"] - pb)
                estimated = r["bytes_estimated"]
                if dbyt == 0 and dpkts > 0:
                    dbyt = dpkts * 1500   # fallback-оценка байт из пакетов
                    estimated = True
                result[qnum] = {
                    "qnum":             qnum,
                    "pkts":             r["pkts"],
                    "bytes":            r["bytes"],
                    "pkts_delta":       dpkts,
                    "bytes_delta":      dbyt,
                    "kbps":             round(dbyt * 8 / 1024 / dt, 1),
                    "pps":              round(dpkts / dt, 1),
                    "active":           dpkts > 0,
                    "share":            round((dpkts / total_dp * 100) if total_dp else 0, 1),
                    "bytes_estimated":  estimated,
                    "source":           "iptables" if qnum in raw_ipt else "nfnetlink",
                }
            self._prev_counters     = raw
            self._prev_counter_time = now
        return result

    def _read_nfnetlink_queue(self):
        """
        Читает /proc/net/netfilter/nfnetlink_queue.
        Формат: queue_num  pid  copy_mode  copy_range  total_pkts  ...
        Колонка 5 (индекс 4) — total пакетов через очередь.
        """
        result = {}
        try:
            with open("/proc/net/netfilter/nfnetlink_queue") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    qnum = int(parts[0])
                    pkts = int(parts[4])
                    result[qnum] = pkts
        except Exception:
            pass
        return result

    def _read_zapret_pool_counters(self):
        """Парсит `iptables -t mangle -L ZAPRET_POOL -n -v -x`."""
        result = {}
        try:
            p = subprocess.run(
                ["iptables", "-t", "mangle", "-L", "ZAPRET_POOL", "-n", "-v", "-x"],
                capture_output=True, text=True, timeout=5
            )
            for line in p.stdout.splitlines():
                m = re.search(r"^\s*(\d+)\s+(\d+)\s+NFQUEUE.*?num\s+(\d+)", line)
                if m:
                    pkts = int(m.group(1))
                    byt  = int(m.group(2))
                    qnum = int(m.group(3))
                    existing = result.get(qnum, (0, 0))
                    result[qnum] = (existing[0] + pkts, existing[1] + byt)
        except Exception:
            pass
        return result

    def start_slot(self, index, strategy_name, nfqws_opt):
        """Запустить/перезапустить один слот."""
        with self._lock:
            slot = self._get_or_create(index)
            self._stop_slot_proc(slot)
            slot.strategy  = strategy_name
            slot.nfqws_opt = nfqws_opt
            self._start_slot_proc(slot)
            self._write_size()
        self._reload_fw()

    def stop_slot(self, index):
        """Остановить слот и убрать из пула."""
        with self._lock:
            slot = self._find(index)
            if slot:
                self._stop_slot_proc(slot)
                self._slots.remove(slot)
            self._write_size()
        self._reload_fw()

    def replace_slot(self, index, strategy_name, nfqws_opt):
        """
        Заменяет стратегию слота.
        Останавливаем старый nfqws2 (освобождаем NFQUEUE), затем запускаем новый
        на том же qnum с ретраями на 'nfq_create_queue' (гонка очереди).
        Слот при этом уже должен быть исключён из fw rotation (fw_excluded),
        поэтому разрыва соединений пользователя не происходит.
        """
        with self._lock:
            slot = self._get_or_create(index)
            self._stop_slot_proc(slot)          # terminate + wait, освобождает очередь
            slot.strategy  = strategy_name
            slot.nfqws_opt = nfqws_opt
            slot.healthy   = None
            self._start_slot_proc(slot)
        self._log("info", "Слот %d заменён на «%s»" % (index, strategy_name))

    def set_slot_health(self, index, healthy):
        with self._lock:
            slot = self._find(index)
            if slot:
                slot.healthy = healthy

    def test_slot_isolated(self, index, url, timeout=12):
        """
        Изолированный тест слота через временный захват трафика.
        На время теста весь трафик направляется в NFQUEUE этого слота.
        Основной random распределитель временно перекрывается правилом с -I.
        Даунтайм ~(timeout) секунд — вызывать только при деградации пула.
        """
        qnum = QNUM_BASE + index

        # Временное правило с наивысшим приоритетом перекрывает random
        capture_rule = [
            "POSTROUTING", "-t", "mangle",
            "-m", "mark", "!", "--mark", "%s/%s" % (DESYNC_MARK, DESYNC_MARK),
            "-j", "NFQUEUE", "--queue-num", str(qnum), "--queue-bypass"
        ]

        def ipt(op):
            for cmd in (["iptables"], ["ip6tables"]):
                try:
                    subprocess.run(cmd + [op] + capture_rule,
                                   capture_output=True, timeout=5)
                except Exception:
                    pass

        ipt("-I")
        try:
            cmd = [
                "curl", "-x", "socks5h://127.0.0.1:%d" % (_SOCKS_PORT or 1080),
                url, "-I",
                "--max-time", str(timeout),
                "--connect-timeout", "8",
                "-s", "-S",
            ]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            out = (p.stdout or "") + (p.stderr or "")
            ok  = p.returncode == 0 and bool(re.search(r"HTTP/\S+ [23]", p.stdout))
            return {"ok": ok, "rc": p.returncode, "output": out.strip()}
        except subprocess.TimeoutExpired:
            return {"ok": False, "rc": -1, "output": "Таймаут %dс" % timeout}
        except Exception as e:
            return {"ok": False, "rc": -1, "output": str(e)}
        finally:
            ipt("-D")

    def test_pool(self, url, timeout=12):
        """Быстрый тест пула целиком через основной SOCKS."""
        port = _SOCKS_PORT or 1080
        self._log("info", "test_pool: socks5h://127.0.0.1:%d → %s" % (port, url))
        cmd = [
            "curl", "-x", "socks5h://127.0.0.1:%d" % port,
            url, "-I",
            "--max-time", str(timeout),
            "--connect-timeout", "8",
            "-s", "-S",
        ]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            out = (p.stdout or "") + (p.stderr or "")
            ok  = p.returncode == 0 and bool(re.search(r"HTTP/\S+ [23]", p.stdout))
            self._log("info", "test_pool: rc=%d ok=%s" % (p.returncode, ok))
            return {"ok": ok, "rc": p.returncode, "output": out.strip()}
        except subprocess.TimeoutExpired:
            return {"ok": False, "rc": -1, "output": "Таймаут %dс" % timeout}
        except Exception as e:
            return {"ok": False, "rc": -1, "output": str(e)}

    # ── теневой слот (безопасный подбор стратегий без захвата трафика) ──────

    def _next_free_qnum(self):
        used = {s.qnum for s in self._slots} | {s.qnum for s in self._shadows}
        q = QNUM_BASE
        while q < QNUM_BASE + 100 and q in used:
            q += 1
        return q

    def start_shadow(self, strategy_name, nfqws_opt):
        """
        Стартует теневой слот с новой стратегией.
        Теневой слот получает отдельный qnum и включается в random-распределение
        наравне с основными — без «захвата» всего трафика. Реальные соединения
        продолжают жить: лишь часть новых соединений случайно уходит на теневой слот.
        """
        if not (nfqws_opt or "").strip():
            return None
        with self._lock:
            shadow = Slot(100 + len(self._shadows))   # index вне диапазона 0-9
            shadow.qnum      = self._next_free_qnum()
            shadow.strategy  = strategy_name
            shadow.nfqws_opt = nfqws_opt
            shadow.healthy   = None
            self._shadows.append(shadow)
            self._start_slot_proc(shadow)
            self._write_size()
        self._reload_fw()
        self._log("info", "Теневой слот «%s»: qnum=%d (участвует в random)" % (
            strategy_name, shadow.qnum))
        return {"index": shadow.index, "qnum": shadow.qnum}

    def stop_shadow(self, qnum):
        """Останавливает теневой слот и возвращает fw в исходное состояние."""
        with self._lock:
            for i, s in enumerate(self._shadows):
                if s.qnum == qnum:
                    self._stop_slot_proc(s)
                    del self._shadows[i]
                    break
            self._write_size()
        self._reload_fw()
        self._log("info", "Теневой слот qnum=%d остановлен" % qnum)

    def shadow_pkts(self, qnum):
        """Текущий total пакетов через очередь теневого слота."""
        return self._read_nfnetlink_queue().get(qnum, 0)

    def stop_all(self):
        with self._lock:
            for slot in self._slots:
                self._stop_slot_proc(slot)
            self._slots.clear()
            for sh in self._shadows:
                self._stop_slot_proc(sh)
            self._shadows.clear()
            self._write_size()
        self._reload_fw()

    def watchdog(self):
        """Перезапускает упавшие процессы. Вызывать периодически."""
        with self._lock:
            for slot in self._slots:
                if not slot.is_alive() and slot.nfqws_opt:
                    self._log("warn", "Слот %d (qnum=%d) упал, перезапускаю" % (slot.index, slot.qnum))
                    self._start_slot_proc(slot)

    def remove_slots_from_fw(self, indices):
        """
        Убирает указанные слоты из iptables rotation немедленно.
        Процессы nfqws2 остаются живыми — только fw правила меняются.
        """
        with self._lock:
            # Помечаем слоты как временно исключённые
            for slot in self._slots:
                if slot.index in indices:
                    slot._fw_excluded = True
            self._write_size()
        self._reload_fw()
        self._log("info", "Слоты %s убраны из rotation" % indices)

    def restore_slot_to_fw(self, index):
        """Возвращает слот в iptables rotation."""
        with self._lock:
            slot = self._find(index)
            if slot:
                slot._fw_excluded = False
            self._write_size()
        self._reload_fw()
        self._log("info", "Слот %d возвращён в rotation" % index)

    def active_count(self):
        with self._lock:
            return len(self._slots)

    # ── контекст для журнала срезов ────────────────────────────────────

    def slot_for_conn(self, conn):
        """
        Best-effort: сопоставляет соединение (local_port, remote_ip_hex, 443)
        со слотом пула по метке conntrack.

        Читает procfs conntrack (путь — self._nf_conntrack_path, env
        NF_CONNTRACK_PROC), ищет запись с dst=remote_ip, dport=443 и
        sport=local_port, берёт mark. По mark (qnum) находит слот.

        Возвращает (slot_dict_or_None, fail_reason).
        fail_reason = None, если слот найден.
        """
        try:
            local_port, remote_ip_hex, remote_port = conn
        except (ValueError, TypeError):
            return None, "bad conn tuple"
        wanted = self._hexip_to_str(remote_ip_hex)
        if not wanted or int(remote_port or 443) != 443:
            return None, "bad ip/port"
        mark = None
        try:
            with open(self._nf_conntrack_path) as f:
                for line in f:
                    mark = self._match_conntrack_line(line, wanted, local_port)
                    if mark:
                        break
        except (IOError, OSError):
            # procfs может быть выключен в ядре (CONFIG_NF_CONNTRACK_PROCFS=n) —
            # пробуем бинарник conntrack (пакет conntrack-tools)
            mark = self._conntrack_binary_mark(wanted, local_port)
            if not mark:
                return None, "nf_conntrack procfs unavailable"
        except Exception as e:
            return None, "nf_conntrack read error: %s" % e
        if not mark:
            return None, "conntrack entry not found"
        qnum = self._parse_mark(mark)
        if qnum is None:
            return None, "bad mark %r" % mark
        with self._lock:
            for s in self._slots:
                if s.qnum == qnum:
                    return {
                        "index":    s.index,
                        "qnum":     s.qnum,
                        "strategy": s.strategy,
                        "nfqws_pid": s.proc.pid if s.proc else None,
                        "nfqws_opt": s.nfqws_opt,
                        "healthy":  s.healthy,
                        "fw_excluded": s._fw_excluded,
                    }, None
        return {"qnum": qnum, "strategy": None}, None

    @staticmethod
    def _match_conntrack_line(line, wanted, local_port):
        """
        mark из строки conntrack, если строка описывает нужный поток.
        Строка содержит оба направления — пару ищем в любом:
        (dst=remote, dport=443, sport=local) или reply-направление.
        """
        d = {}
        for tok in line.split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                d[k] = v
        if ((d.get("dport") == "443" and
             d.get("dst") == wanted and
             d.get("sport") == str(local_port)) or
            (d.get("sport") == "443" and
             d.get("src") == wanted and
             d.get("dport") == str(local_port))):
            return d.get("mark")
        return None

    def _conntrack_binary_mark(self, wanted, local_port, timeout=5):
        """Fallback: conntrack -L через бинарник (когда procfs недоступен)."""
        try:
            r = subprocess.run(
                ["conntrack", "-L", "-p", "tcp", "--dport", "443"],
                capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError):
            return None
        if r.returncode != 0:
            return None
        for line in (r.stdout or "").splitlines():
            m = self._match_conntrack_line(line, wanted, local_port)
            if m:
                return m
        return None

    @staticmethod
    def _parse_mark(mark):
        """mark из conntrack: '0x12d' / '12d' / '301' → int, иначе None."""
        try:
            m = str(mark).strip()
            if m.lower().startswith("0x"):
                return int(m, 16)
            if any(c in "abcdef" for c in m.lower()):
                return int(m, 16)
            return int(m, 10)
        except (ValueError, TypeError):
            return None

    def conn_flow_bytes(self, conn, timeout=5):
        """Per-flow счётчики conntrack для конкретного потока:
        {'orig_bytes', 'reply_bytes', 'orig_pkts'} ({} — если потока нет).
        bytes=/packets= встречаются в строке дважды: orig и reply направление."""
        try:
            local_port, remote_hex, remote_port = conn
        except (ValueError, TypeError):
            return {}
        wanted = self._hexip_to_str(remote_hex)
        if not wanted or int(remote_port or 443) != 443:
            return {}
        line = self._find_conntrack_line(wanted, local_port, timeout)
        if not line:
            return {}
        bytes_list, pkts_list = [], []
        for tok in line.split():
            if "=" not in tok:
                continue
            k, v = tok.split("=", 1)
            if k == "bytes":
                try:
                    bytes_list.append(int(v))
                except ValueError:
                    pass
            elif k == "packets":
                try:
                    pkts_list.append(int(v))
                except ValueError:
                    pass
        if not bytes_list:
            return {}
        return {"orig_bytes": bytes_list[0],
                "reply_bytes": (bytes_list[1] if len(bytes_list) > 1 else None),
                "orig_pkts": (pkts_list[0] if pkts_list else None)}

    def _find_conntrack_line(self, wanted, local_port, timeout=5):
        """Полная строка conntrack для потока (procfs → бинарник conntrack)."""
        try:
            with open(self._nf_conntrack_path) as f:
                for line in f:
                    if self._match_conntrack_line(line, wanted, local_port):
                        return line
        except (IOError, OSError):
            # procfs может быть выключен в ядре (CONFIG_NF_CONNTRACK_PROCFS=n)
            pass
        except Exception:
            pass
        try:
            r = subprocess.run(
                ["conntrack", "-L", "-p", "tcp", "--dport", "443"],
                capture_output=True, text=True, timeout=timeout)
            if r.returncode == 0:
                for line in (r.stdout or "").splitlines():
                    if self._match_conntrack_line(line, wanted, local_port):
                        return line
        except (OSError, subprocess.SubprocessError):
            pass
        return None

    def slot_log_tail(self, index, limit=80):
        """Хвост вывода nfqws2 слота для журнала срезов."""
        with self._lock:
            s = self._find(index)
            if not s:
                return []
            return list(s.log_tail)[-int(limit):]

    @staticmethod
    def _hexip_to_str(hexip):
        """Превращает hex-представление IP из /proc/net/tcp в dotted/IPv6-строку."""
        try:
            n = len(hexip)
            if n == 8:      # IPv4: /proc/net/tcp stores in little-endian on x86/amd64
                b = bytes(int(hexip[i:i + 2], 16) for i in range(6, -1, -2))  # reverse byte order
                return ".".join(str(x) for x in b)
            if n == 32:     # IPv6 (little-endian слова)
                words = [int(hexip[i:i + 8], 16) for i in range(0, 32, 8)]
                groups = []
                for w in reversed(words):
                    groups.append("%x:%x" % ((w >> 16) & 0xFFFF, w & 0xFFFF))
                # сокращаем нули (минимально)
                return ":".join(groups)
        except (ValueError, IndexError):
            return None
        return None

    # ── internals ─────────────────────────────────────────────────────────

    def _find(self, index):
        return next((s for s in self._slots if s.index == index), None)

    def _get_or_create(self, index):
        slot = self._find(index)
        if not slot:
            slot = Slot(index)
            self._slots.append(slot)
            self._slots.sort(key=lambda s: s.index)
        return slot

    def _start_slot_proc(self, slot):
        if not slot.nfqws_opt:
            return

        # Базовые аргументы
        base = [
            NFQWS2_BIN,
            "--qnum=%d" % slot.qnum,
            "--user=%s" % WS_USER,
            "--fwmark=%s" % DESYNC_MARK,
            "--lua-init=@/opt/zapret2/lua/zapret-lib.lua",
            "--lua-init=@/opt/zapret2/lua/zapret-antidpi.lua",
            "--lua-init=@/opt/zapret2/lua/zapret-auto.lua",
            "--debug",
        ]

        # nfqws_opt — многострочная строка, каждая строка = отдельный --new профиль
        import shlex
        args = []
        for line in slot.nfqws_opt.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                args.extend(shlex.split(line))
            except ValueError:
                args.extend(line.split())

        # дополнительные аргументы для каждого nfqws2 (например, отладка):
        # env NFQWS2_EXTRA_ARGS, например "--debug=2 --log-dpkt"
        extra_args = os.environ.get("NFQWS2_EXTRA_ARGS", "").strip()
        if extra_args:
            try:
                args.extend(shlex.split(extra_args))
            except ValueError:
                args.extend(extra_args.split())

        self._log("info", "Слот %d старт: qnum=%d strategy=%s" % (
            slot.index, slot.qnum, slot.strategy or "custom"))
        self._log("info", "CMD: %s" % " ". join(base + args))
        # маркеры жизненного цикла — попадают в журнал срезов даже без трафика
        slot.log_tail.append("START CMD: %s" % " ".join(base + args))

        # Антигонка NFQUEUE: очередь может ещё удерживаться старым процессом
        last_err = ""
        for attempt in range(1, 4):
            slot.log_tail.append("START attempt %d/3" % attempt)
            try:
                # Направляем stdout и stderr в PIPE, чтобы Python мог читать и модифицировать строки
                proc = subprocess.Popen(
                    base + args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,  # Объединяем логи и ошибки в один поток
                    text=True,
                    bufsize=1,                 # Построчная буферизация
                )
                
                # Функция для чтения логов процесса в реальном времени и добавления префикса
                def log_reader(p, log_tail, qnum, slot_idx):
                    prefix = "[NFQWS2][SLOT-%d][QNUM-%d]" % (slot_idx, qnum)
                    for line in p.stdout:
                        # Пишем строку в Docker с пользовательским префиксом
                        print("%s %s" % (prefix, line.strip()), flush=True)
                        # И дублируем в кольцевой буфер слота — для журнала срезов
                        try:
                            log_tail.append("%s %s" % (prefix, line.strip()))
                        except Exception:
                            pass

                # Запускаем фоновый поток чтения логов для этого конкретного процесса
                import threading
                t = threading.Thread(target=log_reader,
                                     args=(proc, slot.log_tail, slot.qnum, slot.index),
                                     daemon=True)
                t.start()

                time.sleep(0.6)
                rc = proc.poll()
                if rc is not None:
                    last_err = "Процесс завершился с кодом %d. Проверьте логи выше." % rc
                    self._log("warn", "Слот %d старт попытка %d/3: rc=%d %s" % (
                        slot.index, attempt, rc, last_err))
                    slot.log_tail.append("EXIT rc=%d (attempt %d/3)" % (rc, attempt))

                    if attempt < 3:
                        time.sleep(1.0)
                        continue
                    slot.proc = None
                    slot.healthy = False
                    return
                slot.proc = proc
                slot.started = time.strftime("%H:%M:%S")
                slot.healthy = None
                self._log("info", "Слот %d (qnum=%d) успешно запущен" % (slot.index, slot.qnum))
                slot.log_tail.append("STARTED pid=%d qnum=%d" % (proc.pid, slot.qnum))
                return
            except Exception as e:
                last_err = str(e)
                if attempt < 3:
                    time.sleep(1.0)
        self._log("error", "Слот %d не запустился после 3 попыток: %s" % (slot.index, last_err))
        slot.log_tail.append("FAILED after 3 attempts: %s" % last_err)

    def _stop_slot_proc(self, slot):
        if slot.proc and slot.proc.poll() is None:
            try:
                slot.proc.terminate()
                slot.proc.wait(timeout=5)
            except Exception:
                try:
                    slot.proc.kill()
                except Exception:
                    pass
        slot.proc    = None
        slot.healthy = None

    def _write_size(self):
        """Записывает активные (не исключённые) qnum для fw скрипта.
        Нездоровые слоты (healthy is False) НЕ включаются — они выпадают
        из random-распределения, чтобы не перехватывать трафик мёртвыми
        стратегиями. Теневые слоты для подбора стратегий включаются."""
        os.makedirs(POOL_RUN_DIR, exist_ok=True)
        slots_path = os.path.join(POOL_RUN_DIR, "slots")
        try:
            qnums = [str(s.qnum) for s in self._slots
                     if s.is_alive() and not s._fw_excluded and s.healthy is not False]
            qnums += [str(s.qnum) for s in self._shadows if s.is_alive()]
            with open(slots_path, "w") as f:
                f.write("\n".join(qnums) + "\n" if qnums else "")
        except Exception as e:
            self._log("warn", "write slots: %s" % e)

    def _ipt(self, *args):
        """Выполнить iptables + ip6tables команду. Ошибки игнорируем."""
        for cmd in ("iptables", "ip6tables"):
            try:
                subprocess.run([cmd] + list(args),
                               capture_output=True, timeout=5)
            except Exception:
                pass

    def _ipt4(self, *args):
        """Только iptables."""
        try:
            subprocess.run(["iptables"] + list(args),
                           capture_output=True, timeout=5)
        except Exception:
            pass



    def _reload_fw(self):
        """
        Управляем iptables напрямую из Python — без custom.d.

        Чистка правил выполняется ПО НОМЕРАМ строк в POSTROUTING:
        находим все правила, содержащие 'NFQUEUE' с queue-num из диапазона
        пула (300..399) или 'ZAPRET_POOL', и удаляем их с конца.
        Это устойчиво к изменению точного синтаксиса (mark/set/connbytes),
        в отличие от `iptables -D ПО ПОЛНОЙ СПЕКЕ`.
        """
        desync_mark = os.environ.get("DESYNC_MARK", "0x40000000")

        with self._lock:
            active_qnums = [s.qnum for s in self._slots
                            if s.is_alive() and not s._fw_excluded and s.healthy is not False]
            active_qnums += [s.qnum for s in self._shadows if s.is_alive()]

        def _ipset_exists(name):
            r = subprocess.run(["ipset", "list", name], capture_output=True)
            return r.returncode == 0

        def _delete_pool_rules(cmd):
            """Удаляет из POSTROUTING все правила, относящиеся к пулу."""
            while True:
                try:
                    r = subprocess.run(
                        [cmd, "-t", "mangle", "-L", "POSTROUTING", "--line-numbers", "-n"],
                        capture_output=True, text=True, timeout=5
                    )
                except Exception:
                    return
                nums = []
                for line in r.stdout.splitlines():
                    # Формат: "num  target ...  NFQUEUE ... num 300" или "num  ZAPRET_POOL"
                    if "ZAPRET_POOL" in line:
                        m = re.match(r"^\s*(\d+)", line)
                        if m:
                            nums.append(int(m.group(1)))
                        continue
                    # NFQUEUE с num 300..399 (слоты пула) — но НЕ чужие очереди
                    m = re.match(r"^\s*(\d+)\s+\S+\s+.*NFQUEUE.*num\s+(\d+)", line)
                    if m:
                        qnum = int(m.group(2))
                        if QNUM_BASE <= qnum < QNUM_BASE + 100:
                            nums.append(int(m.group(1)))
                if not nums:
                    return
                # Удаляем с конца, чтобы номера не сдвигались
                for num in sorted(nums, reverse=True):
                    subprocess.run(
                        [cmd, "-t", "mangle", "-D", "POSTROUTING", str(num)],
                        capture_output=True, timeout=5
                    )
                # повторяем, т.к. после удаления могли появиться новые с одинаковыми номерами

        for cmd in ["iptables", "ip6tables"]:
            _delete_pool_rules(cmd)

        # Конфигурация для привязки ZAPRET_POOL (ipset-имена могли отличаться)
        configs = [
            {"cmd": "iptables",  "tcp": "zport_tcp",  "udp": "zport_udp",  "nz": "nozapret"},
            {"cmd": "ip6tables", "tcp": "zport_tcp6", "udp": "zport_udp6", "nz": "nozapret6"}
        ]

        # --- 2. Пересоздание цепочки ZAPRET_POOL ---
        for cmd in ["iptables", "ip6tables"]:
            subprocess.run([cmd, "-t", "mangle", "-F", "ZAPRET_POOL"], capture_output=True)
            subprocess.run([cmd, "-t", "mangle", "-X", "ZAPRET_POOL"], capture_output=True)

        if not active_qnums:
            self._log("warn", "Нет активных слотов — ZAPRET_POOL не создана")
            return

        for cmd in ["iptables", "ip6tables"]:
            subprocess.run([cmd, "-t", "mangle", "-N", "ZAPRET_POOL"], capture_output=True)

        # --- 3. Наполнение ZAPRET_POOL random-распределением ---
        # --- 3. Наполнение ZAPRET_POOL сессионным (CONNMARK) распределением ---
        for cmd in ["iptables", "ip6tables"]:
            # 3.1. Если у соединения УЖЕ есть сохраненная метка очереди, восстанавливаем ее в маркер пакета
            subprocess.run([
                cmd, "-t", "mangle", "-A", "ZAPRET_POOL",
                "-j", "CONNMARK", "--restore-mark", "--nfmask", "0xFFFF", "--ctmask", "0xFFFF"
            ], capture_output=True)

            # 3.2. Если маркер пакета совпадает с одним из номеров очередей, сразу отправляем в NFQUEUE
            for qnum in active_qnums:
                hex_mark = f"{qnum:#x}"  # Переводим qnum в hex (например, 300 -> 0x12c)
                subprocess.run([
                    cmd, "-t", "mangle", "-A", "ZAPRET_POOL",
                    "-m", "mark", "--mark", f"{hex_mark}/0xFFFF",
                    "-j", "NFQUEUE", "--queue-num", str(qnum), "--queue-bypass"
                ], capture_output=True)

        # 3.3. Если метки еще не было (новое соединение), крутим random балансировщик
        n = len(active_qnums)
        for i, qnum in enumerate(active_qnums):
            remaining = n - i
            hex_mark = f"{qnum:#x}"
            prob = f"{(1.0 / remaining):.6f}"

            for cmd in ["iptables", "ip6tables"]:
                if remaining == 1:
                    # Последний/единственный слот — забирает остаток трафика
                    subprocess.run([
                        cmd, "-t", "mangle", "-A", "ZAPRET_POOL",
                        "-j", "MARK", "--set-mark", f"{hex_mark}/0xFFFF"
                    ], capture_output=True)
                else:
                    # Распределяем с заданной вероятностью
                    subprocess.run([
                        cmd, "-t", "mangle", "-A", "ZAPRET_POOL",
                        "-m", "statistic", "--mode", "random", "--probability", prob,
                        "-j", "MARK", "--set-mark", f"{hex_mark}/0xFFFF"
                    ], capture_output=True)

                # Сохраняем выбранный маркер в CONNMARK, чтобы все пакеты этого соединения шли сюда
                subprocess.run([
                    cmd, "-t", "mangle", "-A", "ZAPRET_POOL",
                    "-m", "mark", "--mark", f"{hex_mark}/0xFFFF",
                    "-j", "CONNMARK", "--save-mark", "--nfmask", "0xFFFF", "--ctmask", "0xFFFF"
                ], capture_output=True)

                # И окончательно отправляем пакет в выбранную очередь
                subprocess.run([
                    cmd, "-t", "mangle", "-A", "ZAPRET_POOL",
                    "-m", "mark", "--mark", f"{hex_mark}/0xFFFF",
                    "-j", "NFQUEUE", "--queue-num", str(qnum), "--queue-bypass"
                ], capture_output=True)

        # --- 4. Привязка ZAPRET_POOL к POSTROUTING ---
        for conf in configs:
            cmd = conf["cmd"]
            nz_set = conf["nz"]
            
            for ipset, mode in [(conf["tcp"], "TCP"), (conf["udp"], "UDP")]:
                # Если ipset для этого протокола (например, IPv6) не существует, не пытаемся добавить правило
                if not _ipset_exists(ipset):
                    self._log("info", f"Пропуск {cmd} {mode}: ipset {ipset} не существует")
                    continue
                    
                # Если список исключений nozapret/nozapret6 почему-то отсутствует, создаем временную проверку
                actual_nz = nz_set if _ipset_exists(nz_set) else None

                try:
                    # Правило БЕЗ -m connbytes: ограничение «1:N пакетов»
                    # обрезало перехват после 20-го пакета сессии — ТСПУ рвал
                    # видеопоток youtube/googlevideo на 21-м пакете. nfqws2
                    # обрабатывает ВСЕ пакеты сессии: перехват чисто по
                    # ipset-списку, а фильтр mark оставлен как антицикл
                    # (исключает только пакеты, уже обработанные nfqws2).
                    # Собираем аргументы динамически в зависимости от наличия списка исключений
                    args = [
                        cmd, "-t", "mangle", "-A", "POSTROUTING",
                        "-m", "mark", "!", "--mark", f"{desync_mark}/{desync_mark}",
                        "-m", "set", "--match-set", ipset, "dst",
                    ]
                    
                    # Добавляем инверсию nozapret, только если сет существует
                    if actual_nz:
                        args.extend(["-m", "set", "!", "--match-set", actual_nz, "dst"])
                        
                    args.extend(["-j", "ZAPRET_POOL"])

                    r = subprocess.run(args, capture_output=True, text=True, timeout=5)
                    
                    if r.returncode != 0:
                        self._log("error", f"{cmd} {mode} rc={r.returncode}: {r.stderr.strip()}")
                    else:
                        self._log("info", f"{cmd} {mode} POSTROUTING → ZAPRET_POOL OK")
                except Exception as e:
                    self._log("error", f"{cmd} {mode} POSTROUTING: {e}")

        self._log("info", f"ZAPRET_POOL создана: {n} слот(ов) qnum={active_qnums}")

        # --- 5. Исправление входящего трафика (INPUT) для авто-TTL ---
        for cmd in ["iptables", "ip6tables"]:
            # Очищаем цепочку INPUT от старых жестких правил 
            # (Внимание: если у вас там есть другие важные системные правила, 
            # лучше удалять точечно, обычно в mangle-INPUT контейнера чисто но всеже ...)
            subprocess.run([cmd, "-t", "mangle", "-F", "INPUT"], capture_output=True)
            
            # Восстанавливаем метку соединения для входящих пакетов
            subprocess.run([
                cmd, "-t", "mangle", "-A", "INPUT",
                "-j", "CONNMARK", "--restore-mark", "--nfmask", "0xFFFF", "--ctmask", "0xFFFF"
            ], capture_output=True)
            
            # Раскидываем входящие пакеты по родным слотам пула
            for qnum in active_qnums:
                hex_mark = f"{qnum:#x}"
                # Для TCP
                subprocess.run([
                    cmd, "-t", "mangle", "-A", "INPUT",
                    "-p", "tcp", "-m", "mark", "--mark", f"{hex_mark}/0xFFFF",
                    "-j", "NFQUEUE", "--queue-num", str(qnum), "--queue-bypass"
                ], capture_output=True)
                # Для UDP
                subprocess.run([
                    cmd, "-t", "mangle", "-A", "INPUT",
                    "-p", "udp", "-m", "mark", "--mark", f"{hex_mark}/0xFFFF",
                    "-j", "NFQUEUE", "--queue-num", str(qnum), "--queue-bypass"
                ], capture_output=True)