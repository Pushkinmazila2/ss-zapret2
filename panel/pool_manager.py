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

import os, re, signal, subprocess, threading, time, socket

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

        self._log("info", "Слот %d старт: qnum=%d strategy=%s" % (
            slot.index, slot.qnum, slot.strategy or "custom"))
        self._log("info", "CMD: %s" % " ". join(base + args))

        # Антигонка NFQUEUE: очередь может ещё удерживаться старым процессом —
        # nfqws2 падает с "nfq_create_queue(): Operation not permitted". Ретраим.
        last_err = ""
        for attempt in range(1, 4):
            try:
                # Перенаправляем stdout в консоль (None), а stderr объединяем с stdout
                proc = subprocess.Popen(
                    base + args,
                    stdout=None,
                    stderr=None,
                    text=True,
                )
                time.sleep(0.6)
                rc = proc.poll()
                if rc is not None:
                    # Так как мы выводим всё напрямую в консоль контейнера, 
                    # детальный текст ошибки про nfq_create_queue напечатается в Docker-логи сам.
                    last_err = "Процесс завершился с кодом %d. Проверьте логи выше." % rc
                    self._log("warn", "Слот %d старт попытка %d/3: rc=%d %s" % (
                        slot.index, attempt, rc, last_err))
                    
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
                return
            except Exception as e:
                last_err = str(e)
                if attempt < 3:
                    time.sleep(1.0)
        self._log("error", "Слот %d не запустился после 3 попыток: %s" % (slot.index, last_err))

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
        tcp_pkt_out = os.environ.get("NFQWS2_TCP_PKT_OUT", "20")
        udp_pkt_out = os.environ.get("NFQWS2_UDP_PKT_OUT", "5")

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
        n = len(active_qnums)
        for i, qnum in enumerate(active_qnums):
            remaining = n - i
            for cmd in ["iptables", "ip6tables"]:
                if remaining == 1:
                    subprocess.run([
                        cmd, "-t", "mangle", "-A", "ZAPRET_POOL",
                        "-j", "NFQUEUE", "--queue-num", str(qnum), "--queue-bypass"
                    ], capture_output=True)
                else:
                    prob = f"{(1.0 / remaining):.6f}"
                    subprocess.run([
                        cmd, "-t", "mangle", "-A", "ZAPRET_POOL",
                        "-m", "statistic", "--mode", "random", "--probability", prob,
                        "-j", "NFQUEUE", "--queue-num", str(qnum), "--queue-bypass"
                    ], capture_output=True)

        # --- 4. Привязка ZAPRET_POOL к POSTROUTING ---
        for conf in configs:
            cmd = conf["cmd"]
            nz_set = conf["nz"]
            
            for ipset, pkt_out, mode in [(conf["tcp"], tcp_pkt_out, "TCP"), (conf["udp"], udp_pkt_out, "UDP")]:
                # Если ipset для этого протокола (например, IPv6) не существует, не пытаемся добавить правило
                if not _ipset_exists(ipset):
                    self._log("info", f"Пропуск {cmd} {mode}: ipset {ipset} не существует")
                    continue
                    
                # Если список исключений nozapret/nozapret6 почему-то отсутствует, создаем временную проверку
                actual_nz = nz_set if _ipset_exists(nz_set) else None

                try:
                    # Собираем аргументы динамически в зависимости от наличия списка исключений
                    args = [
                        cmd, "-t", "mangle", "-A", "POSTROUTING",
                        "-m", "mark", "!", "--mark", f"{desync_mark}/{desync_mark}",
                        "-m", "set", "--match-set", ipset, "dst",
                        "-m", "connbytes", "--connbytes", f"1:{pkt_out}",
                        "--connbytes-mode", "packets", "--connbytes-dir", "original"
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
