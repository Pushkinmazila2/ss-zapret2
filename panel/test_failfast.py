#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Юнит-тесты Fail-Fast ротации PoolSwitcher при срезе ТСПУ (classic/epidemic)."""
import io
import os
import sys
import tempfile
import threading
import time
import unittest

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

os.environ["CUT_LOG_PATH"] = os.path.join(tempfile.mkdtemp(prefix="ff_"), "cuts.jsonl")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import server as S

CONN = (52134, "8EFA4A78", 443)   # → 142.250.74.120:443
EVENT = {
    "kind": "classic",
    "lifetime_sec": 42.5,
    "conn": CONN,
    "rst_deaths_window": 3,
    "fin_deaths_window": 8,
    "reset_confirmed": True,
}


def _make_strategies(d, count=6):
    """Создаёт count .conf-файлов стратегий в каталоге d."""
    for i in range(1, count + 1):
        with io.open(os.path.join(d, "yt_%03d.conf" % i), "w", encoding="utf-8") as f:
            f.write("# test\nNFQWS2_OPT=\"\n--filter-tcp=443 --filter-l7=tls "
                    "--lua-desync=fake:blob=v%d\n\"\n" % i)


class FakePool:
    """Заглушка PoolManager с записью вызовов."""

    def __init__(self):
        self._slots = [{
            "index": 1, "qnum": 301, "strategy": "youtube_com_005",
            "healthy": True, "alive": True, "fw_excluded": False, "pid": 1234,
        }]
        self.replaced      = []   # (index, name, nfqws)
        self.shadow_start  = []   # (name,)
        self.shadow_stop   = []   # (qnum,)
        self.fw_removed    = []   # [indices]
        self.fw_restored   = []   # [index]
        self.health        = {}   # (index, healthy)

    # ── методы, которые дергает fail-fast ────────────────────────────────

    def get_status(self):
        return [dict(s) for s in self._slots]

    def get_traffic_stats(self):
        return {301: {"qnum": 301, "pkts_delta": 500, "bytes_delta": 640000,
                      "kbps": 900.0, "share": 100.0, "active": True,
                      "source": "iptables"}}

    def slot_for_conn(self, conn):
        s = self._slots[0]
        return {"index": s["index"], "qnum": s["qnum"],
                "strategy": s["strategy"], "nfqws_pid": s["pid"],
                "nfqws_opt": "--filter-tcp=443 --new",
                "healthy": s["healthy"], "fw_excluded": s["fw_excluded"]}, None

    def slot_log_tail(self, index, limit=40):
        return ["[NFQWS2][SLOT-%d] line" % index]

    def remove_slots_from_fw(self, indices):
        self.fw_removed.append(list(indices))
        for s in self._slots:
            if s["index"] in indices:
                s["fw_excluded"] = True

    def restore_slot_to_fw(self, index):
        self.fw_restored.append(index)
        for s in self._slots:
            if s["index"] == index:
                s["fw_excluded"] = False

    def replace_slot(self, index, name, nfqws):
        # QNUM сохраняется — меняются только args процесса
        self.replaced.append((index, name, nfqws))
        for s in self._slots:
            if s["index"] == index:
                s["strategy"] = name

    def set_slot_health(self, index, healthy):
        self.health[(index, healthy)] = True
        for s in self._slots:
            if s["index"] == index:
                s["healthy"] = healthy

    def start_shadow(self, name, nfqws):
        self.shadow_start.append(name)
        return {"index": 100, "qnum": 400}

    def stop_shadow(self, qnum):
        self.shadow_stop.append(qnum)

    def shadow_pkts(self, qnum):
        return 0


def _wait_ok(sw, timeout=5):
    """Ждёт завершения фонового потока ротации (state == ok)."""
    end = time.time() + timeout
    while time.time() < end:
        with sw._lock:
            if sw.state == "ok":
                return True
        time.sleep(0.05)
    return False


def _new_switcher(tmp):
    S.STRAT_DIR = tmp
    S.cut_logger.clear()
    pool = FakePool()
    sw = S.PoolSwitcher(pool)
    sw.enabled = True
    sw.cut_rotate_enabled = True
    sw._cut_last_ts = None
    return sw, pool


class TestFailFastCut(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="strat_")
        _make_strategies(self.tmp)

    def test_cut_is_instant_no_shadow(self):
        """Срез → мгновенная замена без теневого теста, QNUM сохранён."""
        sw, pool = _new_switcher(self.tmp)
        self.assertFalse(sw.shadow_test_enabled)
        sw.on_connection_cut(EVENT)
        self.assertTrue(_wait_ok(sw), "ротация не завершилась")
        # точечная замена одного слота: тот же index, новая стратегия из резерва
        self.assertEqual(len(pool.replaced), 1)
        idx, name, nfqws = pool.replaced[0]
        self.assertEqual(idx, 1)                       # SLOT-1 из conntrack
        self.assertNotEqual(name, "youtube_com_005")   # НЕ мёртвая стратегия
        self.assertTrue(nfqws.startswith("--filter-tcp=443"))
        # слот убран из fw на время замены и возвращён
        self.assertEqual(pool.fw_removed, [[1]])
        self.assertEqual(pool.fw_restored, [1])
        # теневой тест не запускался вообще
        self.assertEqual(pool.shadow_start, [])
        self.assertEqual(pool.shadow_stop, [])
        # штрафы сброшены: новая стратегия 0, счётчик провалов слота 0
        self.assertEqual(sw.strategy_scores.get(name), 0.0)
        self.assertEqual(sw._slot_fails.get(1), 0)

    def test_dead_strategy_demoted_to_end_of_pool(self):
        """Мёртвая стратегия уходит в конец пула и не возвращается в rotation."""
        sw, pool = _new_switcher(self.tmp)
        sw.on_connection_cut(EVENT)
        self.assertTrue(_wait_ok(sw))
        self.assertIn("youtube_com_005", sw._demoted)
        # скор старения (×0.98 за попытку) может чуть поднять −20.0, но он остаётся
        # минимальным в пуле — max() выберет эту стратегию самой последней
        self.assertLessEqual(sw.strategy_scores["youtube_com_005"], -19.0)
        # резерв отдаёт только свежие стратегии — демотированная не выбирается
        batch = sw._next_strategy_batch(3)
        names = [n for n, _opt in batch]
        self.assertNotIn("youtube_com_005", names)
        self.assertTrue(all(n.startswith("yt_") for n in names))
        # когда пул исчерпан — демо-сброс: стратегия снова может быть испытана
        with sw._lock:
            sw._used = {s["name"] for s in S.list_strategies()}
        name, _opt = sw._next_strategy()
        self.assertIsNotNone(name)
        self.assertEqual(sw._demoted, set())

    def test_shadow_test_optional_when_enabled(self):
        """Теневой тест запускается только при shadow_test_enabled=True."""
        sw, pool = _new_switcher(self.tmp)
        sw.shadow_test_enabled = True
        sw._probe_shadow = lambda shadow, window=10, min_pkts=2: True
        sw.on_connection_cut(EVENT)
        self.assertTrue(_wait_ok(sw))
        self.assertEqual(pool.shadow_start, ["yt_001"])   # первая свежая
        self.assertEqual(pool.shadow_stop, [400])         # теневой слот остановлен
        self.assertEqual(len(pool.replaced), 1)

    def test_shadow_fail_never_restores_dead_strategy(self):
        """Даже если все кандидаты провалили теневой тест — мёртвая стратегия
        НЕ возвращается в rotation, слот остаётся вне iptables."""
        sw, pool = _new_switcher(self.tmp)
        sw.shadow_test_enabled = True
        sw._probe_shadow = lambda shadow, window=10, min_pkts=2: False
        sw.on_connection_cut(EVENT)
        self.assertTrue(_wait_ok(sw))
        self.assertEqual(pool.replaced, [])               # замены не было
        self.assertEqual(len(pool.shadow_start), 3)       # проверены 3 кандидата
        self.assertNotIn(1, pool.fw_restored)             # старая НЕ возвращена
        self.assertTrue(pool.get_status()[0]["fw_excluded"])

    def test_state_ok_not_degraded(self):
        """После замены state=ok — панель не висит в replacing/degraded."""
        sw, pool = _new_switcher(self.tmp)
        sw.on_connection_cut(EVENT)
        self.assertTrue(_wait_ok(sw))
        with sw._lock:
            self.assertEqual(sw.state, "ok")

    def test_epidemic_event_triggers_failfast(self):
        """Событие kind=epidemic обрабатывается так же, как classic."""
        sw, pool = _new_switcher(self.tmp)
        ev = dict(EVENT)
        ev["kind"] = "epidemic"
        ev["rst_deaths_window"] = 7
        sw.on_connection_cut(ev)
        self.assertTrue(_wait_ok(sw))
        self.assertEqual(len(pool.replaced), 1)

    def test_configure_shadow_options(self):
        """shadow-опции доступны через configure/status."""
        sw, pool = _new_switcher(self.tmp)
        st = sw.configure({"shadow_test_enabled": True,
                           "shadow_window": 7, "shadow_min_pkts": 3})
        self.assertTrue(st["shadow_test_enabled"])
        self.assertEqual(st["shadow_window"], 7)
        self.assertEqual(st["shadow_min_pkts"], 3)
        sw.configure({"shadow_test_enabled": False})


if __name__ == "__main__":
    unittest.main(verbosity=2)
