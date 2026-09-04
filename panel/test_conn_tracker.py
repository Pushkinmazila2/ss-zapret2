#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Юнит-тесты для conn_tracker.LifetimeTracker — детектора ТСПУ.

Проверяем:
  - парсинг /proc/net/tcp (fake proc_root): фильтры :443/loopback/свои порты;
  - RST-смерть (соединение исчезло) → классический срез в [cut_min, cut_max];
  - FIN-закрытие (CLOSE_WAIT/FIN_WAIT*) → НЕ срез, только счётчик;
  - слишком короткая RST-смерть (< short_min_sec) → игнор;
  - эпидемия: >= epidemic_min_events RST-смертей за окно → срез;
  - require_reset=True без reset-событий срез блокируется, note_reset() разблокирует;
  - configure(): клампы значений; get_status(): наличие полей.
"""
import io
import os
import shutil
import sys
import tempfile
import time
import unittest

# UTF-8 stdout/stderr (в Windows консоль по умолчанию cp1251)
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from conn_tracker import LifetimeTracker

CONN = (52134, "8EFA4A78", 443)   # (local_port, remote_ip_hex, remote_port)


def make_tracker(**kw):
    kw.setdefault("log_fn", lambda lvl, msg: None)
    return LifetimeTracker(ss_port=8388, socks_port=1080, panel_port=1888, **kw)


class TestProcParsing(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="fakeproc_")
        self.netdir = os.path.join(self.root, "net")
        os.makedirs(self.netdir, exist_ok=True)
        self.t = make_tracker(proc_root=self.root)
        self.t._log = lambda lvl, msg: None

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _write(self, name, lines):
        with io.open(os.path.join(self.netdir, name), "w", encoding="ascii") as f:
            f.write("\n".join(lines) + "\n")

    def test_filters_and_parse(self):
        self._write("tcp", [
            "  sl local_address rem_address   st tx_queue rx_queue tr tm->when",
            "   0: 0182AC1E:CBAA  8EFA4A78:01BB 01 00000000:00000000 00:0 0",
            "   1: 0182AC1E:CBAB  0100007F:01BB 01 00000000:00000000 00:0 0",
            "   2: 0182AC1E:CBAC  8EFA4A78:0050 01 00000000:00000000 00:0 0",
            "   3: 0182AC1E:20C4  8EFA4A79:01BB 0A 00000000:00000000 00:0 0",
            "   4: 0182AC1E:CBAD  00000000000000000000000001000000:01BB 01 00",
        ])
        self._write("tcp6", [
            "  sl local_address rem_address   st tx_queue rx_queue tr tm->when",
            "   0: 0182AC1E:CBAE  8EFA4A7A:01BB 01 00000000:00000000 00:0 0",
        ])
        conns = self.t._read_tcp_conns()
        self.assertEqual(set(conns.keys()), {
            (0xCBAA, "8EFA4A78", 443),
            (0xCBAE, "8EFA4A7A", 443),
        })
        self.assertEqual(conns[(0xCBAA, "8EFA4A78", 443)], "01")

    def test_missing_files_ok(self):
        self.assertEqual(self.t._read_tcp_conns(), {})


class TestCutDetection(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.t = make_tracker(cut_min_sec=30, cut_max_sec=60,
                              epidemic_min_events=4, short_min_sec=5)
        self.t._log = lambda lvl, msg: None
        self.t.on_cut = self.events.append

    def _established(self, conn=CONN, ago=42.0):
        self.t._conns[conn] = {"first": time.time() - ago,
                               "last": time.time(), "state": "01"}

    def test_classic_rst_cut(self):
        self._established(ago=42.0)
        self.t._read_tcp_conns = lambda: {}      # соединение исчезло → RST-смерть
        self.t._tick()
        self.assertEqual(len(self.events), 1)
        ev = self.events[0]
        self.assertEqual(ev["kind"], "classic")
        self.assertTrue(30 <= ev["lifetime_sec"] <= 60)
        self.assertEqual(ev["conn"], CONN)
        self.assertTrue(ev["reset_confirmed"])
        self.assertEqual(self.t.total_cuts, 1)
        self.assertEqual(self.t.last_cut_lifetime, ev["lifetime_sec"])

    def test_out_of_range_lifetime_no_cut(self):
        self._established(ago=100.0)             # дольше cut_max → не срез
        self.t._read_tcp_conns = lambda: {}
        self.t._tick()
        self.assertEqual(self.events, [])
        self.assertEqual(self.t.total_cuts, 0)
        self.assertGreaterEqual(self.t.rst_deaths_window, 1)

    def test_fin_close_not_a_cut(self):
        self._established(ago=42.0)
        self.t._read_tcp_conns = lambda: {CONN: "08"}   # CLOSE_WAIT → FIN
        self.t._tick()
        self.assertEqual(self.events, [])
        self.assertEqual(self.t.fin_deaths_window, 1)
        self.assertEqual(self.t.rst_deaths_window, 0)

    def test_too_short_rst_ignored(self):
        self._established(ago=1.0)               # < short_min_sec(5) → игнор
        self.t._read_tcp_conns = lambda: {}
        self.t._tick()
        self.assertEqual(self.events, [])
        self.assertEqual(self.t.rst_deaths_window, 0)

    def test_epidemic_cut(self):
        now = time.time()
        for i in range(4):                        # 4 короткие RST-смерти за окно
            self.t._deaths.append((now - i, 10.0 + i, (50000 + i, "8EFA4A78", 443)))
        self.t._read_tcp_conns = lambda: {}
        self.t._tick()
        self.assertEqual(len(self.events), 1)
        ev = self.events[0]
        self.assertEqual(ev["kind"], "epidemic")
        self.assertGreaterEqual(ev["rst_deaths_window"], 4)
        self.assertEqual(self.t.total_cuts, 1)

    def test_require_reset_gate(self):
        self.t.require_reset = True
        self._established(ago=42.0)
        self.t._read_tcp_conns = lambda: {}
        self.t._tick()                            # нет reset-событий → тишина
        self.assertEqual(self.events, [])
        self.t.note_reset()                       # подтверждение из ss-лога
        self._established(ago=42.0)
        self.t._read_tcp_conns = lambda: {}
        self.t._tick()
        self.assertEqual(len(self.events), 1)
        self.assertEqual(self.events[0]["kind"], "classic")


class TestConfigureStatus(unittest.TestCase):
    def test_configure_clamps(self):
        t = make_tracker()
        t._log = lambda lvl, msg: None
        st = t.configure({"epidemic_min_events": 1,       # кламп до 2
                          "epidemic_window_sec": 5,       # кламп до 20
                          "short_min_sec": 0.5,           # кламп до 2
                          "cut_min_sec": 10, "cut_max_sec": 5,   # → сортировка
                          "require_reset": True})
        self.assertEqual(st["epidemic_min_events"], 2)
        self.assertEqual(st["epidemic_window_sec"], 20)
        self.assertEqual(st["short_min_sec"], 2.0)
        self.assertEqual(st["cut_min_sec"], 5)            # lo
        self.assertEqual(st["cut_max_sec"], 10)           # hi
        self.assertTrue(st["require_reset"])

    def test_status_fields(self):
        t = make_tracker()
        t._log = lambda lvl, msg: None
        st = t.get_status()
        for key in ("active_conns", "tracked", "poll_interval", "cut_min_sec",
                    "cut_max_sec", "require_reset", "epidemic_min_events",
                    "short_min_sec", "epidemic_window_sec", "rst_deaths_window",
                    "fin_deaths_window", "last_cut_lifetime", "last_cut_ts",
                    "last_cut_conn", "total_cuts", "recent_resets"):
            self.assertIn(key, st)


if __name__ == "__main__":
    unittest.main(verbosity=2)
