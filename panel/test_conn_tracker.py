#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Юнит-тесты для conn_tracker.LifetimeTracker (парсинг /proc/net/tcp, срезы)."""

import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conn_tracker import LifetimeTracker


def _mk_proc(root, tcp_lines, tcp6_lines=None):
    """Создаёт fake <root>/net/tcp и возвращает корень."""
    net = os.path.join(root, "net")
    os.makedirs(net, exist_ok=True)
    header = ("  sl  local_address rem_address   st tx_queue rx_queue "
              "tr tm->when retrnsmt   uid  timeout inode\n")
    with open(os.path.join(net, "tcp"), "w") as f:
        f.write(header)
        for row in tcp_lines:
            f.write(row + "\n")
    if tcp6_lines is not None:
        with open(os.path.join(net, "tcp6"), "w") as f:
            f.write(header)
            for row in tcp6_lines:
                f.write(row + "\n")
    return root


# 8388 = 0x20C4, 1080 = 0x0438, 443 = 0x01BB, эфемерный 50000/50001
_SS_F    = "0A000201:C350 8EFA4A78:01BB"   # исходящее к YouTube:443
_SOCKS_F = "0A000201:C351 AABBCCDD:01BB"   # второе исходящее к :443
_LSTN_F  = "0A000201:20C4 0100007F:0438"   # входящее на ss-server (локальный порт 8388)
_HELP_F  = "0A000201:C352 0A000001:1F90"   # 8080 (не 443) — пропускается
_TIME_F  = "0A000201:C353 8EFA4A78:01BB"   # то же, но state TIME_WAIT


def _row(addr):
    return "0: %s 01 00000000:00000000 00:00000000 00000000   100    0 12345 1 0000000000000000 0 0 0" % addr


class TestReadTcp(unittest.TestCase):
    def test_parsing_filters(self):
        root = tempfile.mkdtemp()
        try:
            lines = [_row(_SS_F), _row(_SOCKS_F), _row(_LSTN_F), _row(_HELP_F)]
            # TIME_WAIT (state 06) — аналогичная строка, но st=06
            lines.append("0: %s 06 00000000:00000000 00:00000000 00000000   100    0 12349 1 0000000000000000 0 0 0" % _TIME_F)
            _mk_proc(root, lines)
            t = LifetimeTracker(8388, 1080, 1888, proc_root=root)
            conns = t._read_tcp_conns()
            # только два внешних :443 ESTABLISHED
            self.assertEqual(len(conns), 2)
            self.assertIn((50000, "8EFA4A78", 443), conns)
            self.assertIn((50001, "AABBCCDD", 443), conns)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_track_and_count(self):
        root = tempfile.mkdtemp()
        try:
            _mk_proc(root, [_row(_SS_F)])
            t = LifetimeTracker(8388, 1080, 1888, proc_root=root)
            t._tick()
            self.assertEqual(t.active_conns, 1)
        finally:
            shutil.rmtree(root, ignore_errors=True)


class TestCut(unittest.TestCase):
    def _tracker(self, require_reset=False, log=lambda l, m: None):
        # пустой /proc/net/tcp — соединение «умерло», как только выпало из таблицы
        root = tempfile.mkdtemp()
        try:
            _mk_proc(root, [])
            t = LifetimeTracker(8388, 1080, 1888, proc_root=root,
                                require_reset=require_reset, log_fn=log)
            return t
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_cut_in_window_fires(self):
        t = self._tracker()
        fired = []
        t.on_cut = lambda lt: fired.append(lt)
        t._conns[(50000, "8EFA4A78", 443)] = time.time() - 45   # умер, прожив 45с
        t._tick()
        self.assertEqual(len(fired), 1)
        self.assertTrue(44 <= fired[0] <= 46)

    def test_healthy_long_connection_ignored(self):
        t = self._tracker()
        fired = []
        t.on_cut = lambda lt: fired.append(lt)
        t._conns[(50000, "8EFA4A78", 443)] = time.time() - 120  # живёт 2 мин — ок
        t._tick()
        self.assertEqual(fired, [])

    def test_too_short_ignored(self):
        t = self._tracker()
        fired = []
        t.on_cut = lambda lt: fired.append(lt)
        t._conns[(50000, "8EFA4A78", 443)] = time.time() - 10   # сам закрыл вкладку
        t._tick()
        self.assertEqual(fired, [])

    def test_require_reset_blocks_without_reset(self):
        t = self._tracker(require_reset=True)
        fired = []
        t.on_cut = lambda lt: fired.append(lt)
        t._conns[(50000, "8EFA4A78", 443)] = time.time() - 45
        t._tick()
        self.assertEqual(fired, [])   # без reset — не подтверждаем

    def test_require_reset_confirmed(self):
        t = self._tracker(require_reset=True)
        fired = []
        t.on_cut = lambda lt: fired.append(lt)
        t.note_reset()                # reset-событие из ss-server лога
        t._conns[(50000, "8EFA4A78", 443)] = time.time() - 45
        t._tick()
        self.assertEqual(len(fired), 1)

    def test_status_fields(self):
        t = self._tracker()
        st = t.get_status()
        self.assertEqual(st["active_conns"], 0)
        self.assertEqual(st["total_cuts"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)