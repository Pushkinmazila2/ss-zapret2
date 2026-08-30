#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Юнит-тесты для conn_tracker.LifetimeTracker (парсинг /proc/net/tcp, сессии YouTube)."""

import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conn_tracker import LifetimeTracker

# Отключаем диагностические prints из трекера
_orig_print = print
def _silent(*a, **kw): pass

# Сохраняем оригинальный print для unittest
import builtins


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


# 8388 = 0x20C4, 1080 = 0x0438, 443 = 0x01BB, эфемерные 50000/50001
_SS_F    = "0A000201:C350 8EFA4A78:01BB"   # исходящее к YouTube:443
_HELP_F  = "0A000201:C352 0A000001:1F90"   # 8080 (не 443) — пропускается


def _row(addr):
    return "0: %s 01 00000000:00000000 00:00000000 00000000   100    0 12345 1 0000000000000000 0 0 0" % addr


class TestReadTcp(unittest.TestCase):
    def test_parsing_filters(self):
        root = tempfile.mkdtemp()
        try:
            lines = [_row(_SS_F), _row(_HELP_F)]
            _mk_proc(root, lines)
            t = LifetimeTracker(8388, 1080, 1888, proc_root=root)
            conns = t._read_tcp_conns()
            self.assertEqual(len(conns), 1)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_empty_proc(self):
        root = tempfile.mkdtemp()
        try:
            _mk_proc(root, [])
            t = LifetimeTracker(8388, 1080, 1888, proc_root=root)
            self.assertEqual(t._read_tcp_conns(), set())
        finally:
            shutil.rmtree(root, ignore_errors=True)


class TestSessionLogic(unittest.TestCase):
    """New logic: track YouTube session by :443 activity."""

    def _mk_root(self):
        root = tempfile.mkdtemp()
        _mk_proc(root, [])
        return root

    def test_cut_after_inactivity(self):
        root = self._mk_root()
        t = LifetimeTracker(8388, 1080, 1888, proc_root=root,
                            cut_min_sec=30, cut_max_sec=60, require_reset=False)
        fired = []
        t.on_cut = lambda lt: fired.append(lt)
        t._session_start = time.time() - 40
        t._last_activity = time.time() - 8
        t._yt_active = False
        t._tick()
        self.assertEqual(len(fired), 1)
        self.assertTrue(38 <= fired[0] <= 48)

    def test_short_session_ignored(self):
        root = self._mk_root()
        t = LifetimeTracker(8388, 1080, 1888, proc_root=root,
                            cut_min_sec=30, cut_max_sec=60, require_reset=False)
        fired = []
        t.on_cut = lambda lt: fired.append(lt)
        t._session_start = time.time() - 10
        t._last_activity = time.time() - 6
        t._yt_active = False
        t._tick()
        self.assertEqual(fired, [])

    def test_require_reset_blocks_without_reset(self):
        root = self._mk_root()
        t = LifetimeTracker(8388, 1080, 1888, proc_root=root,
                            cut_min_sec=30, cut_max_sec=60, require_reset=True)
        fired = []
        t.on_cut = lambda lt: fired.append(lt)
        t._session_start = time.time() - 40
        t._last_activity = time.time() - 6
        t._yt_active = False
        t._tick()
        self.assertEqual(fired, [])

    def test_require_reset_with_reset(self):
        root = self._mk_root()
        t = LifetimeTracker(8388, 1080, 1888, proc_root=root,
                            cut_min_sec=30, cut_max_sec=60, require_reset=True)
        fired = []
        t.on_cut = lambda lt: fired.append(lt)
        t.note_reset()
        t._session_start = time.time() - 40
        t._last_activity = time.time() - 6
        t._yt_active = False
        t._tick()
        self.assertEqual(len(fired), 1)

    def test_short_inactivity_no_cut(self):
        root = self._mk_root()
        t = LifetimeTracker(8388, 1080, 1888, proc_root=root,
                            cut_min_sec=30, cut_max_sec=60, require_reset=False)
        t._session_start = time.time() - 35
        t._last_activity = time.time() - 2
        t._yt_active = False
        fired = []
        t.on_cut = lambda lt: fired.append(lt)
        t._tick()
        self.assertEqual(fired, [])

    def test_status_fields(self):
        root = self._mk_root()
        t = LifetimeTracker(8388, 1080, 1888, proc_root=root)
        st = t.get_status()
        self.assertIn("yt_active", st)
        self.assertIn("session_start", st)
        self.assertIn("last_activity", st)

if __name__ == "__main__":
    builtins.print = _orig_print
    unittest.main(verbosity=2)
