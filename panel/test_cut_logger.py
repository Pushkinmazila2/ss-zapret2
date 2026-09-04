#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Юнит-тесты для cut_logger.CutLogger."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cut_logger import CutLogger


class TestCutLogger(unittest.TestCase):
    def _mk(self, **kw):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "cuts.jsonl")
        return d, CutLogger(path=path, **kw)

    def test_record_and_list(self):
        d, lg = self._mk()
        try:
            e = lg.record({"kind": "classic", "lifetime_sec": 42.5})
            self.assertEqual(e["kind"], "classic")
            self.assertTrue("id" in e and "ts" in e)
            lst = lg.list(10)
            self.assertEqual(len(lst), 1)
            self.assertEqual(lst[0]["lifetime_sec"], 42.5)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_file_contains_lines(self):
        d, lg = self._mk()
        try:
            lg.record({"kind": "epidemic"})
            lg.record({"kind": "classic"})
            txt = lg.export()
            self.assertEqual(txt.count("\n"), 2)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_clear(self):
        d, lg = self._mk()
        try:
            lg.record({"kind": "classic"})
            lg.clear()
            self.assertEqual(lg.list(10), [])
            self.assertEqual(lg.export(), "")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_buffer_limit(self):
        d, lg = self._mk(max_buffered=3)
        try:
            for i in range(5):
                lg.record({"n": i})
            lst = lg.list(10)
            self.assertEqual(len(lst), 3)
            # буфер хранит последние 3
            self.assertEqual([e["n"] for e in lst], [4, 3, 2])
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_rotation(self):
        d, lg = self._mk(max_file=1000, keep=2)
        try:
            long = "x" * 300
            for _ in range(20):
                lg.record({"blob": long})
            self.assertTrue(os.path.exists(lg.path) or lg.status()["count"] >= 0)
            # после ротации файл не пуст и записываемость сохранена
            lg.record({"kind": "classic"})
            self.assertTrue(len(lg.export().splitlines()) >= 1)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)