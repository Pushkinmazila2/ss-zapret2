#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Юнит-тесты PoolManager для журнала срезов: _parse_mark и slot_for_conn."""
import io
import os
import shutil
import sys
import tempfile
import threading
import unittest
from unittest import mock

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pool_manager import PoolManager, Slot


def bare_manager(conntrack_path):
    """PoolManager без __init__ — чтобы не трогать /run на Windows."""
    pm = PoolManager.__new__(PoolManager)
    pm._lock = threading.Lock()
    pm._slots = []
    pm._shadows = []
    pm._fail_closed = False
    pm._nf_conntrack_path = conntrack_path
    pm._log = lambda lvl, msg: None
    return pm


def make_slot(index, qnum, strategy="disorder"):
    s = Slot(index)
    s.qnum = qnum
    s.strategy = strategy
    return s


class TestParseMark(unittest.TestCase):
    def test_hex_prefixed(self):
        self.assertEqual(PoolManager._parse_mark("0x12d"), 301)

    def test_hex_bare(self):
        self.assertEqual(PoolManager._parse_mark("12d"), 301)

    def test_decimal(self):
        self.assertEqual(PoolManager._parse_mark("301"), 301)

    def test_garbage(self):
        self.assertIsNone(PoolManager._parse_mark("zzz"))
        self.assertIsNone(PoolManager._parse_mark(None))


class TestSlotForConn(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ct_")
        self.path = os.path.join(self.tmp, "nf_conntrack")
        self.pm = bare_manager(self.path)
        self.pm._slots = [make_slot(1, 301)]
        self.conn = (52134, "784AFA8E", 443)   # → 142.250.74.120

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, text):
        with io.open(self.path, "w", encoding="ascii") as f:
            f.write(text)

    def test_found_hex_mark(self):
        self._write(
            "tcp 6 431998 ESTABLISHED src=172.17.0.2 dst=142.250.74.120 "
            "sport=52134 dport=443 packets=10 bytes=1400 "
            "src=142.250.74.120 dst=172.17.0.2 sport=443 dport=52134 "
            "mark=0x12d use=1\n")
        slot, reason = self.pm.slot_for_conn(self.conn)
        self.assertIsNone(reason)
        self.assertEqual(slot["index"], 1)
        self.assertEqual(slot["qnum"], 301)
        self.assertEqual(slot["strategy"], "disorder")

    def test_found_decimal_mark(self):
        self._write(
            "tcp 6 100 ESTABLISHED src=172.17.0.2 dst=142.250.74.120 "
            "sport=52134 dport=443 src=142.250.74.120 dst=172.17.0.2 "
            "sport=443 dport=52134 mark=301 use=1\n")
        slot, reason = self.pm.slot_for_conn(self.conn)
        self.assertIsNone(reason)
        self.assertEqual(slot["qnum"], 301)

    def test_no_entry(self):
        self._write(
            "tcp 6 100 ESTABLISHED src=172.17.0.2 dst=1.2.3.4 "
            "sport=1111 dport=443 mark=0x12d use=1\n")
        slot, reason = self.pm.slot_for_conn(self.conn)
        self.assertIsNone(slot)
        self.assertEqual(reason, "conntrack entry not found")

    def test_missing_procfs(self):
        # файл не создавали → procfs "недоступен" (типичный кейс в контейнере)
        slot, reason = self.pm.slot_for_conn(self.conn)
        self.assertIsNone(slot)
        self.assertIn("unavailable", reason)

    # ── fallback через бинарник conntrack (procfs недоступен) ──────────

    class _R:
        returncode = 0
        stdout = ("tcp 6 100 ESTABLISHED src=172.17.0.2 dst=142.250.74.120 "
                  "sport=52134 dport=443 mark=0x12d use=1\n")
        stderr = ""

    def test_fallback_binary_found(self):
        from unittest import mock
        # procfs отсутствует, но бинарник conntrack отдаёт нужную запись
        with mock.patch("pool_manager.subprocess.run", return_value=self._R()):
            slot, reason = self.pm.slot_for_conn(self.conn)
        self.assertIsNone(reason)
        self.assertEqual(slot["qnum"], 301)
        self.assertEqual(slot["strategy"], "disorder")

    def test_fallback_binary_no_entry(self):
        from unittest import mock

        class R:
            returncode = 0
            stdout = ""
            stderr = ""
        with mock.patch("pool_manager.subprocess.run", return_value=R()):
            slot, reason = self.pm.slot_for_conn(self.conn)
        self.assertIsNone(slot)
        self.assertIn("unavailable", reason)

    def test_fallback_binary_missing(self):
        from unittest import mock
        # бинарника нет вовсе (OSError) — тихий отказ
        with mock.patch("pool_manager.subprocess.run",
                        side_effect=OSError("no conntrack")):
            slot, reason = self.pm.slot_for_conn(self.conn)
        self.assertIsNone(slot)
        self.assertIn("unavailable", reason)

    def test_qnum_not_in_slots(self):
        self._write(
            "tcp 6 100 ESTABLISHED src=172.17.0.2 dst=142.250.74.120 "
            "sport=52134 dport=443 mark=0x999 use=1\n")
        slot, reason = self.pm.slot_for_conn(self.conn)
        self.assertIsNone(reason)
        self.assertEqual(slot["qnum"], 0x999)
        self.assertIsNone(slot["strategy"])


class TestReloadFwRules(unittest.TestCase):
    """Fail-Fast/FW: _reload_fw собирает POSTROUTING без -m connbytes."""

    class _R:
        returncode = 0
        stdout = ""
        stderr = ""

    class _P:
        """Фейковый живой процесс nfqws2."""
        pid = 4242
        def poll(self):
            return None

    def setUp(self):
        from unittest import mock
        from pool_manager import Slot
        self.pm = bare_manager(None)
        self.pm._log = lambda lvl, msg: None
        s1 = make_slot(0, 301); s1.nfqws_opt = "x"; s1.proc = self._P()
        s2 = make_slot(1, 302); s2.nfqws_opt = "x"; s2.proc = self._P()
        self.pm._slots = [s1, s2]
        sh = Slot(100); sh.qnum = 400; sh.nfqws_opt = "x"; sh.proc = self._P()
        self.pm._shadows = [sh]
        self.calls = []
        self.patcher = mock.patch("pool_manager.subprocess.run",
                                  side_effect=self._record)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        ports = mock.patch.object(self.pm, "_read_nfqws2_ports",
                                  return_value=("80,443", "443"))
        ports.start()
        self.addCleanup(ports.stop)

    def _record(self, args, **kw):
        self.calls.append(list(args) if isinstance(args, (list, tuple)) else [args])
        return type(self)._R()

    def test_postrouting_pure_ipset_no_connbytes(self):
        self.pm._reload_fw()   # не должно падать (раньше был NameError на pkt_out)
        postrouting = [" ".join(c) for c in self.calls
                       if "-I" in c and "POSTROUTING" in c and "ZAPRET_POOL" in c]
        self.assertEqual(len(postrouting), 4)  # iptables/ip6tables × tcp/udp
        for line in postrouting:
            self.assertNotIn("connbytes", line)
            self.assertIn("-m mark ! --mark 0x40000000/0x40000000", line)
        self.assertIn(
            "iptables -t mangle -I POSTROUTING 1"
            " -m mark ! --mark 0x40000000/0x40000000"
            " -p tcp"
            " -m set --match-set zport_tcp dst"
            " -m set ! --match-set nozapret dst"
            " -j ZAPRET_POOL", postrouting)
        # цепочка ZAPRET_POOL содержит NFQUEUE для всех активных qnum
        chain = [" ".join(c) for c in self.calls
                 if "-A" in c and "ZAPRET_POOL" in c and "NFQUEUE" in c]
        qnums = {q for line in chain
                 for q in [line.rsplit("--queue-num", 1)[1].split()[0]]}
        self.assertEqual(qnums, {"301", "302"})

    def test_partial_ipsets_fall_back_per_family_and_protocol(self):
        def run(args, **kwargs):
            result = self._record(args, **kwargs)
            if args[:2] == ["ipset", "list"] and args[2] != "zport_tcp":
                result.returncode = 1
            return result

        with mock.patch("pool_manager.subprocess.run", side_effect=run):
            self.pm._reload_fw()
        hooks = [c for c in self.calls
                 if "POSTROUTING" in c and "ZAPRET_POOL" in c and "-I" in c]
        self.assertEqual(len(hooks), 4)
        for cmd in ("iptables", "ip6tables"):
            for protocol in ("tcp", "udp"):
                hook = next(c for c in hooks if c[0] == cmd and
                            c[c.index("-p") + 1] == protocol)
                self.assertEqual(hook[3:6], ["-I", "POSTROUTING", "1"])
                if (cmd, protocol) == ("iptables", "tcp"):
                    self.assertIn("zport_tcp", hook)
                else:
                    self.assertIn("--dports", hook)

    def test_missing_ipsets_use_priority_port_hooks(self):
        def run(args, **kwargs):
            result = self._record(args, **kwargs)
            if args[0] == "ipset":
                result.returncode = 1
            return result

        with mock.patch("pool_manager.subprocess.run", side_effect=run):
            self.pm._reload_fw()
        hooks = [c for c in self.calls if "POSTROUTING" in c and "--dports" in c]
        self.assertEqual(len(hooks), 4)
        for hook in hooks:
            self.assertEqual(hook[3:6], ["-I", "POSTROUTING", "1"])
            self.assertEqual(hook[-2:], ["-j", "ZAPRET_POOL"])

    def test_cleanup_removes_pool_queues_and_preserves_other_queues(self):
        listed = set()

        def run(args, **kwargs):
            result = self._record(args, **kwargs)
            if "--line-numbers" in args and args[0] not in listed:
                listed.add(args[0])
                result.stdout = (
                    "1 NFQUEUE tcp -- 0.0.0.0/0 0.0.0.0/0 NFQUEUE num 200 bypass\n"
                    "2 NFQUEUE tcp -- 0.0.0.0/0 0.0.0.0/0 NFQUEUE num 300 bypass\n"
                    "3 ZAPRET_POOL all -- 0.0.0.0/0 0.0.0.0/0\n")
            return result

        with mock.patch("pool_manager.subprocess.run", side_effect=run):
            self.pm._reload_fw()
        for cmd in ("iptables", "ip6tables"):
            deleted = [c[-1] for c in self.calls
                       if c[0] == cmd and "-D" in c and "POSTROUTING" in c]
            self.assertEqual(deleted, ["3", "2"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
