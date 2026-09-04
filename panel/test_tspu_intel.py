#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for tspu_intel (dry-run / pure-function oriented)."""
import io
import os
import shutil
import socket
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tspu_intel import (
    DATASET_VERSION, DEFAULT_TARGET_IP, IntelLog, TspuIntel, _Budget,
    _dns_encode_name, _parse_name, _raw_enabled, build_ip_header,
    build_tcp_packet, build_tls_client_hello, build_quic_initial,
    classify_connection_type, classify_target_host, ip_checksum,
    lookup_asn, parse_ip, parse_tcp, split_payload, tls_is_serverhello,
)


def _can_network():
    try:
        socket.setdefaulttimeout(0.4)
        socket.gethostbyname("1.1.1.1")
        socket.setdefaulttimeout(None)
        return True
    except OSError:
        return False


class TestPrimitives(unittest.TestCase):
    def test_ip_checksum_recomputes_stored(self):
        h = build_ip_header("10.0.0.1", "10.0.0.2", 6, 20, 64, ident=7)
        saved = (h[10] << 8) | h[11]
        hz = bytearray(h); hz[10:12] = b"\x00\x00"
        self.assertEqual(ip_checksum(bytes(hz)), saved)
        # a fully valid header folds to all-ones (inverse-sum convention)
        self.assertEqual(ip_checksum(bytes(h)) & 0xFFFF, 0)

    def test_tcp_roundtrip(self):
        pkt = build_tcp_packet(12345, 443, 500, 600, 0x12, b"hello",
                               "10.0.0.1", "10.0.0.2", 64, ident=9)
        ip = parse_ip(pkt)
        self.assertIsNotNone(ip); self.assertEqual(ip["proto"], 6)
        self.assertEqual(ip["src"], "10.0.0.1"); self.assertEqual(ip["dst"], "10.0.0.2")
        t = parse_tcp(ip["payload"])
        self.assertEqual(t["sport"], 12345); self.assertEqual(t["dport"], 443)
        self.assertEqual(t["seq"], 500); self.assertEqual(t["ack"], 600)
        self.assertEqual(t["flags"], 0x12); self.assertEqual(t["payload"], b"hello")

    def test_build_ip_bad_version_rejected(self):
        self.assertIsNone(parse_ip(b"\x00" * 20))


class TestTlsQuic(unittest.TestCase):
    def test_client_hello_has_sni(self):
        ch = build_tls_client_hello("youtube.com")
        self.assertIn(b"youtube.com", ch)
        self.assertEqual(ch[0], 0x16)  # TLS record

    def test_split_payload_lengths(self):
        ch = build_tls_client_hello("youtube.com", bad_tls=False)
        self.assertEqual(len(split_payload(ch, 2)[0]), 2)
        self.assertEqual(len(split_payload(ch, 5)[1]), len(ch) - 5)

    def test_bad_tls_misaligns_length(self):
        good = build_tls_client_hello("youtube.com", bad_tls=False)
        bad = build_tls_client_hello("youtube.com", bad_tls=True)
        rec_len_good = int.from_bytes(good[3:5], "big")
        rec_len_bad = int.from_bytes(bad[3:5], "big")
        self.assertEqual(rec_len_good + 5, rec_len_bad)
        self.assertTrue(tls_is_serverhello(b"\x16\x03\x01\x00\x02\x02\x03\x03"))
        self.assertFalse(tls_is_serverhello(b"\x13\x03\x01\x00\x02\x02\x03\x03"))

    def test_quic_initial_header(self):
        q = build_quic_initial("youtube.com")
        self.assertEqual(q[0] & 0xC0, 0xC0)  # long header, fixed bit
        self.assertEqual(q[1:5], b"\x00\x00\x00\x01")  # version 1


class TestDns(unittest.TestCase):
    def test_encode_decode_name(self):
        enc = _dns_encode_name("origin.4.3.2.1.asn.cymru.com")
        self.assertTrue(enc.endswith(b"\x00"))
        dec, _ = _parse_name(enc, 0)
        self.assertEqual(dec, "origin.4.3.2.1.asn.cymru.com")

    def test_lookup_asn_requires_network(self):
        if not _can_network():
            self.skipTest("no network")
        res = lookup_asn("1.1.1.1", timeout=1.2)
        if res is None:
            self.skipTest("asn.cymru unreachable")
        self.assertTrue(res["isp_asn"].startswith("AS"))
        self.assertIsInstance(res["isp_name"], str)


class TestClassifiers(unittest.TestCase):
    def test_connection_type(self):
        self.assertEqual(classify_connection_type("10.0.0.1", "x"), "unknown")
        self.assertEqual(classify_connection_type("1.1.1.1", "Cloudflare"), "datacenter")
        self.assertEqual(classify_connection_type("1.1.1.1", "MTS Mobile"), "mobile")
        self.assertEqual(classify_connection_type("77.88.8.8", "Yandex"), "broadband")

    def test_target_host_type(self):
        self.assertEqual(classify_target_host("youtube_com_003", "youtube.com"), "youtube_video")
        self.assertEqual(classify_target_host("discord_voice_01", ""), "discord_voice")
        self.assertEqual(classify_target_host("general", "example.com"), "general_https")


class TestIntelLog(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.path = os.path.join(self.d, "intel.jsonl")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_record_export_clear(self):
        lg = IntelLog(path=self.path)
        e = lg.record({"a": 1}); self.assertIn("id", e)
        self.assertEqual(lg.status()["count"], 1)
        e2 = lg.record({"y": 2})
        self.assertIn("ts", e2)
        txt = lg.export(); self.assertEqual(txt.count("\n"), 2)
        self.assertEqual(len(lg.list(10)), 2)
        self.assertEqual(lg.clear(), {"ok": True})
        self.assertEqual(lg.export(), "")
        self.assertEqual(len(lg.list(10)), 0)


class TestEngineDryRun(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.engine = TspuIntel(path=os.path.join(self.d, "intel.jsonl"),
                                enabled=True, cooldown=0.4, budget_ms=800,
                                dry_run=True)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _ctx(self):
        return {"cut_id": 1, "event_kind": "epidemic", "lifetime_sec": 12.3,
                "reset_confirmed": True, "remote_ip": "142.250.74.110",
                "remote_port": 443, "local_port": 54000, "qnum": 301,
                "slot_index": 1, "strategy_name": "youtube_com_003",
                "nfqws_opt": "--filter-tcp=443 --lua-desync=split:pos=2",
                "strategy_score_before": -0.9, "bytes_delta": 1420500,
                "termination_type": None}

    def test_status_and_mode(self):
        st = self.engine.status()
        self.assertTrue(st["enabled"]); self.assertEqual(st["mode"], "dry_run")
        self.assertIn("log_path", st)

    def test_run_schema(self):
        r = self.engine.run(self._ctx())
        self.assertEqual(r["dataset_version"], "1.1")
        for blk in ("environment", "session_profile", "tspu_network_metrics",
                    "tspu_l7_vulnerabilities", "strategy_context"):
            self.assertIn(blk, r)
        self.assertIn("tspu_hop", r["tspu_network_metrics"])
        self.assertIn("delta_distance", r["tspu_network_metrics"])
        self.assertEqual(r["tspu_network_metrics"]["delta_distance"], 6)
        self.assertTrue(r["meta"]["simulated"])
        self.assertEqual(r["environment"]["target_host_type"], "youtube_video")
        self.assertEqual(r["session_profile"]["termination_type"], "RST")

    def test_cooldown_blocks_second_run(self):
        r1 = self.engine.on_cut_async(self._ctx())
        self.assertTrue(r1["ok"])
        r2 = self.engine.on_cut_async(self._ctx())
        self.assertFalse(r2["ok"])
        self.assertIn(r2.get("reason", ""), ("cooldown", "already_running"))
        end = time.time() + 0.6
        while time.time() < end:
            if not self.engine._running:
                break
            time.sleep(0.05)
        time.sleep(0.5)
        r3 = self.engine.on_cut_async(self._ctx())
        self.assertTrue(r3["ok"])

    def test_budget_guarded(self):
        eng = TspuIntel(path=os.path.join(self.d, "b.jsonl"), dry_run=True, budget_ms=200,
                        enabled=True, cooldown=0)
        start = time.monotonic()
        r = eng.run(self._ctx())
        el = (time.monotonic() - start) * 1000.0
        self.assertLess(el, 900)
        self.assertIn("tspu_l7_vulnerabilities", r)

    def test_intel_log_written_by_async(self):
        self.engine.on_cut_async(self._ctx())
        end = time.time() + 2.0
        while time.time() < end:
            if not self.engine._running and self.engine._last_result_ts is not None:
                break
            time.sleep(0.02)
        n = self.engine.intel_log.status()["count"]
        self.assertEqual(n, 1)
        self.assertIsNotNone(self.engine._last_result)


class TestBudget(unittest.TestCase):
    def test_remaining_and_expiry(self):
        b = _Budget(0.05)
        self.assertGreater(b.remaining(), 0)
        time.sleep(0.07)
        self.assertFalse(b.ok())


if __name__ == "__main__":
    unittest.main(verbosity=2)