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
    DATASET_VERSION, DEFAULT_PROBE_MARK, DEFAULT_TARGET_IP, IntelLog,
    TspuIntel, _ASN_CACHE, _Budget, _RESOLVE_CACHE, _apply_probe_mark,
    _dns_encode_name, _dns_resolvers, _guess_domain, _parse_mark_value,
    _parse_name, _raw_enabled, _reset_dns_caches, _rst_fingerprint,
    _ttl_map_summary, build_ip_header, build_tcp_packet,
    build_tls_client_hello, build_quic_initial, classify_connection_type,
    classify_target_host, ip_checksum, lookup_asn, parse_ip, parse_tcp,
    scan_destination_hop, split_payload, tls_is_serverhello, TCP_URG,
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
        self.assertEqual(r["dataset_version"], "1.2")
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


class _FakeSniffer:
    """Deterministic sniffer stub for scan_destination_hop unit tests."""

    def __init__(self, recs):
        self.recs = recs

    def query(self, since, matcher):
        now = since + 0.01
        out = []
        for r in self.recs:
            rr = dict(r)
            rr["t"] = now
            if matcher(rr):
                out.append(rr)
        return out


class TestIntelFixes(unittest.TestCase):
    """Unit coverage for the dataset-quality fixes (offline)."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.engine = TspuIntel(path=os.path.join(self.d, "intel.jsonl"),
                                enabled=True, cooldown=0.0, budget_ms=800,
                                dry_run=True)

    def tearDown(self):
        _reset_dns_caches()
        _ASN_CACHE.clear()
        shutil.rmtree(self.d, ignore_errors=True)

    def test_guess_domain(self):
        self.assertEqual(_guess_domain("youtube_com_007"), "youtube.com")
        self.assertEqual(_guess_domain("discord_com"), "discord.com")
        self.assertEqual(_guess_domain("redirector.googlevideo.com"),
                         "redirector.googlevideo.com")
        self.assertIsNone(_guess_domain(None))
        self.assertIsNone(_guess_domain(""))

    def test_dns_resolvers_are_stable(self):
        rs = _dns_resolvers()
        self.assertIsInstance(rs, list)
        self.assertTrue(rs)
        custom_dns = os.environ.get("TSPU_INTEL_DNS", "1.1.1.1").strip()
        self.assertTrue(rs[0] in ("8.8.8.8", "1.1.1.1", "77.88.8.8", custom_dns))
        self.assertEqual(len(rs), len(set(rs)))

    def test_resolve_cache_short_circuits_network(self):
        _RESOLVE_CACHE["test.example.com"] = (time.time(), "1.2.3.4")
        ctx = {"remote_ip": None, "sni": "test.example.com",
               "strategy_name": "test_example_com_001", "bytes_delta": None}
        r = self.engine.run(ctx)
        self.assertEqual(r["meta"]["dst"], "1.2.3.4")
        self.assertEqual(r["meta"]["sni"], "test.example.com")

    def test_degraded_reset_between_runs(self):
        self.engine._degraded = ["isp_lookup_failed", "fake_payload_partial"]
        self.engine.on_cut_async({"cut_id": 1, "sni": "test.example.com",
                                  "remote_ip": "8.8.8.8",
                                  "event_kind": "classic",
                                  "reset_confirmed": True,
                                  "strategy_name": "test_com_001"})
        end = time.time() + 2.0
        while time.time() < end:
            if not self.engine._running and self.engine._last_result_ts is not None:
                break
            time.sleep(0.02)
        self.assertIsNotNone(self.engine._last_result)
        # stale-флаги сброшены; остался только актуальный — bytes_delta
        # отсутствовал в ctx (новая диагностика полноты входа)
        self.assertEqual(self.engine._last_result["meta"]["degraded"],
                         ["bytes_delta_absent"])

    def test_scan_destination_hop_icmp_evidence(self):
        sport = 45000
        inner_pkt = build_tcp_packet(sport, 443, 3, 0, 0x02, b"",
                                     "10.0.0.2", "10.0.0.5", 40)
        inner = parse_ip(inner_pkt)
        icmp_rec = {"proto": 1, "icmp_type": 11, "src": "10.0.0.1",
                    "dst": "10.0.0.5",
                    "inner": {"proto": 6, "dst": "10.0.0.5",
                              "payload": inner["payload"]}}
        sink = _FakeSniffer([icmp_rec])
        dst_hop, tmap = scan_destination_hop("10.0.0.5", "10.0.0.2", sport,
                                             sink, 2.0, max_ttl=30)
        self.assertIsNone(dst_hop)                 # no TCP reply from dst
        self.assertEqual(tmap.get(3), "icmp-ttl-exceed")

    def test_scan_destination_hop_synack_attrib_ttl(self):
        sport = 45001
        synack_rec = {"proto": 6, "src": "10.0.0.5", "dst": "10.0.0.2",
                      "sport": 443, "dport": sport, "seq": 100,
                      "ack": 4, "flags": 0x12}
        sink = _FakeSniffer([synack_rec])
        dst_hop, tmap = scan_destination_hop("10.0.0.5", "10.0.0.2", sport,
                                             sink, 2.0, max_ttl=30)
        self.assertEqual(dst_hop, 3)               # seq=3 (ttl=3) -> ack=4
        self.assertEqual(tmap.get(3), "syn-ack/rst-from-dst")

    def test_probe_mark_default(self):
        self.assertEqual(DEFAULT_PROBE_MARK, 0x40000000)
        self.assertEqual(self.engine.probe_mark, DEFAULT_PROBE_MARK)

    def test_probe_mark_override(self):
        eng = TspuIntel(path=os.path.join(self.d, "m.jsonl"), dry_run=True,
                        probe_mark=0x10000000)
        self.assertEqual(eng.probe_mark, 0x10000000)
        self.assertEqual(eng.status()["probe_mark"], 0x10000000)

    def test_probe_mark_parse(self):
        self.assertEqual(_parse_mark_value("0x40000000"), 0x40000000)
        self.assertEqual(_parse_mark_value(" 0x20000000 "), 0x20000000)
        self.assertEqual(_parse_mark_value("123456"), 123456)
        self.assertEqual(_parse_mark_value("garbage"), 0x40000000)
        self.assertEqual(_parse_mark_value(None), 0x40000000)
        self.assertEqual(_parse_mark_value("", default=7), 7)

    def test_apply_probe_mark_sets_sockopt(self):
        class _FakeSock:
            def __init__(self):
                self.calls = []
                self.fail = False
            def setsockopt(self, level, opt, val):
                if self.fail:
                    raise OSError("no cap")
                self.calls.append((level, opt, val))
        s = _FakeSock()
        self.assertTrue(_apply_probe_mark(s, DEFAULT_PROBE_MARK))
        self.assertEqual(s.calls,
                         [(socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36),
                           DEFAULT_PROBE_MARK)])
        self.assertFalse(_apply_probe_mark(s, 0))          # falsy mark: no-op
        self.assertEqual(len(s.calls), 1)
        s.fail = True
        self.assertFalse(_apply_probe_mark(s, DEFAULT_PROBE_MARK))  # degraded

    def test_ctx_intake_fields_and_bytes_absent(self):
        ctx = {"sni": "test.example.com", "remote_ip": "1.2.3.4",
               "strategy_name": "test_com_001", "strategy_score_before": None,
               "bytes_delta": None, "lifetime_sec": 12.5, "qnum": 301}
        r = self.engine.run(ctx)
        cf = r["meta"]["ctx_fields"]
        self.assertFalse(cf["bytes_delta_present"])
        self.assertIsNone(cf["strategy_score_before"])
        self.assertEqual(cf["strategy_name"], "test_com_001")
        self.assertEqual(cf["qnum"], 301)
        self.assertIn("bytes_delta_absent", self.engine._degraded)

    def test_ctx_intake_bytes_present(self):
        r = self.engine.run({"remote_ip": "1.2.3.4", "sni": "test.example.com",
                             "strategy_name": "test_com_001",
                             "strategy_score_before": 1.0, "bytes_delta": 42000})
        cf = r["meta"]["ctx_fields"]
        self.assertTrue(cf["bytes_delta_present"])
        self.assertNotIn("bytes_delta_absent", self.engine._degraded)

    def test_strategy_score_known_flag(self):
        r = self.engine.run({"remote_ip": "1.2.3.4", "sni": "test.example.com",
                             "strategy_name": "test_com_001",
                             "strategy_score_before": -1.5})
        self.assertTrue(r["strategy_context"]["strategy_score_known"])
        r2 = self.engine.run({"remote_ip": "1.2.3.4", "sni": "test.example.com",
                              "strategy_name": "test_com_002"})
        self.assertFalse(r2["strategy_context"]["strategy_score_known"])
        self.assertIsNone(r2["strategy_context"]["strategy_score_before"])

    def test_asn_fallback_marked_degraded(self):
        import tspu_intel as ti
        orig = ti.lookup_asn
        ti.lookup_asn = lambda *a, **k: {"isp_asn": "AS_LOCAL",
                                         "isp_name": "LocalProvider",
                                         "fallback": True,
                                         "fallback_reason": "cymru_txt_no_answer"}
        try:
            env = self.engine._environment({}, "8.8.8.8", _Budget(1.0), False)
        finally:
            ti.lookup_asn = orig
        self.assertEqual(env["isp_source"], "fallback_local")
        self.assertEqual(env["isp_asn"], "AS_LOCAL")
        self.assertIn("asn_unresolved_fallback", self.engine._degraded)

    def test_ttl_map_summary(self):
        tmap = {1: "no-dst-reply", 2: "no-dst-reply", 3: "icmp-ttl-exceed",
                5: "syn-ack/rst-from-dst", 6: "syn-ack/rst-from-dst"}
        s = _ttl_map_summary(tmap, 5)
        self.assertEqual(s["silent_hops"], 2)
        self.assertEqual(s["icmp_hops"], [3])
        self.assertEqual(s["first_dst_reply_ttl"], 5)
        self.assertEqual(s["exact_dst_hop"], 5)
        empty = _ttl_map_summary({}, None)
        self.assertEqual(empty["silent_hops"], 0)
        self.assertIsNone(empty["first_dst_reply_ttl"])
        self.assertIsNone(empty["exact_dst_hop"])

    def test_scan_destination_hop_batch_attribution(self):
        # ответили SYN-ACK'и на SYN с seq=23 и seq=24 (TTL 23/24): карта
        # должна пометить только 23 и 24, а 19-22 остаться no-dst-reply
        sport = 45002
        recs = [
            {"proto": 6, "src": "10.0.0.5", "dst": "10.0.0.2", "sport": 443,
             "dport": sport, "seq": 100, "ack": 24, "flags": 0x12},
            {"proto": 6, "src": "10.0.0.5", "dst": "10.0.0.2", "sport": 443,
             "dport": sport, "seq": 101, "ack": 25, "flags": 0x12},
        ]
        sink = _FakeSniffer(recs)
        dst_hop, tmap = scan_destination_hop("10.0.0.5", "10.0.0.2", sport,
                                             sink, 2.0, max_ttl=30)
        self.assertEqual(dst_hop, 23)
        self.assertEqual(tmap.get(23), "syn-ack/rst-from-dst")
        self.assertEqual(tmap.get(24), "syn-ack/rst-from-dst")
        self.assertEqual(tmap.get(19), "no-dst-reply")
        self.assertEqual(tmap.get(1), "no-dst-reply")

    def test_asn_cache_avoids_repeat_lookup(self):
        import tspu_intel as ti
        orig = ti.lookup_asn
        calls = []
        def _fake(ip, **kw):
            calls.append(ip)
            return {"isp_asn": "AS15169", "isp_name": "Google LLC"}
        ti.lookup_asn = _fake
        try:
            b = _Budget(1.0)
            env1 = self.engine._environment({}, "8.8.8.8", b, False)
            env2 = self.engine._environment({}, "8.8.8.8", b, False)
        finally:
            ti.lookup_asn = orig
        self.assertEqual(calls, ["8.8.8.8"])          # второй — из кэша
        self.assertEqual(env1["isp_asn"], "AS15169")
        self.assertEqual(env2["isp_asn"], "AS15169")
        self.assertNotIn("asn_unresolved_fallback", self.engine._degraded)

    def test_rst_fingerprint(self):
        rec = {"proto": 6, "ttl": 58, "window": 512, "flags": 0x14,
               "seq": 9, "ack": 3}
        fp = _rst_fingerprint([rec])
        self.assertEqual(fp["ttl"], 58)
        self.assertEqual(fp["window"], 512)
        self.assertEqual(fp["flags_str"], "RST+ACK")
        self.assertIsNone(_rst_fingerprint([]))

    def test_build_tcp_bad_checksum_and_urg(self):
        pkt = build_tcp_packet(12345, 443, 1, 1, 0x18, b"x", "10.0.0.1",
                               "10.0.0.2", 64, bad_checksum=True)
        ip = parse_ip(pkt)
        self.assertIsNotNone(ip)
        tcp = ip["payload"]
        saved = (tcp[16] << 8) | tcp[17]
        zero = bytearray(tcp); zero[16:18] = b"\x00\x00"
        self.assertNotEqual(ip_checksum(bytes(zero)), saved)
        pkt2 = build_tcp_packet(12345, 443, 1, 1, 0x38, b"x", "10.0.0.1",
                                "10.0.0.2", 64, urg_ptr=513, window=5)
        t2 = parse_tcp(parse_ip(pkt2)["payload"])
        self.assertEqual(t2["flags"] & TCP_URG, TCP_URG)
        self.assertEqual(t2["urg"], 513)
        self.assertEqual(t2["window"], 5)

    def test_session_per_flow_bytes(self):
        r = self.engine.run({"remote_ip": "1.2.3.4", "sni": "test.example.com",
                             "strategy_name": "test_com_009",
                             "conn_bytes_orig": 54321,
                             "conn_bytes_reply": 998877,
                             "conn_pkts_orig": 42})
        sp = r["session_profile"]
        self.assertEqual(sp["bytes_sent_before_cut"], 54321)
        self.assertEqual(sp["bytes_recv_before_cut"], 998877)
        self.assertEqual(sp["pkts_sent_before_cut"], 42)
        self.assertNotIn("bytes_sent_unavailable", self.engine._degraded)
        self.assertNotIn("bytes_delta_absent", self.engine._degraded)

    def test_meta_time_of_day(self):
        r = self.engine.run({"remote_ip": "1.2.3.4", "sni": "test.example.com",
                             "strategy_name": "test_com_010"})
        self.assertIn("hour_of_day_utc", r["meta"])
        self.assertIn("day_of_week_utc", r["meta"])

    def test_channel_quality(self):
        import tspu_intel as ti
        orig = ti._udp_dns_alive
        state = {"i": 0}
        def fake(server=None, timeout=0.8):
            i = state["i"]; state["i"] += 1
            return i != 2          # третий замер — потеря
        ti._udp_dns_alive = fake
        try:
            cq = ti._channel_quality(samples=3, timeout=0.25)
        finally:
            ti._udp_dns_alive = orig
        self.assertEqual(cq["samples"], 3)
        self.assertEqual(cq["dns_loss_rate"], 0.33)
        self.assertIsNotNone(cq["dns_rtt_min_ms"])
        self.assertIsNotNone(cq["dns_jitter_ms"])

    def test_l7_probe_details_active(self):
        import tspu_intel as ti
        orig = (ti._Sniffer, ti.TspuProber, ti.test_quic, ti._channel_quality)

        class _FakeSn:
            def set_log(self, *a):
                pass
            def open_or_dummy(self):
                return True
            def query(self, *a, **k):
                return []
            def close(self):
                pass

        class _FakePb:
            _FP = {"ttl": 58, "window": 512, "flags": 20,
                   "flags_str": "RST+ACK", "seq": 9, "ack": 3}
            def __init__(self, *a, **k):
                pass
            def test_split(self, pos):
                return {"connected": True, "bypass": False, "rst_received": True,
                        "serverhello": False, "confidence": 0.85,
                        "rst": dict(self._FP), "ch_rst_ms": 11.5,
                        "synack_rtt_ms": 8.2}
            def test_seqovl(self):
                return {"connected": True, "bypass": True, "rst_received": False,
                        "serverhello": True, "confidence": 0.9,
                        "rst": dict(self._FP), "ch_rst_ms": 11.5,
                        "synack_rtt_ms": 8.2}
            def test_disorder(self):
                return {"connected": True, "bypass": False, "rst_received": True,
                        "serverhello": False, "confidence": 0.85,
                        "rst": dict(self._FP), "ch_rst_ms": 11.5,
                        "synack_rtt_ms": 8.2}
            def test_fake_tls(self):
                return {"connected": True, "rst_received": True}
            def test_fake_random(self):
                return {"connected": True, "rst_received": True}
            def test_anomaly(self, kind):
                return {"kind": kind, "connected": True, "rst_received": False,
                        "ch_rst_ms": 12.5}

        ti._Sniffer, ti.TspuProber, ti.test_quic = _FakeSn, _FakePb, \
            lambda *a, **k: (True, True)
        ti._channel_quality = lambda *a, **k: {
            "dns_loss_rate": 0.0, "dns_rtt_min_ms": 9.5, "dns_rtt_avg_ms": 11.0,
            "dns_jitter_ms": 1.1, "samples": 3, "server": "1.1.1.1"}
        try:
            r = self.engine._l7({}, "8.8.8.8", _Budget(2.0), False)
        finally:
            ti._Sniffer, ti.TspuProber, ti.test_quic, ti._channel_quality = orig
        self.assertFalse(r["split_pos_2_bypass"])
        self.assertTrue(r["seqovl_bypass"])
        self.assertEqual(r["fake_payload_strictness"], "strict_both")
        d = r["probe_details"]["split_pos_2"]
        self.assertTrue(d["connected"])
        self.assertEqual(d["confidence"], 0.85)
        self.assertEqual(d["ch_rst_ms"], 11.5)
        self.assertEqual(d["synack_rtt_ms"], 8.2)
        # fake_tls-фейк не возвращает serverhello — детали заполняются None
        self.assertIsNone(r["probe_details"]["fake_tls"]["serverhello"])
        # контроль QUIC в фейке успешен — флага ненадёжности быть не должно
        self.assertNotIn("quic_control_failed", self.engine._degraded)
        # агрегаты: фингерпринт RST + RTT
        self.assertEqual(r["rst_fp_count"], 4)
        self.assertEqual(r["avg_ch_rst_ms"], 11.5)
        self.assertEqual(r["avg_synack_rtt_ms"], 8.2)
        self.assertEqual(r["rst_fingerprint"]["ttl"], 58)
        # TCP-аномалии и качество канала
        self.assertEqual(r["tcp_anomaly"]["kind"], "bad_checksum")
        self.assertEqual(r["channel_quality"]["dns_loss_rate"], 0.0)
        self.assertEqual(r["probe_tls_profile"], "tls12_client_sni_noech_noalpn")


if __name__ == "__main__":
    unittest.main(verbosity=2)