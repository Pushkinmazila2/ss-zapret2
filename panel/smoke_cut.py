# -*- coding: utf-8 -*-
# принудительная UTF-8 кодировка для stdout/stderr — в Windows иначе падает на →
import io
import os
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

os.environ["PYTHONIOENCODING"] = "utf-8"

os.environ["CUT_LOG_PATH"] = os.path.join(tempfile.mkdtemp(), "cuts.jsonl")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import server as S


class FakePool:
    def get_status(self):
        return [{"index": 1, "qnum": 301, "strategy": "disorder",
                 "healthy": True, "alive": True, "fw_excluded": False}]

    def get_traffic_stats(self):
        return {301: {"qnum": 301, "pkts_delta": 128, "bytes_delta": 410000,
                      "kbps": 500.0, "share": 66.0, "active": True,
                      "source": "iptables"}}

    def slot_for_conn(self, conn):
        if getattr(FakePool, "no_conntrack", False):
            return None, "nf_conntrack procfs unavailable"
        return {"index": 1, "qnum": 301, "strategy": "disorder",
                "nfqws_pid": 1234, "nfqws_opt": "--filter-tcp=443 --new"}, None

    def slot_log_tail(self, index, limit=40):
        return ["[NFQWS2][SLOT-1][QNUM-301] debug line 1",
                "[NFQWS2][SLOT-1][QNUM-301] debug line 2"]

    def __getattr__(self, name):
        # заглушки для остальных методов пула (remove_slots_from_fw, start_shadow…),
        # чтобы фоновая ротация в smoke-тесте завершалась тихо
        def _noop(*a, **k):
            return None
        _noop.__name__ = name
        return _noop


sw = S.PoolSwitcher(FakePool())
sw.enabled = True
sw.cut_rotate_enabled = True
sw._cut_last_ts = None

# засоряем монитор хвостом ss-лога и логом панели
with S.reset_monitor._lock:
    S.reset_monitor._ss_tail.append("2026-09-04 22:05:12 INFO: close a connection to remote, 21 opened")
sw._log_event("info", "Слот 1 → «disorder»")

event = {
    "kind": "classic",
    "lifetime_sec": 42.5,
    "conn": (52134, "8EFA4A78", 443),
    "rst_deaths_window": 3,
    "fin_deaths_window": 8,
    "reset_confirmed": True,
}
sw.on_connection_cut(event)

entries = S.cut_logger.list(10)
print("ENTRIES:", len(entries))
e = entries[0]
print("kind:", e.get("event_kind"), "| lifetime:", e.get("lifetime_sec"))
print("conn:", e.get("connection"))
print("slot:", e.get("slot"))
print("traffic pkts_delta:", e.get("traffic", {}).get("pkts_delta"))
print("ss_tail:", len(e.get("traces", {}).get("ss_server_tail", [])))
print("nfqws_tail:", len(e.get("traces", {}).get("nfqws2_log_tail", [])))
print("panel_tail:", len(e.get("traces", {}).get("panel_log_tail", [])))
assert e["event_kind"] == "classic"
assert e["connection"]["remote_ip"] == "142.250.74.120"  # 8EFA4A78 LE → 142.250.74.120
assert e["slot"]["strategy"] == "disorder"
assert e["traffic"]["pkts_delta"] == 128
assert e["traces"]["nfqws2_log_tail"]  # непустой
print("SMOKE_OK")

# ── сценарий 2: conntrack недоступен → fallback на самый активный слот ──
FakePool.no_conntrack = True
sw2 = S.PoolSwitcher(FakePool())
sw2.enabled = True
sw2.cut_rotate_enabled = True
sw2._cut_last_ts = None
sw2.on_connection_cut(event)

e2 = S.cut_logger.list(1)[0]
print("S2 slot_resolved:", e2.get("slot_resolved"),
      "| reason:", e2.get("slot_resolve_reason"))
print("S2 slot:", e2.get("slot"))
print("S2 nfqws_tail len:", len(e2["traces"]["nfqws2_log_tail"]))
print("S2 all_slots:", sorted(e2["traces"]["nfqws2_all_slots"].keys()))
assert e2["slot_resolved"] is False
assert e2["slot"]["guessed"] is True
assert e2["slot"]["index"] == 1
assert e2["traces"]["nfqws2_log_tail"]      # fallback-хвост заполнен
assert e2["traces"]["nfqws2_all_slots"]     # хвосты всех живых слотов
print("SMOKE2_OK")