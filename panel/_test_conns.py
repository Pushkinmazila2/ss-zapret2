# Functional test: get_conn_counts + conns merge in get_traffic_stats
import os, sys, tempfile

LINES = [
    "tcp      6 431997 ESTABLISHED src=172.19.0.2 dst=142.250.74.120 sport=33382 dport=443 src=142.250.74.120 dst=172.19.0.2 sport=443 dport=33382 mark=301 secctx=none use=1",
    "tcp      6 119 TIME_WAIT src=172.19.0.2 dst=1.2.3.4 sport=40000 dport=443 src=1.2.3.4 dst=172.19.0.2 sport=443 dport=40000 mark=302 use=1",
    "udp      17 29 src=172.19.0.2 dst=5.6.7.8 sport=50000 dport=443 src=5.6.7.8 dst=172.19.0.2 sport=443 dport=50000 mark=0x12d [ASSURED] use=1",
    "tcp      6 431997 ESTABLISHED src=172.19.0.2 dst=9.9.9.9 sport=41000 dport=443 src=9.9.9.9 dst=172.19.0.2 sport=443 dport=41000 mark=0 use=1",
    "tcp      6 431997 ESTABLISHED src=172.19.0.2 dst=9.9.9.9 sport=41001 dport=443 src=9.9.9.9 dst=172.19.0.2 sport=443 dport=41001 mark=999 use=1",
    "tcp      6 431997 ESTABLISHED src=172.19.0.2 dst=9.9.9.9 sport=41002 dport=443 src=9.9.9.9 dst=172.19.0.2 sport=443 dport=41002 mark=0x4000012f use=1",
    "udp      17 130 src=172.19.0.2 dst=6.6.6.6 sport=51000 dport=443 src=6.6.6.6 dst=172.19.0.2 sport=443 dport=51000 mark=305 use=1",
    "icmp     1 29 src=172.19.0.2 dst=7.7.7.7 mark=301",
]

def main():
    sys.path.insert(0, "panel")
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".ct", delete=False)
    tmp.write(chr(10).join(LINES) + chr(10))
    tmp.close()
    os.environ["NF_CONNTRACK_PROC"] = tmp.name
    import pool_manager
    pool_manager.POOL_RUN_DIR = os.path.join(tempfile.gettempdir(), "zapret-pool-test")
    pm = pool_manager.PoolManager()

    q = pm._conntrack_line_qnum
    assert q(LINES[0]) == 301, q(LINES[0])
    assert q(LINES[1]) is None, q(LINES[1])
    assert q(LINES[2]) == 301, q(LINES[2])
    assert q(LINES[3]) is None, q(LINES[3])
    assert q(LINES[4]) is None, q(LINES[4])
    assert q(LINES[5]) == 303, q(LINES[5])
    assert q(LINES[6]) == 305, q(LINES[6])
    assert q(LINES[7]) is None, q(LINES[7])
    assert q("garbage line") is None

    counts = pm.get_conn_counts()
    assert counts == {301: 2, 303: 1, 305: 1}, counts

    stats = pm.get_traffic_stats()
    assert set(stats.keys()) == {301, 303, 305}, stats
    for qn, rec in stats.items():
        assert rec["conns"] == counts[qn], (qn, rec)
        assert rec["source"] == "conntrack", (qn, rec)
        assert rec["active"] is False and rec["pkts_delta"] == 0, (qn, rec)

    os.environ["NF_CONNTRACK_PROC"] = os.path.join(tmp.name, "nope")
    pm2 = pool_manager.PoolManager()
    assert pm2.get_conn_counts() == {}
    print("TEST_OK conn counts:", counts)
    os.unlink(tmp.name)

if __name__ == "__main__":
    main()
