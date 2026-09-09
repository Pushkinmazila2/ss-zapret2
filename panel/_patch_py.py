# One-shot patch: per-slot active connection counts (conntrack) in pool_manager.py
import sys

PATH = "panel/pool_manager.py"

def rd(p):
    with open(p, "r", encoding="utf-8") as f:
        return f.read()

def wr(p, s):
    with open(p, "w", encoding="utf-8", newline="") as f:
        f.write(s.replace(chr(10), chr(13) + chr(10)))

def die(path, i, n):
    print("FAIL %s rule#%d matched %d times" % (path, i, n))
    sys.exit(1)

MERGE = '''            # Queues with connections but no counters (iptables counters are
            # reset on fw reload) - the panel must still see their connections.
            for qnum, c in conns.items():
                if qnum not in result:
                    result[qnum] = {
                        "qnum":             qnum,
                        "conns":            c,
                        "pkts":             0,
                        "bytes":            0,
                        "pkts_delta":       0,
                        "bytes_delta":      0,
                        "kbps":             0.0,
                        "pps":              0.0,
                        "active":           False,
                        "share":            0.0,
                        "bytes_estimated":  False,
                        "source":           "conntrack",
                    }
'''

METHODS = '''    # -- per-slot active connection counts (connmark -> qnum) -------------

    def get_conn_counts(self):
        """
        Number of active connections pinned to each pool qnum via connmark
        (low 16 bits of the mark = queue number).

        Source: procfs nf_conntrack (path: self._nf_conntrack_path, env
        NF_CONNTRACK_PROC); binary `conntrack` fallback when procfs is
        unavailable. Counted: tcp in ESTABLISHED state and any udp entries
        (udp has no states - an entry lives while the flow is active).

        Returns {qnum: conns}; {} when conntrack is unavailable.
        """
        lines = self._read_conntrack_lines()
        if not lines:
            return {}
        counts = {}
        for line in lines:
            qnum = self._conntrack_line_qnum(line)
            if qnum is not None:
                counts[qnum] = counts.get(qnum, 0) + 1
        return counts

    def _read_conntrack_lines(self, timeout=5):
        """
        List of conntrack lines, or None when no source is available.
        procfs may be disabled in the kernel (CONFIG_NF_CONNTRACK_PROCFS=n)
        - fall back to the conntrack binary (conntrack-tools).
        """
        try:
            with open(self._nf_conntrack_path) as f:
                return f.readlines()
        except (IOError, OSError):
            pass
        try:
            r = subprocess.run(["conntrack", "-L"],
                               capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError):
            return None
        if r.returncode != 0:
            return None
        return (r.stdout or "").splitlines()

    @staticmethod
    def _conntrack_line_qnum(line):
        """
        qnum from a conntrack line when the flow is pool-marked and active:
        tcp - only ESTABLISHED, udp - any entry.
        The mark keeps qnum in the low 16 bits (CONNMARK --ctmask 0xFFFF).
        """
        parts = line.split()
        if len(parts) < 4 or parts[0] not in ("tcp", "udp"):
            return None
        if parts[0] == "tcp" and parts[3] != "ESTABLISHED":
            return None
        mark = None
        for tok in parts:
            if tok.startswith("mark="):
                mark = tok[5:]
                break
        if not mark:
            return None
        m = PoolManager._parse_mark(mark)
        if not m:
            return None
        qnum = m & 0xFFFF
        if QNUM_BASE <= qnum < QNUM_BASE + 100:
            return qnum
        return None

'''

src = rd(PATH)
i = 0

# 1) fetch connection counts in get_traffic_stats
old = "        raw_nfq  = self._read_nfnetlink_queue()"
new = old + "\n        conns    = self.get_conn_counts()               # active conns per qnum (connmark)"
n = src.count(old)
if n != 1: die(PATH, i, n)
src = src.replace(old, new, 1); i += 1

# 2) document the new field in the docstring
old = '''        """
        raw_ipt  = self._read_zapret_pool_counters()'''
new = '''        Additionally returns `conns`: number of established connections
        pinned to the queue via connmark. Unlike pkts_delta, a connection
        stays visible while it is alive even when no packets flow at the
        moment (idle stream, keep-alive).
        """
        raw_ipt  = self._read_zapret_pool_counters()'''
n = src.count(old)
if n != 1: die(PATH, i, n)
src = src.replace(old, new, 1); i += 1

# 3) add conns field to the per-qnum record
old = '''                    "qnum":             qnum,'''
new = '''                    "qnum":             qnum,
                    "conns":            conns.get(qnum, 0),'''
n = src.count(old)
if n != 1: die(PATH, i, n)
src = src.replace(old, new, 1); i += 1

# 4) records for queues with connections but no counters
old = '''            self._prev_counters     = raw
            self._prev_counter_time = now
        return result'''
new = MERGE + old
n = src.count(old)
if n != 1: die(PATH, i, n)
src = src.replace(old, new, 1); i += 1

# 5) new methods
old = '''        return result

    def start_slot(self, index, strategy_name, nfqws_opt):'''
new = '''        return result

''' + METHODS + '''    def start_slot(self, index, strategy_name, nfqws_opt):'''
n = src.count(old)
if n != 1: die(PATH, i, n)
src = src.replace(old, new, 1); i += 1

wr(PATH, src)
print("OK %s (%d rules)" % (PATH, i))
