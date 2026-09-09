# Fix comment placement after conn patch in pool_manager.py
import re, sys
PATH = "panel/pool_manager.py"
with open(PATH, "r", encoding="utf-8") as f:
    src = f.read()
NL = chr(10)
ARROW = chr(0x2192)

old = "raw_nfq  = self._read_nfnetlink_queue()" + NL + "        conns    = self.get_conn_counts()"
new = "raw_nfq  = self._read_nfnetlink_queue()         # qnum " + ARROW + " pkts_total" + NL + "        conns    = self.get_conn_counts()"
n = src.count(old)
if n != 1:
    print("FAIL fix#0 matched %d" % n); sys.exit(1)
src = src.replace(old, new, 1)

pat = re.compile(r"\(connmark\)         # qnum . pkts_total")
ms = pat.findall(src)
if len(ms) != 1:
    print("FAIL fix#1 matched %d" % len(ms)); sys.exit(1)
src = pat.sub("(connmark)", src, count=1)

with open(PATH, "w", encoding="utf-8", newline="") as f:
    f.write(src.replace(NL, chr(13) + NL))
print("FIX_OK")
