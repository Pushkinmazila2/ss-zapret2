#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TspuIntel - asynchronous TSPU (РЭБ) reconnaissance module for logs.

Triggered strictly at the moment a session cut is detected by the detector
(conn_tracker -> PoolSwitcher.on_connection_cut -> TspuIntel.on_cut_async).
Within a tight budget (<= ~2s) it collects an enriched feature vector that is
appended to two sinks:

  * an independent JSONL (IntelLog)
  * a companion record in the cut journal (cut_logger, kind='tspu_intel')

Implemented with the Python stdlib only (socket.SOCK_RAW, struct, socket).
No host utilities (traceroute/iptables) are spawned and no 3rd party packages
(scapy) are required (they are absent from the image). On platforms without
CAP_NET_RAW / on non-Linux runners it transparently falls into a deterministic
dry-run simulator so CI and unit tests stay green.

Probe sockets carry SO_MARK = DEFAULT_PROBE_MARK (0x40000000, mirroring
DESYNC_MARK from `config`): the mangle-POSTROUTING anti-loop rule
('-m mark ! --mark $DESYNC_MARK/$DESYNC_MARK') then lets probe packets bypass
the local zapret NFQUEUE, so the dataset measures the raw TSPU path instead of
the locally desynced traffic. The mark is a kernel-internal sk_buff field and
never reaches the wire; if SO_MARK is unavailable probes degrade to unmarked
sending.
"""
import datetime
import json
import os
import platform
import random
import socket
import struct
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor

# - constants -
DATASET_VERSION = "1.1"
DEFAULT_BUDGET_MS = 1800
HARD_BUDGET_MS    = 2000
DEFAULT_TTL_MAX   = 30
DEFAULT_COOLDOWN  = 30
DEFAULT_SNI       = "youtube.com"
DEFAULT_TARGET_IP = "142.250.74.110"  # well-known anycast youtube ip
# SO_MARK for probe raw sockets. Mirrors DESYNC_MARK from `config` so the
# firewall anti-loop rule (mangle POSTROUTING '-m mark ! --mark $DESYNC_MARK')
# skips probe packets: they bypass the local zapret NFQUEUE and reach TSPU raw.
DEFAULT_PROBE_MARK = 0x40000000

TCP_FIN = 0x01; TCP_SYN = 0x02; TCP_RST = 0x04; TCP_PSH = 0x08; TCP_ACK = 0x10
TCP_URG = 0x20; TCP_ECE = 0x40; TCP_CWR = 0x80

_MOBILE_HINTS = ("mobile","gsm","lte","5g","4g","cellular","mts","mobil",
                 "megafon","beeline","vimpel","tele2","yota","nss","tkom","t2")
_DC_HINTS     = ("datacenter","data center","hosting","cloud","dedicated",
                 "server","colo","colocation","vps","amazon","aws","google",
                 "microsoft","azure","hetzner","ovh","digitalocean","selectel",
                 "timeweb","linode","cdn","akamai","cloudflare")



def _utcnow_iso():
    return _iso()


def _iso(ts=None):
    ts = time.time() if ts is None else ts
    try:
        return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


# - packet level primitives (pure stdlib) -

def ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data = data + b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    s = (s & 0xFFFF) + (s >> 16)
    s += (s >> 16)
    return (~s) & 0xFFFF


def tcp_checksum(src: bytes, dst: bytes, tcp_seg: bytes, payload: bytes = b"") -> int:
    total = 0
    total += int.from_bytes(src, "big") + int.from_bytes(dst, "big")
    total += 6 + (len(tcp_seg) + len(payload))
    seg = tcp_seg + payload
    if len(seg) % 2:
        seg = seg + b"\x00"
    for i in range(0, len(seg), 2):
        total += (seg[i] << 8) | seg[i + 1]
    total = (total & 0xFFFF) + (total >> 16)
    total += (total >> 16)
    return (~total) & 0xFFFF


def build_ip_header(src: str, dst: str, proto: int, payload_len: int,
                    ttl: int, ident: int = 0, df: bool = False,
                    tos: int = 0) -> bytes:
    srcb = ip4_to_bytes(src); dstb = ip4_to_bytes(dst)
    total_len = 20 + payload_len
    ihl_ver = (4 << 4) | 5
    flagsfrag = 0x4000 if df else 0x0000
    hdr = struct.pack("!BBHHHBBH4s4s", ihl_ver, tos, total_len, ident & 0xFFFF,
                      flagsfrag, ttl, proto, 0, srcb, dstb)
    chk = ip_checksum(hdr)
    hdr = hdr[:10] + struct.pack("!H", chk) + hdr[12:]
    return hdr


def build_tcp_packet(sport: int, dport: int, seq: int, ack: int, flags: int,
                     payload: bytes = b"", src: str = "0.0.0.0",
                     dst: str = "0.0.0.0", ttl: int = 64, window: int = 65535,
                     ident: int = 0, df: bool = True) -> bytes:
    doff = 5
    off = (doff << 4) | (0 & 0xF)
    tcp_hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, off, flags,
                          window, 0, 0)
    chk = tcp_checksum(ip4_to_bytes(src), ip4_to_bytes(dst), tcp_hdr, payload)
    tcp_hdr = tcp_hdr[:16] + struct.pack("!H", chk) + tcp_hdr[18:]
    return build_ip_header(src, dst, socket.IPPROTO_TCP, len(tcp_hdr) + len(payload),
                           ttl, ident=ident, df=df) + tcp_hdr + payload


def build_udp_packet(sport: int, dport: int, payload: bytes, src: str, dst: str,
                     ttl: int = 64, ident: int = 0) -> bytes:
    udp_hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    ip = build_ip_header(src, dst, socket.IPPROTO_UDP, len(udp_hdr) + len(payload),
                         ttl, ident=ident, df=False)
    chk = tcp_checksum(ip4_to_bytes(src), ip4_to_bytes(dst), udp_hdr, payload)
    udp_hdr = udp_hdr[:6] + struct.pack("!H", chk) + udp_hdr[8:]
    return ip + udp_hdr + payload


def ip4_to_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)


def ip4_from_bytes(b: bytes) -> str:
    return socket.inet_ntoa(b)


def parse_ip(buf: bytes):
    if len(buf) < 24 or (buf[0] >> 4) != 4:
        return None
    ihl = (buf[0] & 0x0F) * 4
    if len(buf) < ihl:
        return None
    proto = buf[9]
    ttl = buf[5]
    ident = int.from_bytes(buf[4:6], "big")
    src = ip4_from_bytes(buf[12:16]); dst = ip4_from_bytes(buf[16:20])
    return {"ihl": ihl, "proto": proto, "ttl": ttl, "id": ident,
            "src": src, "dst": dst, "payload": buf[ihl:]}


def parse_tcp(seg: bytes):
    if len(seg) < 20:
        return None
    sport, dport, seq, ack, off_flags, window, chk, urg = struct.unpack("!HHIIHHHH", seg[:20])
    doff = (off_flags >> 12) & 0xF
    fl = off_flags & 0xFF
    payload = seg[doff * 4:] if len(seg) > doff * 4 else b""
    return {"sport": sport, "dport": dport, "seq": seq, "ack": ack,
            "flags": fl, "window": window, "payload": payload}


def parse_udp(seg: bytes):
    if len(seg) < 8:
        return None
    sp, dp, ln, chk = struct.unpack("!HHHH", seg[:8])
    return {"sport": sp, "dport": dp, "length": ln,
            "payload": seg[8:ln] if ln <= len(seg) else seg[8:]}


def parse_icmp(buf: bytes):
    if len(buf) < 8:
        return None
    return {"type": buf[0], "code": buf[1], "rest": buf[2:8], "payload": buf[8:]}# - tls / quic builders -

def _sni_extension(hostname: str) -> bytes:
    name = hostname.encode("ascii", "ignore")[:253]
    entry = b"\x00" + struct.pack("!H", len(name)) + name
    server_name_list = struct.pack("!H", len(entry)) + entry
    return struct.pack("!HH", 0x0000, len(server_name_list)) + server_name_list


def build_tls_client_hello(sni: str = DEFAULT_SNI, bad_tls: bool = False,
                           random_bytes: bytes = None) -> bytes:
    """Minimal TLS 1.2 ClientHello record with a forbidden SNI (youtube.com)."""
    if random_bytes is None:
        random_bytes = bytes(random.getrandbits(8) for _ in range(32))
    ch_version = b"\x03\x03"
    session_id = b"\x00"
    cipher_suites = b"\x00\x2b" + b"\x13\x01\x13\x02\x13\x03\x00\x35\x00\x2c\x00\x0a\x00\xff"
    compression = b"\x01\x00"
    extensions = _sni_extension(sni)
    body = ch_version + random_bytes + session_id + cipher_suites + compression + extensions
    hs = b"\x01" + _uint24(len(body)) + body
    rec_len = len(hs) + 1 if bad_tls else len(hs)
    rec_len = len(hs) if not bad_tls else (len(hs) + 5)
    return b"\x16\x03\x01" + struct.pack("!H", rec_len) + hs


def split_payload(record: bytes, pos: int):
    """Split a TLS record payload into [0:pos] and [pos:] for fragment tests."""
    if pos <= 0:
        return [record]
    if pos >= len(record):
        return [record]
    return [record[:pos], record[pos:]]


def _uint24(v: int) -> bytes:
    return struct.pack("!I", v)[1:]


def tls_is_serverhello(payload: bytes) -> bool:
    """True if a captured TLS record is a ServerHello (content=handshake, type=2)."""
    if len(payload) < 6 or payload[0] != 0x16:
        return False
    body = payload[5:]
    return bool(body) and body[0] == 0x02


def build_quic_initial(sni: str = DEFAULT_SNI, dst_id_len: int = 8) -> bytes:
    """Best-effort QUIC v1 Initial carrying a TLS ClientHello in a CRYPTO frame.
    No header protection / packet number protection (ТСПУ parsers usually skip
    it anyway) -> sufficient to trigger a DPI reaction."""
    ch = build_tls_client_hello(sni)
    dcid = bytes(random.getrandbits(8) for _ in range(dst_id_len))
    scid = bytes(random.getrandbits(8) for _ in range(8))
    token = b"\x00"
    crypto = b"\x06" + b"\x00" + _varint(len(ch)) + ch  # CRYPTO frame, offset 0
    pn = b"\x00"
    length = _varint(len(pn) + len(crypto))
    hdr = (bytes([0xC0]) + struct.pack("!I", 1) + bytes([len(dcid)]) + dcid
           + bytes([len(scid)]) + scid + token + length + pn)
    return hdr + crypto


def _varint(v: int) -> bytes:
    if v < 64:
        return bytes([v])
    if v < 16384:
        return struct.pack("!H", 0x4000 | v)
    if v < 1048576:
        return struct.pack("!I", 0x80000000 | v)
    return struct.pack("!Q", 0xC000000000000000 | v)


# - dns / asn (stdlib only) -

def _dns_encode_name(name: str) -> bytes:
    out = b""
    for part in name.split("."):
        part = part.encode("ascii", "ignore")
        out += bytes([len(part)]) + part
    return out + b"\x00"


def _parse_name(data: bytes, off: int):
    labels = []
    jumped = False
    orig = off
    for _ in range(50):
        if off >= len(data):
            break
        b0 = data[off]
        if b0 & 0xC0 == 0xC0:
            ptr = ((b0 & 0x3F) << 8) | data[off + 1]
            if not jumped:
                orig = off + 2
            off = ptr
            jumped = True
            continue
        off += 1
        if b0 == 0:
            break
        if off + b0 > len(data):
            break
        labels.append(data[off:off + b0].decode("ascii", "ignore"))
        off += b0
    return ".".join(labels), (orig if jumped else off)


def dns_txt_query(name: str, server: str = None, timeout: float = 1.5):
    if server is None:
        server = os.environ.get("TSPU_INTEL_DNS", "1.1.1.1").strip()
        
    msg = _dns_encode_name(name)
    header = struct.pack("!HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
    msg = header + msg + struct.pack("!HH", 16, 1)  # qtype TXT, class IN
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # DNS-сокет тоже маркируем (SCANNER_FWMARK, дефолт DESYNC_MARK), чтобы
    # исходящие DNS-пробы не попадали в NFQUEUE-правила zapret.
    try:
        _apply_probe_mark(s, _parse_mark_value(
            os.environ.get("SCANNER_FWMARK", "0x40000000")))
    except Exception:
        pass
    s.settimeout(timeout)
    try:
        s.sendto(msg, (server, 53))
        data, _ = s.recvfrom(4096)
    finally:
        try:
            s.close()
        except Exception:
            pass
    return _parse_txt_answers(data)


def _parse_txt_answers(data: bytes):
    if len(data) < 12:
        return []
    ancount = struct.unpack("!H", data[6:8])[0]
    off = 12
    name, off = _parse_name(data, off)
    # question: name + qtype(2)+qclass(2)
    off += 4
    out = []
    for _ in range(ancount):
        if off + 12 > len(data):
            break
        name2, off2 = _parse_name(data, off)
        atype, aclass, ttl = struct.unpack("!HHI", data[off2:off2 + 8])
        rdlen = struct.unpack("!H", data[off2 + 8:off2 + 10])[0]
        rdata = data[off2 + 10:off2 + 10 + rdlen]
        off = off2 + 10 + rdlen
        if atype != 16:
            continue
        frag = []
        i = 0
        while i < len(rdata):
            ln = rdata[i]; i += 1
            frag.append(rdata[i:i + ln].decode("utf-8", "ignore")); i += ln
        out.append("".join(frag))
    return out


def lookup_asn(ip: str, server: str = None, timeout: float = 1.5):
    if server is None:
        server = os.environ.get("TSPU_INTEL_DNS", "1.1.1.1").strip()

    octets = ip.split(".")
    if len(octets) != 4:
        return None
    name = "origin." + ".".join(reversed(octets)) + ".asn.cymru.com"
    try:
        ans = dns_txt_query(name, server, timeout=timeout)
    except Exception:
        ans = []
    if not ans:
        return {"isp_asn": "AS_LOCAL", "isp_name": "LocalProvider",
                "fallback": True, "fallback_reason": "cymru_txt_no_answer"}
    line = "".join(ans)
    parts = [p.strip() for p in line.split("|")]
    as_raw = None; isp_name = "unknown"
    if len(parts) >= 2 and parts[0].upper() == "AS":
        as_raw = parts[1].strip()
        isp_name = parts[5].strip() if len(parts) >= 6 else (parts[-1].strip() or "unknown")
    elif len(parts) >= 2:
        as_raw = parts[1].strip(); isp_name = parts[-1].strip() or "unknown"
    else:
        toks = line.split()
        if len(toks) >= 2:
            as_raw = toks[1]; isp_name = " ".join(toks[2:]) or "unknown"
    if not as_raw:
        return {"isp_asn": "AS_LOCAL", "isp_name": "LocalProvider",
                "fallback": True, "fallback_reason": "cymru_txt_bad_asn"}
    digits = "".join(ch for ch in as_raw if ch.isdigit())
    isp_asn = ("AS" + digits) if digits else ("AS" + as_raw)
    return {"isp_asn": isp_asn, "isp_name": isp_name}


def _is_private_ip(ip: str) -> bool:
    try:
        import ipaddress
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_reserved
    except Exception:
        return False


def classify_connection_type(ip: str, isp_name: str) -> str:
    if _is_private_ip(ip):
        return "unknown"
    low = (isp_name or "").lower()
    if any(h in low for h in _MOBILE_HINTS):
        return "mobile"
    if any(h in low for h in _DC_HINTS):
        return "datacenter"
    return "broadband"


def classify_target_host(strategy_name: str, sni: str) -> str:
    low = ((strategy_name or "") + " " + (sni or "")).lower()
    if "youtube" in low or "googlevideo" in low:
        return "youtube_video"
    if "discord" in low:
        return "discord_voice"
    if "netflix" in low:
        return "netflix_stream"
    if "twitch" in low:
        return "twitch_stream"
    return "general_https"


# - resolve cache + resolvers (dataset probes run under a tight budget) -

_RESOLVE_TTL = 600.0  # seconds a cached A record stays hot
_RESOLVE_CACHE = {}   # name -> (wall_ts, ipv4)


def _dns_resolvers():
    """Stable, de-duplicated resolver list; TSPU_INTEL_DNS goes first."""
    out = []
    for r in ((os.environ.get("TSPU_INTEL_DNS") or "").strip(),
              "1.1.1.1", "8.8.8.8", "77.88.8.8"):
        if r and r not in out:
            out.append(r)
    return out


def _reset_dns_caches():
    _RESOLVE_CACHE.clear()


def _guess_domain(strategy_name):
    """Best-effort domain recovery from a strategy name ('youtube_com_007'
    -> 'youtube.com'); dotted names pass through, junk yields None."""
    if not strategy_name:
        return None
    s = str(strategy_name).strip().lower()
    if not s:
        return None
    if "." in s:
        return s
    parts = [p for p in s.split("_") if p]
    tlds = ("com", "net", "org", "ru", "io", "gov", "edu", "info", "biz", "tv")
    for i in range(1, len(parts)):
        if parts[i] in tlds:
            return parts[i - 1] + "." + parts[i]
    if len(parts) >= 2:
        return parts[0] + "." + parts[1]
    return None


def _dns_parse_a_reply(data, tid):
    """Extract the first A record from a UDP DNS reply."""
    try:
        if len(data) < 12:
            return None
        rid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
        if rid != tid or not (flags & 0x8000) or an < 1:
            return None
        off = 12
        for _ in range(qd):
            _, off = _parse_name(data, off)
            off += 4
        for _ in range(an):
            _, off = _parse_name(data, off)
            if off + 10 > len(data):
                return None
            rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10
            if rtype == 1 and rdlen == 4 and off + 4 <= len(data):
                return "%d.%d.%d.%d" % (data[off], data[off + 1],
                                        data[off + 2], data[off + 3])
            off += rdlen
    except Exception:
        return None
    return None


def _dns_resolve_a(name, timeout=0.35):
    """Minimal stdlib UDP DNS A lookup across _dns_resolvers()."""
    qname = _dns_encode_name(name)
    if not qname:
        return None
    tid = random.randint(1, 0xFFFF)
    query = (struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + qname
             + struct.pack("!HH", 1, 1))  # type A, class IN
    for server in _dns_resolvers():
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(query, (server, 53))
            data, _ = s.recvfrom(4096)
            ip = _dns_parse_a_reply(data, tid)
            if ip:
                return ip
        except OSError:
            continue
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
    return None


def local_ip_for(dst: str):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.3)
        s.connect((dst, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None
import select as _select


def _raw_enabled() -> bool:
    """True only on Linux with working SOCK_RAW (container runs as root)."""
    if platform.system() != "Linux":
        return False
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.close()
        return True
    except OSError:
        if s:
            try:
                s.close()
            except Exception:
                pass
        return False


def _apply_probe_mark(sock, mark, log_fn=None) -> bool:
    """Best-effort SO_MARK so raw probe packets bypass the local zapret
    NFQUEUE capture rules (mangle POSTROUTING). Requires CAP_NET_RAW /
    CAP_NET_ADMIN (the container runs as root); on failure probes degrade to
    unmarked sending. The mark is a kernel-internal sk_buff field and never
    touches the wire."""
    if not mark:
        return False
    try:
        so_mark = getattr(socket, "SO_MARK", 36)  # 36 = SO_MARK on old headers
        sock.setsockopt(socket.SOL_SOCKET, so_mark, int(mark))
        return True
    except OSError as e:
        if log_fn:
            try:
                log_fn("warn", "SO_MARK(%s) unavailable: %s" % (mark, e))
            except Exception:
                pass
        return False


def _parse_mark_value(raw, default=None) -> int:
    """Parse an iptables-style mark value ('0x40000000', '40000000', int)."""
    if default is None:
        default = DEFAULT_PROBE_MARK
    if raw is None:
        return int(default)
    s = str(raw).strip()
    if not s:
        return int(default)
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s, 0)
    except (TypeError, ValueError):
        return int(default)


class _Sniffer:
    """Single multi-proto raw sniffer shared by all probes.

    Raw sockets give back inbound copies of every IP packet; we normalise them
    into lightweight dicts and let matchers poll a time-ordered ring buffer.
    """

    def __init__(self):
        self._ring = deque(maxlen=8192)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._th = None
        self._socks = []      # (proto, sock)
        self._running = False
        self._log = lambda lvl, msg: None  # replaced by set_log(); safe default for open()

    def open(self) -> bool:
        self._socks = []
        for proto in (socket.IPPROTO_TCP, socket.IPPROTO_ICMP, socket.IPPROTO_UDP):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
                s.settimeout(0.2)
                self._socks.append((proto, s))
            except OSError:
                pass
        if not self._socks:
            return False
        self._log("info", "sniffer opened on %d proto(s)" % len(self._socks))
        return True

    def open_or_dummy(self):
        if not self.open():
            return False
        self._stop.clear()
        self._th = threading.Thread(target=self._loop, daemon=True)
        self._th.start()
        self._running = True
        return True

    def set_log(self, log_fn):
        self._log = log_fn or (lambda lvl, msg: None)

    def close(self):
        self._stop.set()
        for _, s in self._socks:
            try:
                s.close()
            except Exception:
                pass
        self._socks = []
        self._running = False

    def _loop(self):
        fds = {s.fileno(): (proto, s) for proto, s in self._socks}
        socks = [s for _, s in self._socks]
        while not self._stop.is_set():
            try:
                r, _, _ = _select.select(socks, [], [], 0.2)
            except Exception:
                break
            for s in r:
                try:
                    buf, _ = s.recvfrom(65536)
                except Exception:
                    continue
                self._push(buf)
        self._log("info","sniffer stopped")

    def _push(self, buf):
        ip = parse_ip(buf)
        if not ip:
            return
        rec = {"t": time.monotonic(), "proto": ip["proto"], "ttl": ip["ttl"],
               "src": ip["src"], "dst": ip["dst"],
               "dport": 0, "sport": 0, "seq": 0, "ack": 0, "flags": 0,
               "tcp_payload": b"", "udp_payload": b"", "icmp_type": 0}
        if ip["proto"] == 6:
            t = parse_tcp(ip["payload"])
            if t:
                rec.update(sport=t["seq"] and t["sport"] or 0, dport=t["dport"],
                           seq=t["seq"], ack=t["ack"], flags=t["flags"],
                           tcp_payload=t["payload"])
            # sport/ack overwrite fixed above:
            if t:
                rec["sport"] = t["sport"]; rec["dport"] = t["dport"]
                rec["seq"] = t["seq"]; rec["ack"] = t["ack"]; rec["flags"] = t["flags"]
                rec["tcp_payload"] = t["payload"]
        elif ip["proto"] == 17:
            u = parse_udp(ip["payload"])
            if u:
                rec["sport"] = u["sport"]; rec["dport"] = u["dport"]
                rec["udp_payload"] = u["payload"]
        elif ip["proto"] == 1:
            ic = parse_icmp(ip["payload"])
            if ic:
                rec["icmp_type"] = ic["type"]
                # ICMP time-exceeded: inner IP has ttl/seq for matching
                rec["inner"] = parse_ip(ic["payload"]) if ic["type"] == 11 else None
        with self._lock:
            self._ring.append(rec)

    def query(self, since: float, matcher):
        with self._lock:
            return [x for x in self._ring if x["t"] >= since and matcher(x)]# - low level raw IO -

class _RawIO:
    """Per-flow raw sender that pairs with a shared _Sniffer."""

    def __init__(self, src: str, dst: str, dport: int = 443, sniffer=None,
                 log_fn=None, mark: int = DEFAULT_PROBE_MARK):
        self.src = src; self.dst = dst; self.dport = dport; self.sni = sniffer
        self.log = log_fn or (lambda lvl, msg: None)
        self.sport = random.randint(32768, 61000)
        self.isn = random.randint(1, 0xFFFFFFFF)
        self.mark = int(mark or 0)
        self.mark_applied = False
        self._send = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # SO_MARK = DESYNC_MARK: probes bypass the zapret NFQUEUE rules so
            # every SYN/PSH|ACK/UDP packet sent from this socket hits TSPU raw.
            self.mark_applied = _apply_probe_mark(s, self.mark, self.log)
            self._send = s
        except OSError as e:
            self.log("warn", "raw send socket unavailable: %s" % e)

    def tcp_pkt(self, seq: int, ack: int, flags: int, payload: bytes = b"",
                ttl: int = 64, window: int = 65535) -> bytes:
        return build_tcp_packet(self.sport, self.dport, seq, ack, flags, payload,
                                self.src, self.dst, ttl, window,
                                ident=random.randint(0, 0xFFFF), df=False)

    def udp_pkt(self, sport: int, dport: int, payload: bytes, ttl: int = 64) -> bytes:
        return build_udp_packet(sport, dport, payload, self.src, self.dst, ttl)

    def send(self, pkt: bytes):
        if self._send is None:
            return False
        try:
            self._send.sendto(pkt, (self.dst, 0))
            return True
        except OSError as e:
            self.log("warn", "raw send failed: %s" % e)
            return False
        return False

    def close(self):
        if self._send is not None:
            try:
                self._send.close()
            except Exception:
                pass
            self._send = None

    def handshake(self, timeout: float = 0.4):
        self.isn = random.randint(1, 0xFFFFFFFF)
        self.send(self.tcp_pkt(self.isn, 0, TCP_SYN, b"", ttl=64))
        since = time.monotonic()
        while time.monotonic() - since < timeout:
            hits = self.sni.query(since, self._synack_matcher())
            if hits:
                self._srv_seq = hits[-1]["seq"]
                ack_val = self._srv_seq + 1
                self.send(self.tcp_pkt(self.isn + 1, ack_val, TCP_ACK, b"", ttl=64))
                return ack_val, True
            time.sleep(0.006)
        self._srv_seq = 0
        return None, False

    def _synack_matcher(self):
        dst = self.dst; sport = self.sport; isn = self.isn
        def m(x):
            return (x["proto"] == 6 and x["src"] == dst and x["dport"] == sport
                    and x["sport"] == self.dport and (x["flags"] & TCP_SYN)
                    and not (x["flags"] & TCP_RST) and x["ack"] == isn + 1)
        return m

    def wait_tcp(self, since: float, timeout: float, want_syn=False,
                 want_rst=False, want_data=False, serverhello=False,
                 from_dst=True):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            res = self.sni.query(since, self._tcp_matcher(want_syn, want_rst,
                                                          want_data, from_dst,
                                                          serverhello))
            if res:
                return res
            time.sleep(0.005)
        return []

    def _tcp_matcher(self, want_syn, want_rst, want_data, from_dst, serverhello):
        dst = self.dst; sport = self.sport
        def m(x):
            if x["proto"] != 6:
                return False
            if from_dst and not (x["src"] == dst and x["dport"] == sport
                                 and x["sport"] == self.dport):
                return False
            f = x["flags"]
            if want_syn and not (f & TCP_SYN):
                return False
            if want_rst and not (f & TCP_RST):
                return False
            if want_data and not x["tcp_payload"]:
                return False
            if serverhello:
                return tls_is_serverhello(x["tcp_payload"])
            return True
        return m


def _icmp_quoted_ttl(matches, dst, ttl, wstart, end):
    """True if an ICMP time-exceeded quoting our SYN with seq == ttl arrived:
    the inner packet echoes our probe, whose seq pins the hop exactly."""
    for x in matches:
        if (x.get("proto") != 1 or x.get("icmp_type") != 11
                or x.get("dst") != dst
                or not (wstart <= x.get("t", 0) <= end)):
            continue
        inner = x.get("inner") or {}
        if inner.get("dst") != dst:
            continue
        it = parse_tcp(inner.get("payload") or b"")
        if it and it.get("seq") == ttl:
            return True
    return False


def scan_destination_hop(dst, src, sport, sniffer, budget,
                         max_ttl=DEFAULT_TTL_MAX, log_fn=lambda lvl, msg: None,
                         mark=DEFAULT_PROBE_MARK):
    io = _RawIO(src, dst, dport=443, sniffer=sniffer, log_fn=log_fn, mark=mark)
    io.sport = sport
    step = 6
    ttl = 1
    first_hit = None
    ttl_map = {}
    since0 = time.monotonic()
    while ttl <= max_ttl and (time.monotonic() - since0) < budget:
        batch = list(range(ttl, min(ttl + step, max_ttl + 1)))
        for t in batch:
            # seq == ttl pins every reply to its exact probe: a SYN-ACK acking
            # seq+1, or an ICMP quoting our SYN, identifies the hop precisely
            io.send(io.tcp_pkt(t, 0, TCP_SYN, b"", ttl=t, window=16384))
        wstart = time.monotonic(); time.sleep(0.05); end = time.monotonic()
        matches = sniffer.query(wstart, lambda x: True) if sniffer else []
        for t in batch:
            hit = [x for x in matches if wstart <= x["t"] <= end
                   and x["src"] == dst and x["dport"] == sport
                   and (x["flags"] & (TCP_RST | TCP_SYN))]
            if hit:
                ttl_map[t] = "syn-ack/rst-from-dst"
                if first_hit is None and any(x.get("ack") == t + 1 for x in hit):
                    first_hit = t
            else:
                ttl_map[t] = "no-dst-reply"
                if _icmp_quoted_ttl(matches, dst, t, wstart, end):
                    ttl_map[t] = "icmp-ttl-exceed"
        if first_hit is not None:
            break
        ttl += step
    io.close()
    if first_hit is None:
        # fallback: no ack-confirmed hit — trust the first hop that answered
        for t in sorted(ttl_map):
            if ttl_map[t] == "syn-ack/rst-from-dst":
                first_hit = t
                break
    return (first_hit, ttl_map) if first_hit is not None else (None, ttl_map)# - rst classification + tspu ttl scan -

def _rst_tspu_confidence(x, dst, sport, dest_hop=None):
    server_ttl = (64 - dest_hop) if dest_hop else 60
    ttl = x.get("ttl", 64)
    if ttl >= server_ttl + 2:
        return 0.9
    if ttl >= server_ttl:
        return 0.8
    if ttl >= server_ttl - 4:
        return 0.6
    return 0.4


def _rst_from_dst(dst, sport):
    def m(x):
        return (x["proto"] == 6 and x["src"] == dst and x["dport"] == sport
                and x["sport"] == 443 and (x["flags"] & TCP_RST)
                and not (x["flags"] & TCP_SYN))
    return m


def scan_tspu_hop(dst, src, sni, sport, sniffer, budget, dest_hop,
                  max_ttl=DEFAULT_TTL_MAX, log_fn=lambda lvl, msg: None,
                  mark=DEFAULT_PROBE_MARK):
    io = _RawIO(src, dst, dport=443, sniffer=sniffer, log_fn=log_fn, mark=mark)
    io.sport = sport
    ch = build_tls_client_hello(sni)
    ack, ok = io.handshake(0.45)
    if not ok:
        ack = 1
        log_fn("info", "tspu_hop: handshake pre-check missed; using half-open CH")
    step = 4; ttl = 1; tspu = None; since = time.monotonic()
    while ttl <= max_ttl and (time.monotonic() - since) < budget:
        batch = list(range(ttl, min(ttl + step, max_ttl) + 1))
        for t in batch:
            io.send(io.tcp_pkt(io.isn + 1, ack, TCP_PSH | TCP_ACK, ch, ttl=t))
        w0 = time.monotonic(); time.sleep(0.05)
        rsts = sniffer.query(w0, _rst_from_dst(dst, sport)) if sniffer else []
        if rsts:
            lo, hi = batch[0], batch[-1]; br = time.monotonic()
            while lo < hi and (time.monotonic() - br) < budget * 0.4:
                mid = (lo + hi) // 2
                io.send(io.tcp_pkt(io.isn + 1, ack, TCP_PSH | TCP_ACK, ch, ttl=mid))
                r0 = time.monotonic(); time.sleep(0.04)
                r = sniffer.query(r0, _rst_from_dst(dst, sport)) if sniffer else []
                if r:
                    hi = mid
                else:
                    lo = mid + 1
            tspu = lo; break
        ttl += step
    io.close()
    return tspu, (64 - tspu) if tspu else None


def _dead():
    return {"bypass": None, "rst_received": False, "serverhello": False,
            "confidence": 0.0, "connected": False}


class TspuProber:
    def __init__(self, src, dst, sni, sniffer, log_fn,
                 mark=DEFAULT_PROBE_MARK):
        self.src = src; self.dst = dst; self.sni_name = sni
        self.sniffer = sniffer; self.log = log_fn; self.mark = mark

    def _connect(self, timeout=0.45):
        io = _RawIO(self.src, self.dst, 443, self.sniffer, self.log,
                    mark=self.mark)
        ack, ok = io.handshake(timeout)
        return io, ack, ok

    def _result(self, bypass, rst, sh):
        conf = 0.9 if sh else (0.75 if bypass else 0.85)
        return {"bypass": bool(bypass), "rst_received": bool(rst),
                "serverhello": bool(sh), "confidence": conf, "connected": True}

    def test_split(self, pos, window=0.38, prep=0.5):
        io, ack, ok = self._connect(prep)
        if not ok:
            io.close(); return _dead()
        ch = build_tls_client_hello(self.sni_name)
        parts = split_payload(ch, pos)
        since = time.monotonic()
        io.send(io.tcp_pkt(io.isn + 1, ack, TCP_PSH | TCP_ACK, parts[0]))
        time.sleep(0.012)
        io.send(io.tcp_pkt(io.isn + 1 + pos, ack, TCP_PSH | TCP_ACK, parts[1]))
        rst = io.wait_tcp(since, window, want_rst=True)
        sh = io.wait_tcp(since, window, serverhello=True)
        io.close()
        return self._result(len(rst) == 0, rst, sh)

    def test_seqovl(self, window=0.38, prep=0.5):
        io, ack, ok = self._connect(prep)
        if not ok:
            io.close(); return _dead()
        ch = build_tls_client_hello(self.sni_name)
        S = io.isn + 1
        junk = bytes(random.getrandbits(8) for _ in range(6))
        since = time.monotonic()
        io.send(io.tcp_pkt(S - 6, ack, TCP_PSH | TCP_ACK, junk + ch[:2]))
        time.sleep(0.012)
        io.send(io.tcp_pkt(S, ack, TCP_PSH | TCP_ACK, ch[2:]))
        rst = io.wait_tcp(since, window, want_rst=True)
        sh = io.wait_tcp(since, window, serverhello=True)
        io.close()
        return self._result(len(rst) == 0, rst, sh)

    def test_disorder(self, window=0.38, prep=0.5):
        io, ack, ok = self._connect(prep)
        if not ok:
            io.close(); return _dead()
        ch = build_tls_client_hello(self.sni_name)
        p = (10, 20)
        c0 = ch[:p[0]]; c1 = ch[p[0]:p[1]]; c2 = ch[p[1]:]
        S = io.isn + 1
        seqs = [S, S + len(c0), S + len(c0) + len(c1)]
        chunks = [c0, c1, c2]
        order = [2, 0, 1]
        since = time.monotonic()
        for idx in order:
            io.send(io.tcp_pkt(seqs[idx], ack, TCP_PSH | TCP_ACK, chunks[idx]))
            time.sleep(0.008)
        rst = io.wait_tcp(since, window, want_rst=True)
        sh = io.wait_tcp(since, window, serverhello=True)
        io.close(); return self._result(len(rst) == 0, rst, sh)

    def test_fake_tls(self, window=0.32, prep=0.45):
        io, ack, ok = self._connect(prep)
        if not ok:
            io.close(); return {"rst_received": False, "connected": False}
        since = time.monotonic()
        io.send(io.tcp_pkt(io.isn + 1, ack, TCP_PSH | TCP_ACK,
                           build_tls_client_hello(self.sni_name, bad_tls=True)))
        rst = io.wait_tcp(since, window, want_rst=True)
        io.close(); return {"rst_received": bool(rst), "connected": True}

    def test_fake_random(self, window=0.32, prep=0.45):
        io, ack, ok = self._connect(prep)
        if not ok:
            io.close(); return {"rst_received": False, "connected": False}
        junk = bytes(random.getrandbits(8) for _ in range(128))
        since = time.monotonic()
        io.send(io.tcp_pkt(io.isn + 1, ack, TCP_PSH | TCP_ACK, junk))
        rst = io.wait_tcp(since, window, want_rst=True)
        io.close(); return {"rst_received": bool(rst), "connected": True}


def _udp_dns_alive(server=None, timeout=0.8):
    if server is None:
        server = os.environ.get("TSPU_INTEL_DNS", "1.1.1.1").strip()

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
        tid = random.randint(0, 0xFFFF)
        name = "asn.%d.probe" % random.randint(10000, 99999)
        q = _dns_encode_name(name) + struct.pack("!HH", 1, 1)
        hdr = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0x0200)
        s.sendto(hdr + q, (server, 53)); data, _ = s.recvfrom(512); s.close()
        return len(data) > 0
    except OSError:
        return False


def test_quic(dst, src, sni, sniffer, budget=0.4, log_fn=lambda lvl, msg: None,
              mark=DEFAULT_PROBE_MARK):
    ctrl = _udp_dns_alive(timeout=0.2)
    qio = _RawIO(src, dst, dport=443, sniffer=sniffer, log_fn=log_fn, mark=mark)
    sport = qio.sport
    since = time.monotonic()
    qio.send(qio.udp_pkt(sport, 4740, b"\x00", ttl=64))
    time.sleep(0.03)
    qio.send(qio.udp_pkt(sport, 443, build_quic_initial(sni), ttl=64))
    end = time.monotonic() + min(budget, 0.35)
    resp = False
    while time.monotonic() < end:
        r = sniffer.query(since, lambda x: x["proto"] == 17 and x["src"] == dst
                          and x["dport"] == sport) if sniffer else []
        if r:
            resp = True; break
        time.sleep(0.01)
    qio.close()
    return (not resp) and ctrl, ctrl
# - ML dataset log (jsonl + rotation, mirrors CutLogger shape) -

class IntelLog:
    def __init__(self, path, max_file=2 * 1024 * 1024, keep=5,
                 max_buffered=500):
        self.path = path
        self.max_file = int(max_file)
        self.keep = max(1, int(keep))
        self._lock = threading.Lock()
        self._buf = []
        self._max_buf = int(max_buffered)
        self._seq = 0
        self._count = 0
        try:
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            self._count = self._read_tail_count()
        except Exception:
            pass

    def record(self, payload):
        entry = {"id": self._next_id(), "ts": _iso(), "unix_ts": round(time.time(), 3)}
        entry.update(payload)
        line = json.dumps(entry, ensure_ascii=False, default=str)
        with self._lock:
            self._buf.append(entry)
            if len(self._buf) > self._max_buf:
                self._buf = self._buf[-self._max_buf:]
            try:
                self._rotate_if_needed()
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                self._count += 1
            except Exception as e:
                sys.stderr.write("[tspu-intel] log write: %s\n" % e)
        return entry

    def list(self, limit=50):
        with self._lock:
            return list(reversed(self._buf[-int(limit):]))

    def export(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            return ""

    def clear(self):
        with self._lock:
            self._buf = []
            try:
                with open(self.path, "w") as f:
                    f.write("")
            except Exception:
                pass
            self._count = 0
        return {"ok": True}

    def status(self):
        with self._lock:
            return {"path": self.path, "count": self._count, "buffered": len(self._buf)}

    def _next_id(self):
        self._seq += 1
        return self._seq

    def _rotate_if_needed(self):
        try:
            if os.path.exists(self.path) and os.path.getsize(self.path) >= self.max_file:
                base, ext = os.path.splitext(self.path)
                for i in range(self.keep, 0, -1):
                    src = "%s.%d%s" % (base, i, ext)
                    dst = "%s.%d%s" % (base, i + 1, ext)
                    if os.path.exists(src):
                        os.replace(src, dst)
                if os.path.exists(self.path):
                    os.replace(self.path, "%s.1%s" % (base, ext))
                self._count = 0
        except Exception:
            pass

    def _read_tail_count(self):
        n = 0
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for _line in f:
                    n += 1
            self._seq = n
        except Exception:
            pass
        return n# - async reconnaissance engine -

class _Budget:
    __slots__ = ("deadline",)

    def __init__(self, seconds: float):
        self.deadline = time.monotonic() + max(0.05, float(seconds))

    def remaining(self) -> float:
        return max(0.0, self.deadline - time.monotonic())

    def ok(self) -> bool:
        return time.monotonic() < self.deadline


class TspuIntel:
    """Async TSPU reconnaissance engine, triggered on every session cut.

    Context dict (built by PoolSwitcher.on_connection_cut) keys:
      cut_id, event_kind, lifetime_sec, reset_confirmed,
      remote_ip, remote_port, local_port, qnum, slot_index,
      strategy_name, nfqws_opt, strategy_score_before, bytes_delta,
      termination_type, socks_port, panel_port
    """

    def __init__(self, path=None, log_fn=None, enabled=True, cooldown=None,
                 budget_ms=DEFAULT_BUDGET_MS, ttl_max=DEFAULT_TTL_MAX,
                 sni=DEFAULT_SNI, dry_run=False, raw_available=None,
                 probe_mark=None):
        self.log = log_fn or (lambda lvl, msg: print("[tspu-intel][%s] %s" % (lvl, msg), flush=True))
        self.intel_log = IntelLog(path=path or "/opt/zapret2/logs/tspu_intel.jsonl")
        self.enabled = bool(enabled)
        self.cooldown = float(cooldown if cooldown is not None else DEFAULT_COOLDOWN)
        self.budget_ms = int(budget_ms)
        self.ttl_max = int(ttl_max)
        self.sni = sni
        self.dry_run = bool(dry_run)
        self.raw_available = bool(raw_available if raw_available is not None else _raw_enabled())
        self.sim_mode = bool(self.dry_run or not self.raw_available)
        self.probe_mark = (int(probe_mark) if probe_mark is not None
                           else DEFAULT_PROBE_MARK)
        self._lock = threading.RLock()
        self._last_run_ts = None
        self._last_result_ts = None
        self._total_runs = 0
        self._running = False
        self._last_result = None
        self._degraded = []
        self._on_cut_logger = None

    def configure(self, cfg: dict):
        if not isinstance(cfg, dict):
            return self.status()
        if "enabled" in cfg:
            self.enabled = bool(cfg["enabled"])
        if "cooldown" in cfg:
            self.cooldown = max(0, float(cfg["cooldown"]))
        if "budget_ms" in cfg:
            self.budget_ms = max(120, min(HARD_BUDGET_MS, int(cfg["budget_ms"])))
        if "ttl_max" in cfg:
            self.ttl_max = max(5, min(DEFAULT_TTL_MAX, int(cfg["ttl_max"])))
        if "sni" in cfg:
            self.sni = cfg["sni"]
        if "dry_run" in cfg:
            self.dry_run = bool(cfg["dry_run"])
        if "probe_mark" in cfg:
            self.probe_mark = int(cfg["probe_mark"] or 0)
        self.sim_mode = bool(self.dry_run or not self.raw_available)
        return self.status()

    def register_cut_logger_callback(self, cb):
        self._on_cut_logger = cb

    def status(self):
        with self._lock:
            return {
                "enabled": self.enabled,
                "cooldown": self.cooldown,
                "budget_ms": self.budget_ms,
                "ttl_max": self.ttl_max,
                "sni": self.sni,
                "probe_mark": self.probe_mark,
                "raw_available": self.raw_available,
                "mode": "dry_run" if self.sim_mode else "active",
                "last_run_ts": _iso(self._last_run_ts) if self._last_run_ts else None,
                "last_result_ts": _iso(self._last_result_ts) if self._last_result_ts else None,
                "total_runs": self._total_runs,
                "running": self._running,
                "log_path": self.intel_log.path,
                "log_count": self.intel_log.status()["count"],
            }

    def on_cut_async(self, ctx: dict) -> dict:
        if not self.enabled:
            return {"ok": False, "reason": "disabled"}
        now = time.time()
        with self._lock:
            if self._last_run_ts and (now - self._last_run_ts) < self.cooldown:
                rem = self.cooldown - (now - self._last_run_ts)
                return {"ok": False, "reason": "cooldown", "remaining": round(rem, 1)}
            if self._running:
                return {"ok": False, "reason": "already_running"}
            self._last_run_ts = now
            self._running = True
        t = threading.Thread(target=self._guarded_run, args=(ctx,), daemon=True)
        t.start()
        return {"ok": True, "mode": "dry_run" if self.sim_mode else "active"}

    def _guarded_run(self, ctx: dict):
        start = time.monotonic()
        self.log("info", "probe started (mode=%s, sni=%s)" % (
            "dry_run" if self.sim_mode else "active", self.sni))
        try:
            result = self.run(ctx)
        except Exception as e:
            self.log("error", "probe crashed: %s" % e)
            result = {"dataset_version": DATASET_VERSION, "ts": _utcnow_iso(),
                      "meta": {"crashed": True, "error": str(e)}}
        elapsed = round((time.monotonic() - start) * 1000.0, 1)
        with self._lock:
            meta = result.setdefault("meta", {})
            meta["elapsed_ms"] = elapsed
            meta["mode"] = "dry_run" if self.sim_mode else "active"
            meta["degraded"] = list(self._degraded)
            meta["partial"] = bool(self._degraded)
        try:
            self.intel_log.record(result)
        except Exception as e:
            self.log("error", "dataset log write failed: %s" % e)
        if self._on_cut_logger:
            try:
                self._on_cut_logger({"kind": "tspu_intel",
                                     "cut_id": ctx.get("cut_id"),
                                     "vector": result})
            except Exception as e:
                self.log("error", "cut-log callback failed: %s" % e)
        with self._lock:
            self._last_result_ts = time.time()
            self._total_runs += 1
            self._last_result = result
            self._running = False
        self.log("info", "probe done in %sms" % elapsed)
        return result

    def run(self, ctx: dict) -> dict:
        with self._lock:
            self._degraded = []   # reset per-run so stale flags don't leak across probes
        bd = _Budget(self.budget_ms / 1000.0)
        sim = self.sim_mode
        result = {
            "dataset_version": DATASET_VERSION,
            "ts": _utcnow_iso(),
            "meta": {"sni": self.sni, "ttl_max": self.ttl_max,
                     "dataset_path": self.intel_log.path},
        }
        result["meta"]["ctx_fields"] = self._ctx_fields(ctx)
        cf = result["meta"]["ctx_fields"]
        self.log("info", "cut ctx intake: dst_ip=%s qnum=%s strategy=%s score=%s "
                         "bytes_delta=%s lifetime=%s term=%s ctx_keys=%d" % (
                     cf.get("remote_ip"), cf.get("qnum"), cf.get("strategy_name"),
                     cf.get("strategy_score_before"),
                     (cf.get("bytes_delta") if cf.get("bytes_delta_present")
                      else "<absent>"),
                     cf.get("lifetime_sec"), cf.get("termination_type"),
                     cf.get("ctx_key_count")))
        if sim:
            result["meta"]["simulated"] = True
            result["meta"]["dry_run"] = True
            self.log("warn", "dry-run simulator: raw socket unavailable")
        dst = self._resolve_dst(ctx, bd)
        # фактические цель и SNI этого прогона — важны для датасета
        # (что именно зондировали)
        result["meta"]["dst"] = dst
        result["meta"]["sni"] = self._ctx_sni(ctx)
        result["environment"] = self._environment(ctx, dst, bd, sim)
        result["session_profile"] = self._session(ctx)
        result["tspu_network_metrics"] = self._network(ctx, dst, bd, sim)
        result["tspu_l7_vulnerabilities"] = self._l7(ctx, dst, bd, sim)
        result["strategy_context"] = self._strategy(ctx)
        return result

    def _ctx_fields(self, ctx):
        """Провенанс входа: что детектор передал в момент среза. Пишется в
        meta, чтобы датасет сам показывал, какие поля были доступны — иначе
        пустые bytes_*/score неотличимы от «не измеряли»."""
        def _present(k):
            v = ctx.get(k)
            return v is not None and v != ""
        return {
            "ctx_key_count": len(ctx),
            "remote_ip": ctx.get("remote_ip") or ctx.get("ip") or ctx.get("dst"),
            "remote_port": ctx.get("remote_port"),
            "local_port": ctx.get("local_port"),
            "qnum": ctx.get("qnum"),
            "slot_index": ctx.get("slot_index"),
            "sni": ctx.get("sni"),
            "strategy_name": ctx.get("strategy_name"),
            "strategy_score_before": ctx.get("strategy_score_before"),
            "bytes_delta_present": _present("bytes_delta"),
            "bytes_delta": ctx.get("bytes_delta"),
            "lifetime_sec": ctx.get("lifetime_sec", ctx.get("lifetime")),
            "reset_confirmed": bool(ctx.get("reset_confirmed")),
            "event_kind": ctx.get("event_kind") or "classic",
            "termination_type": ctx.get("termination_type"),
        }

    def _ctx_sni(self, ctx):
        """Фактический SNI прогона: ctx -> домен из стратегии -> дефолт движка."""
        return (ctx.get("sni") or ctx.get("hostname")
                or _guess_domain(ctx.get("strategy_name")
                                 or ctx.get("applied_strategy_name"))
                or self.sni)

    def _resolve_dst(self, ctx, budget: _Budget):
        # 1. Try all context key variants for the remote IP
        ip = ctx.get("remote_ip") or ctx.get("ip") or ctx.get("dst") or ctx.get("remote_host")
        # Reject loopback/private/link-local IPs - they mean the conn was local-proxied
        # or the hex IP from /proc/net/tcp was mis-decoded; fall through to SNI resolution
        if ip and not _is_private_ip(ip):
            return ip

        # 2. Пытаемся динамически взять SNI из контекста сессии, если он там есть
        sni_to_resolve = self._ctx_sni(ctx)

        # 3. Горячий кэш полностью исключает сеть из зонда (~2s бюджет):
        #    DNS-резолв на каждый обрыв съедал бы половину окна измерений
        hit = _RESOLVE_CACHE.get(sni_to_resolve)
        now = time.time()
        if hit and (now - hit[0]) < _RESOLVE_TTL:
            return hit[1]

        left = budget.remaining()
        if left <= 0.1:
            return DEFAULT_TARGET_IP
        res = {"ip": None}
        def _w():
            ip2 = None
            try:
                # Резолвим динамический SNI вместо жесткого дефолта (UDP DNS)
                ip2 = _dns_resolve_a(sni_to_resolve, timeout=0.35)
            except Exception:
                ip2 = None
            if not ip2:
                try:
                    infos = socket.getaddrinfo(sni_to_resolve, 443, socket.AF_INET,
                                               socket.SOCK_STREAM)
                    if infos:
                        ip2 = infos[0][4][0]
                except Exception:
                    ip2 = None
            res["ip"] = ip2
        t = threading.Thread(target=_w, daemon=True)
        t.start(); t.join(max(0.1, min(left, 0.4)))
        ip3 = res["ip"]
        if ip3 and not _is_private_ip(ip3):
            _RESOLVE_CACHE[sni_to_resolve] = (now, ip3)
            return ip3
        return ip3 or DEFAULT_TARGET_IP


    def _environment(self, ctx, dst, budget: _Budget, sim):
        if sim:
            return {"isp_asn": "AS12345", "isp_name": "Rostelecom-sim",
                    "connection_type": "broadband",
                    "target_host_type": classify_target_host(
                        ctx.get("strategy_name") or "", self.sni)}
        isp = None
        try:
            isp = lookup_asn(dst, timeout=min(0.35, max(0.1, budget.remaining())))
        except Exception as e:
            self.log("warn", "asn lookup crashed for %s: %s" % (dst, e))
            isp = None
        isp_source = "cymru_txt"
        if not isp:
            self._degraded.append("isp_lookup_failed")
            isp_name = "unknown"
            isp_asn = "AS0"
        elif isp.get("fallback"):
            self._degraded.append("asn_unresolved_fallback")
            isp_source = "fallback_local"
            isp_asn = isp.get("isp_asn", "AS_LOCAL")
            isp_name = isp.get("isp_name", "LocalProvider")
            self.log("warn", "ASN lookup for %s fell back to %s/%s (%s): "
                             "cymru TXT gave no usable answer" %
                     (dst, isp_asn, isp_name, isp.get("fallback_reason", "?")))
        else:
            isp_asn = isp.get("isp_asn", "AS0")
            isp_name = isp.get("isp_name", "unknown")
        return {"isp_asn": isp_asn,
                "isp_name": isp_name,
                "isp_source": isp_source,
                "connection_type": classify_connection_type(dst, isp_name),
                "target_host_type": classify_target_host(
                    ctx.get("strategy_name") or "", self.sni)}

    def _session(self, ctx):
        lifetime = ctx.get("lifetime_sec", ctx.get("lifetime", 0.0))
        try:
            lifetime = float(lifetime)
        except Exception:
            lifetime = 0.0
        bdelta = ctx.get("bytes_delta")
        recv = None; sent = None
        if bdelta is not None:
            recv = int(bdelta)
            # per-flow tx is unavailable here (no nf_conntrack host access);
            # the queue aggregate is downstream (recv) only
            sent = None
            self._degraded.append("bytes_sent_unavailable")
        else:
            # отсутствие данных — тоже диагноз: в момент среза не было
            # снапшота очереди (traffic) либо детектор не передал счётчики
            self._degraded.append("bytes_delta_absent")
            self.log("warn", "session profile: ctx.bytes_delta absent — queue "
                             "traffic snapshot missing at cut time, bytes_* "
                             "stay null in the vector")
        term = ctx.get("termination_type")
        if not term:
            if ctx.get("reset_confirmed"):
                term = "RST"
            elif ctx.get("event_kind") == "epidemic":
                term = "RST"
            else:
                term = "Silent_Drop"
        return {"session_lifetime_sec": round(lifetime, 3),
                "bytes_sent_before_cut": sent,
                "bytes_recv_before_cut": recv,
                "termination_type": term}# - network metrics (TTL scan) + L7 micro-tests -

def _empty_l7(note="no_data"):
    return {"split_pos_2_bypass": None, "split_pos_5_bypass": None,
            "seqovl_bypass": None, "disorder_bypass": None,
            "fake_payload_strictness": None, "quic_handshake_drop": None,
            "note": note}


# collector methods are attached below via monkey-patch
def _network(self, ctx, dst, budget: "_Budget", sim):
    if sim:
        return {"tspu_hop": 11, "destination_hop": 17, "delta_distance": 6,
                "ingress_ttl_est": 51, "note": "simulated"}
    sniffer = _Sniffer(); sniffer.set_log(self.log)
    if not sniffer.open_or_dummy():
        self._degraded.append("sniffer_unavailable")
        return {"tspu_hop": None, "destination_hop": None, "delta_distance": None,
                "note": "sniffer_unavailable"}
    src = local_ip_for(dst) or "127.0.0.1"
    try:
        dst_hop, tmap = scan_destination_hop(
            dst, src, random.randint(32768, 60000), sniffer,
            budget.remaining() * 0.45, self.ttl_max, self.log,
            mark=self.probe_mark)
    except Exception as e:
        self.log("warn", "destination_hop scan failed: %s" % e)
        self._degraded.append("dest_hop_failed"); dst_hop = None; tmap = {}
    tspu_h = None; near = None
    if budget.ok():
        try:
            tspu_h, near = scan_tspu_hop(dst, src, self.sni,
                                        random.randint(32768, 60000), sniffer,
                                        budget.remaining() * 0.55, dst_hop,
                                        self.ttl_max, self.log,
                                        mark=self.probe_mark)
        except Exception as e:
            self.log("warn", "tspu_hop scan failed: %s" % e)
            self._degraded.append("tspu_hop_failed")
    delta = None
    if dst_hop is not None and tspu_h is not None and dst_hop >= tspu_h:
        delta = dst_hop - tspu_h
    sniffer.close()
    self.log("info", "network scan done: dst_hop=%s tspu_hop=%s "
                     "ttl_map_hops=%d degraded=%s" %
             (dst_hop, tspu_h, len(tmap), self._degraded))
    return {"tspu_hop": tspu_h, "destination_hop": dst_hop,
            "delta_distance": delta, "ingress_ttl_est": near,
            "ttl_scan_map": tmap}


def _l7(self, ctx, dst, budget: "_Budget", sim):
    if sim:
        return {"split_pos_2_bypass": True, "split_pos_5_bypass": False,
                "seqovl_bypass": True, "disorder_bypass": False,
                "fake_payload_strictness": "low_validation",
                "quic_handshake_drop": True, "probe_details": None,
                "note": "simulated"}
    sniffer = _Sniffer(); sniffer.set_log(self.log)
    if not sniffer.open_or_dummy():
        self._degraded.append("sniffer_unavailable")
        return _empty_l7("sniffer_unavailable")
    src = local_ip_for(dst) or "127.0.0.1"
    pb = TspuProber(src, dst, self.sni, sniffer, self.log,
                    mark=self.probe_mark)
    ex = ThreadPoolExecutor(max_workers=4)
    futs = {}
    try:
        futs["s2"] = ex.submit(pb.test_split, 2)
        futs["s5"] = ex.submit(pb.test_split, 5)
        futs["seq"] = ex.submit(pb.test_seqovl)
        futs["dis"] = ex.submit(pb.test_disorder)
        futs["ftls"] = ex.submit(pb.test_fake_tls)
        futs["frnd"] = ex.submit(pb.test_fake_random)
        futs["q"] = ex.submit(test_quic, dst, src, self.sni, sniffer,
                              max(0.1, budget.remaining() * 0.9), self.log,
                              mark=self.probe_mark)

        def _g(key, default=None):
            try:
                f = futs[key]
                left = budget.remaining()
                if left <= 0.05:
                    return default
                return f.result(timeout=min(0.6, max(0.05, left)))
            except Exception as e:
                self.log("warn", "l7 %s failed: %s" % (key, e))
                return default

        r2, r5, rseq, rdis = _g("s2"), _g("s5"), _g("seq"), _g("dis")
        ftls, frnd, q = _g("ftls"), _g("frnd"), _g("q")
    finally:
        ex.shutdown(wait=False)
        sniffer.close()

    def _bv(r):
        if not r or not r.get("connected"):
            return None
        return bool(r.get("bypass"))

    s2, s5, seq, dis = _bv(r2), _bv(r5), _bv(rseq), _bv(rdis)
    ft = ftls or {}; fr = frnd or {}
    ftls_rst = ft.get("rst_received") if ft.get("connected") else None
    frnd_rst = fr.get("rst_received") if fr.get("connected") else None
    if ftls_rst and frnd_rst:
        strict = "strict_both"
    elif ftls_rst:
        strict = "strict_tls"
    elif frnd_rst:
        strict = "strict_random"
    elif not ft.get("connected") or not fr.get("connected"):
        strict = None
        self._degraded.append("fake_payload_partial")
    else:
        strict = "low_validation"
    if q is None:
        qdrop = None; qctrl = None
    else:
        qdrop, qctrl = q[0], q[1]
    # детали каждой пробы: отличаем «строгий ТСПУ» (conn=1,rst=1) от
    # сломанной пробы (conn=0/None — timeout, нет SYN-ACK, инфраструктура)
    details = {}
    for key, r in (("split_pos_2", r2), ("split_pos_5", r5),
                   ("seqovl", rseq), ("disorder", rdis),
                   ("fake_tls", ftls), ("fake_random", frnd)):
        if isinstance(r, dict) and r:
            details[key] = {"connected": bool(r.get("connected")),
                            "rst_received": r.get("rst_received"),
                            "serverhello": r.get("serverhello"),
                            "confidence": r.get("confidence")}
        else:
            details[key] = None
    det_str = " ".join(
        "%s[conn=%s,rst=%s,sh=%s,conf=%s]" % (k, d["connected"], d["rst_received"],
                                              d["serverhello"], d["confidence"])
        if isinstance(d, dict) else "%s[no_data]" % k
        for k, d in details.items())
    self.log("info", "l7 probes: s2=%s s5=%s seq=%s dis=%s strict=%s quic_drop=%s %s" %
             (s2, s5, seq, dis, strict, qdrop, det_str))
    return {"split_pos_2_bypass": s2, "split_pos_5_bypass": s5,
            "seqovl_bypass": seq, "disorder_bypass": dis,
            "fake_payload_strictness": strict,
            "quic_handshake_drop": qdrop,
            "quic_control_ok": qctrl,
            "quic_response_seen": (q is not None),
            "probe_details": details}


def _strategy(self, ctx):
    name = ctx.get("strategy_name") or (ctx.get("slot") or {}).get("strategy") or "unknown"
    nfqws = ctx.get("nfqws_opt") or ctx.get("nfqws_raw") or ""
    score = ctx.get("strategy_score_before")
    if score is None:
        self.log("warn", "strategy %s has no score history yet — "
                         "strategy_score_before=null (это не реальный 0.0)" % name)
    return {"applied_strategy_name": name, "applied_strategy_raw": nfqws,
            "strategy_score_before": score,
            "strategy_score_known": score is not None}


# attach collector methods to the engine (keeps the class block readable above)
TspuIntel._network = _network
TspuIntel._l7 = _l7
TspuIntel._strategy = _strategy


# - env factory + helpers -

def _env_bool(name, default=False):
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "on", "yes")


def _env_float(name, default):
    try:
        return float(os.environ.get(name) or default)
    except (TypeError, ValueError):
        return float(default)


def _env_int(name, default):
    try:
        return int(os.environ.get(name) or default)
    except (TypeError, ValueError):
        return int(default)


def _default_intel_path():
    cut = os.environ.get("CUT_LOG_PATH")
    if cut:
        parent = os.path.dirname(cut)
        if parent:
            return os.path.join(parent, "tspu_intel.jsonl")
    return "/opt/zapret2/logs/tspu_intel.jsonl"


def build_tspu_intel_from_env(log_fn=None):
    log_fn = log_fn or (lambda lvl, msg: print("[tspu-intel][%s] %s" % (lvl, msg), flush=True))
    # Mark priority: TSPU_INTEL_MARK > DESYNC_MARK (kept in sync with the
    # firewall anti-loop rules) > built-in DEFAULT_PROBE_MARK.
    env_mark = os.environ.get("TSPU_INTEL_MARK") or os.environ.get("DESYNC_MARK")
    return TspuIntel(path=_default_intel_path(),
                     log_fn=log_fn,
                     enabled=_env_bool("TSPU_INTEL_ENABLE", True),
                     cooldown=_env_float("TSPU_INTEL_COOLDOWN", DEFAULT_COOLDOWN),
                     budget_ms=_env_int("TSPU_INTEL_BUDGET_MS", DEFAULT_BUDGET_MS),
                     ttl_max=_env_int("TSPU_INTEL_TTL_MAX", DEFAULT_TTL_MAX),
                     sni=os.environ.get("TSPU_INTEL_SNI") or DEFAULT_SNI,
                     dry_run=_env_bool("TSPU_INTEL_DRY_RUN", False),
                     probe_mark=(_parse_mark_value(env_mark)
                                 if env_mark else None))


# - smoke run (dry-run by default outside Linux) -

if __name__ == "__main__":
    eng = build_tspu_intel_from_env()
    print("mode=%s raw_available=%s path=%s" % (eng.status()["mode"],
          eng.raw_available, eng.intel_log.path))
    ctx = {"cut_id": 0, "event_kind": "classic", "lifetime_sec": 99.0,
           "reset_confirmed": True, "remote_ip": None, "remote_port": 443,
           "local_port": 0, "qnum": None, "slot_index": None,
           "strategy_name": "youtube_com_003", "nfqws_opt": "--filter-tcp=443",
           "strategy_score_before": -0.5, "bytes_delta": 4096}
    out = eng.run(ctx)
    print(json.dumps(out, ensure_ascii=False, indent=2))