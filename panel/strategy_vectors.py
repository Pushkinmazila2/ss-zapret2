#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
strategy_vectors.py — group nfqws2 strategies into "vectors" (families of the
same underlying desync technique) and track which vector TSPУ currently
seems to have a working detector for.

Why
---
A "strategy" (one NFQWS2_OPT string) is usually one trick, or a small
combination of tricks, e.g.:

    --dpi-desync=fake,split --dpi-desync-ttl=4 --dpi-desync-fooling=badseq

When TSPУ starts cutting connections on a given slot, it is rarely that one
*exact* strategy got fingerprinted — DPI middleboxes generally key on a
*pattern* (how the ClientHello gets split, a TTL trick, an IPv6 extension
header abuse, ...), not a literal byte sequence. Picking the next candidate
strategy purely by individual score means the pool can spend its whole
shadow-test budget cycling through near-identical siblings of the exact
technique that just got blocked.

This module:
  1. classifies each strategy's NFQWS2_OPT into a coarse "vector" fingerprint,
  2. scores both individual strategies AND vectors (successes/failures with
     the same aging scheme the switcher already used),
  3. lets the switcher explicitly "implicate" a vector the moment a live
     TSPУ cut happens on a slot using it, biasing subsequent candidate
     selection toward a *different* technique for a cooldown period,
  4. diversifies a batch of shadow-test candidates across vectors instead of
     drawing several near-duplicates,
  5. can replay the persisted tspУ.log journal to rebuild scores across a
     panel restart, instead of starting every strategy/vector back at 0.

This is a heuristic, not a certainty — vector classification is best-effort
string matching on nfqws2's documented --dpi-desync grammar. When nothing
recognizable is found the strategy is classified as 'other' and just
competes on its individual score, same as before this module existed.
"""

import collections
import re
import time

# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

# Coarse technique buckets for --dpi-desync=<mode1,mode2,...> tokens.
# Multiple raw modes commonly collapse to the same underlying idea.
_MODE_FAMILY = {
    # segmentation-style: split the TLS ClientHello / TCP stream across packets
    "split":          "seg",
    "split2":         "seg",
    "multisplit":     "seg",
    "disorder":       "seg",
    "disorder2":      "seg",
    "multidisorder":  "seg",
    # fake packet: inject a decoy packet before/around the real one
    "fake":           "fake",
    "fakedsplit":     "fake",
    "fakeddisorder":  "fake",
    "fakedisorder":   "fake",
    "fake_syndata":   "fake",
    # IP-layer fragmentation
    "ipfrag1":        "ipfrag",
    "ipfrag2":        "ipfrag",
    # IPv6 extension-header abuse
    "hopbyhop":       "ipv6ext",
    "hopbyhop2":      "ipv6ext",
    "destopt":        "ipv6ext",
    # TCP state-machine abuse
    "syndata":        "tcpstate",
    "rst":            "tcpstate",
    "rstack":         "tcpstate",
}

_FOOL_TOKENS = frozenset((
    "md5sig", "ts", "badsum", "badseq", "datanoack", "hopbyhop", "hopbyhop2",
))

_OPT_RE      = re.compile(r"--dpi-desync=(\S+)")
_TTL_RE      = re.compile(r"--dpi-desync-ttl6?=\d+")
_AUTOTTL_RE  = re.compile(r"--dpi-desync-autottl\b")
_FOOL_RE     = re.compile(r"--dpi-desync-fooling=(\S+)")
_L7_RE       = re.compile(r"--filter-l7=(\S+)")
_FAKETLS_RE  = re.compile(r"--dpi-desync-fake-tls\b")
_FAKEQUIC_RE = re.compile(r"--dpi-desync-fake-quic\b")
_SPLITPOS_RE = re.compile(r"--dpi-desync-split-pos(es)?=\S+")

UNKNOWN_VECTOR = "unknown"


def classify_vector(nfqws_opt):
    """
    Best-effort classification of an NFQWS2_OPT string into a short vector
    key, e.g. 'seg+badseq+ttl+tls' or 'fake+quic'.

    A multi-profile strategy (several `--new`-delimited segments) is
    classified from its FIRST profile only — profiles chained in one
    strategy are usually variations on one idea, and this keeps the
    fingerprint stable and cheap.

    Returns None for empty input (caller should treat that as "no strategy
    active" rather than a real classification); returns 'other' when the
    text has no recognizable --dpi-desync mode (e.g. a pure --hostlist
    tuning strategy).
    """
    if not nfqws_opt or not nfqws_opt.strip():
        return None

    text = nfqws_opt.split("--new", 1)[0]

    families = set()
    m = _OPT_RE.search(text)
    if m:
        for tok in m.group(1).split(","):
            tok = tok.strip()
            if not tok:
                continue
            families.add(_MODE_FAMILY.get(tok, tok))
    family_part = "+".join(sorted(families)) if families else "other"

    fool = set()
    m = _FOOL_RE.search(text)
    if m:
        fool = {t.strip() for t in m.group(1).split(",") if t.strip() in _FOOL_TOKENS}
    fool_part = ",".join(sorted(fool))

    ttl_part = "ttl" if (_TTL_RE.search(text) or _AUTOTTL_RE.search(text)) else ""

    extra = []
    if _FAKETLS_RE.search(text):
        extra.append("faketls")
    if _FAKEQUIC_RE.search(text):
        extra.append("fakequic")
    if _SPLITPOS_RE.search(text):
        extra.append("splitpos")
    extra_part = ",".join(extra)

    l7_m = _L7_RE.search(text)
    l7 = l7_m.group(1).strip() if l7_m else "generic"

    parts = [p for p in (family_part, fool_part, ttl_part, extra_part, l7) if p]
    return "+".join(parts)


# ---------------------------------------------------------------------------
# Scoring / selection
# ---------------------------------------------------------------------------

_SCORE_MIN, _SCORE_MAX = -20.0, 20.0
_DECAY = 0.98
_SUCCESS_DELTA = 1.0
_FAIL_DELTA    = -2.0
_IMPLICATE_DELTA = -3.0   # a live TSPУ cut is stronger evidence than a shadow-test fail


class VectorScorer:
    """
    Same +success/-failure/decay scoring PoolSwitcher already used for
    individual strategies, applied in parallel to their vector, plus a
    time-boxed "implicated" flag per vector for live-cut evidence.
    """

    def __init__(self, vector_cooldown_sec=600):
        self.strategy_scores = {}
        self.vector_scores   = {}
        self.vector_ok       = collections.Counter()
        self.vector_cuts     = collections.Counter()
        self.vector_cooldown_sec = float(vector_cooldown_sec)
        self._implicated_until = {}   # vector -> ts until which it's deprioritized

    # -- scoring --------------------------------------------------------

    @staticmethod
    def _clamp(v):
        return max(_SCORE_MIN, min(_SCORE_MAX, v))

    def _decay(self, table):
        for k in list(table):
            table[k] = self._clamp(table[k] * _DECAY)

    def decay_all(self):
        self._decay(self.strategy_scores)
        self._decay(self.vector_scores)

    def bump(self, name, vector, ok):
        """Record a shadow-test (or journal-replayed) outcome."""
        delta = _SUCCESS_DELTA if ok else _FAIL_DELTA
        vector = vector or UNKNOWN_VECTOR
        if name:
            self.strategy_scores[name] = self._clamp(
                self.strategy_scores.get(name, 0.0) + delta)
        self.vector_scores[vector] = self._clamp(
            self.vector_scores.get(vector, 0.0) + delta)
        if ok:
            self.vector_ok[vector] += 1
        else:
            self.vector_cuts[vector] += 1

    def implicate(self, vector, now=None):
        """
        Mark a vector as the likely current TSPУ target after a *live*
        connection cut (stronger signal than a shadow-test failure): push
        its score down harder and deprioritize it for vector_cooldown_sec,
        regardless of how its score recovers via decay in the meantime.
        """
        if not vector:
            return
        now = now if now is not None else time.time()
        self.vector_scores[vector] = self._clamp(
            self.vector_scores.get(vector, 0.0) + _IMPLICATE_DELTA)
        self.vector_cuts[vector] += 1
        self._implicated_until[vector] = now + self.vector_cooldown_sec

    def is_implicated(self, vector, now=None):
        now = now if now is not None else time.time()
        until = self._implicated_until.get(vector)
        return bool(until and now < until)

    def vector_hazard(self, vector):
        """Share of recorded outcomes for this vector that were failures/cuts."""
        ok, cuts = self.vector_ok[vector], self.vector_cuts[vector]
        total = ok + cuts
        return (cuts / total) if total else 0.0

    # -- selection --------------------------------------------------------

    def rank_candidates(self, strategies, avoid_vector=None, now=None):
        """
        strategies: iterable of dicts with at least 'name' and 'nfqws_opt'.
        Returns a new list of shallow copies, each annotated with '_vector',
        ordered so that:
          1. vectors that are currently implicated (cooling down after a
             live cut) or explicitly passed as avoid_vector sort LAST —
             but are still included, so selection never stalls just
             because every remaining candidate happens to share that
             vector,
          2. among the rest, higher vector score first,
          3. then higher individual strategy score first.
        """
        now = now if now is not None else time.time()
        out = []
        for s in strategies:
            v = classify_vector(s.get("nfqws_opt")) or UNKNOWN_VECTOR
            out.append(dict(s, _vector=v))

        def key(s):
            v = s["_vector"]
            deprioritize = bool(self.is_implicated(v, now) or (avoid_vector and v == avoid_vector))
            return (
                deprioritize,                                     # False < True
                -self.vector_scores.get(v, 0.0),
                -self.strategy_scores.get(s["name"], 0.0),
            )

        out.sort(key=key)
        return out

    def diversified_batch(self, strategies, n, avoid_vector=None, now=None):
        """
        Pick up to n candidates, maximizing vector diversity: round-robin
        across vectors (best-ranked strategy from each) before taking a
        second strategy from any vector. This means a 3-attempt shadow-test
        budget after a cut tries 3 *different* techniques when possible,
        instead of 3 siblings of whatever just failed.
        """
        ranked = self.rank_candidates(strategies, avoid_vector, now)
        by_vector = collections.OrderedDict()
        for s in ranked:
            by_vector.setdefault(s["_vector"], []).append(s)

        out = []
        while len(out) < n and by_vector:
            for v in list(by_vector.keys()):
                if len(out) >= n:
                    break
                bucket = by_vector[v]
                out.append(bucket.pop(0))
                if not bucket:
                    del by_vector[v]
        return out

    # -- persistence: rebuild from the tspУ.log journal --------------------

    def seed_from_journal(self, events, vector_for_name):
        """
        Replay tspУ_log events (as returned by TspuLog.get_recent()) in
        chronological order to reconstruct strategy/vector scores across a
        panel restart, instead of starting cold every time despite the
        journal already holding this history.

        vector_for_name: callable(strategy_name) -> vector | None, used to
        classify events that only recorded the strategy name (all of them,
        historically) rather than the raw NFQWS2_OPT text.
        """
        for ev in sorted(events, key=lambda e: e.get("ts", 0)):
            et = ev.get("event")
            if et in ("cut", "idle"):
                slot = ev.get("slot") or {}
                name = slot.get("strategy")
                if not name:
                    continue
                vector = vector_for_name(name)
                self.bump(name, vector, ok=False)
                if vector:
                    # historical replay: treat past cuts as having implicated
                    # their vector too, so a strategy that's been cut
                    # repeatedly doesn't look neutral right after a restart.
                    self.implicate(vector, now=ev.get("ts"))
            elif et == "test_ok":
                name = ev.get("strategy")
                if name:
                    self.bump(name, vector_for_name(name), ok=True)
            elif et == "test_fail":
                name = ev.get("strategy")
                if name:
                    self.bump(name, vector_for_name(name), ok=False)