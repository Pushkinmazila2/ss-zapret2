# One-shot patch: show active connections (not only traffic) in panel/index.html
import re, sys

PATH = "panel/index.html"

def rd(p):
    with open(p, "r", encoding="utf-8") as f:
        return f.read()

def wr(p, s):
    with open(p, "w", encoding="utf-8", newline="") as f:
        f.write(s.replace(chr(10), chr(13) + chr(10)))

def die(path, i, n):
    print("FAIL %s rule#%d matched %d times" % (path, i, n))
    sys.exit(1)

src = rd(PATH)
i = 0

def rep(old, new):
    global src, i
    n = src.count(old)
    if n != 1: die(PATH, i, n)
    src = src.replace(old, new, 1); i += 1

def rex(pat, repl):
    global src, i
    ms = list(re.finditer(pat, src))
    if len(ms) != 1: die(PATH, i, len(ms))
    m = ms[0]
    src = src[:m.start()] + repl(m) + src[m.end():]; i += 1

# 2a. addEdge signature
rep("  function addEdge(a, b, cat, color, slots, traf){",
    "  function addEdge(a, b, cat, color, slots, traf, conns){")

# 2b. edge accumulator init
rep("    if(!e){ e = { from:a, to:b, cat, color, strength:0, slots:[] }; edgeMap.set(id, e); }",
    "    if(!e){ e = { from:a, to:b, cat, color, strength:0, conns:0, slots:[] }; edgeMap.set(id, e); }")

# 2c. accumulate conns
rep("    e.strength += traf;",
    "    e.strength += traf;\n    e.conns    += conns;")

# 3. per-strategy conns
rep('''    const traf  = slots.reduce((sum, sl) => {
      const t = _traffic[sl.qnum] || {};
      return sum + (t.kbps || 0);
    }, 0);''',
'''    const traf  = slots.reduce((sum, sl) => {
      const t = _traffic[sl.qnum] || {};
      return sum + (t.kbps || 0);
    }, 0);
    // connections pinned to this strategy via its slots (connmark) -
    // active even when pkts_delta == 0
    const conns = slots.reduce((sum, sl) => sum + ((_traffic[sl.qnum] || {}).conns || 0), 0);''')

# 4. pass conns into addEdge calls
rep("      if(inN  && first) addEdge(inN,  first, 'in',  IN_COLOR,  slots, traf);",
    "      if(inN  && first) addEdge(inN,  first, 'in',  IN_COLOR,  slots, traf, conns);")
rep("      if(outN && last)  addEdge(last, outN,  'out', OUT_COLOR, slots, traf);",
    "      if(outN && last)  addEdge(last, outN,  'out', OUT_COLOR, slots, traf, conns);")
rep("      addEdge(a, b, path[i].cat, vecColor(path[i].cat), slots, traf);",
    "      addEdge(a, b, path[i].cat, vecColor(path[i].cat), slots, traf, conns);")

# 5. final edge map
rep('''  _edges = [...edgeMap.values()].map(e => ({
    from: e.from, to: e.to, cat: e.cat, color: e.color,
    strength: e.strength, slots: e.slots,
    live: e.strength > 0.1,
  }));''',
'''  _edges = [...edgeMap.values()].map(e => ({
    from: e.from, to: e.to, cat: e.cat, color: e.color,
    strength: e.strength, conns: e.conns, slots: e.slots,
    flowing: e.strength > 0.1,
    // beam stays live while traffic flows OR active connections exist
    live: e.strength > 0.1 || e.conns > 0,
  }));''')

# 6a. edge draw: opening of the live branch
rep('''    ctx.save();
    ctx.lineWidth = e.live ? Math.min(3, 1 + e.strength/50) : 1;
    if(e.live){''',
'''    ctx.save();
    if(e.live && e.flowing){
      // packets are flowing - animated beam
      ctx.lineWidth = Math.min(3, 1 + e.strength/50);''')

# 6b. edge draw: connected-but-idle branch
rep('''      ctx.closePath();
      ctx.fillStyle = col;
      ctx.fill();
    } else {
      ctx.strokeStyle = col + '44';''',
'''      ctx.closePath();
      ctx.fillStyle = col;
      ctx.fill();
    } else if(e.live){
      // connections established but no packets right now -
      // calm solid beam with a static arrow head
      ctx.lineWidth = 1.5;
      ctx.strokeStyle = col;
      ctx.globalAlpha = .30;
      ctx.beginPath(); ctx.moveTo(x1,y1); ctx.lineTo(x2,y2); ctx.stroke();
      const ang = Math.atan2(y2-y1, x2-x1);
      const al  = 8 * _cam.scale;
      ctx.globalAlpha = .45;
      ctx.beginPath();
      ctx.moveTo(x2, y2);
      ctx.lineTo(x2 - al*Math.cos(ang-.4), y2 - al*Math.sin(ang-.4));
      ctx.lineTo(x2 - al*Math.cos(ang+.4), y2 - al*Math.sin(ang+.4));
      ctx.closePath();
      ctx.fillStyle = col;
      ctx.fill();
    } else {
      ctx.lineWidth = 1;
      ctx.strokeStyle = col + '44';''')

# 7. port nodes glow on connections too
rep("      const liveAny = n.slots.some(sl => (_traffic[sl.qnum] || {}).pkts_delta > 0);",
    "      const liveAny = n.slots.some(sl => (_traffic[sl.qnum] || {}).pkts_delta > 0\n                                    || ((_traffic[sl.qnum] || {}).conns || 0) > 0);")

# 8. node dot: cyan when connected but idle
rep('''    const anyLive = n.slots.some(sl => (_traffic[sl.qnum] || {}).pkts_delta > 0);
    if(anyLive){
      const pulse = .5 + .5 * Math.sin(ts / 220);
      ctx.beginPath(); ctx.arc(nx, ny, 3 * _cam.scale, 0, Math.PI*2);
      ctx.fillStyle = `rgba(39,201,122,${.5 + .5*pulse})`;
      ctx.fill();
    }''',
'''    const anyLive = n.slots.some(sl => (_traffic[sl.qnum] || {}).pkts_delta > 0);
    const anyConn = !anyLive && n.slots.some(sl => ((_traffic[sl.qnum] || {}).conns || 0) > 0);
    if(anyLive){
      const pulse = .5 + .5 * Math.sin(ts / 220);
      ctx.beginPath(); ctx.arc(nx, ny, 3 * _cam.scale, 0, Math.PI*2);
      ctx.fillStyle = `rgba(39,201,122,${.5 + .5*pulse})`;
      ctx.fill();
    } else if(anyConn){
      ctx.beginPath(); ctx.arc(nx, ny, 2.5 * _cam.scale, 0, Math.PI*2);
      ctx.fillStyle = 'rgba(79,214,255,.75)';
      ctx.fill();
    }''')

# 9. tooltip: connsSum
rep('''  const trafSum = n.slots.reduce((s, sl) => s + ((_traffic[sl.qnum] || {}).kbps || 0), 0);
  const isPort = n.key === '__in' || n.key === '__out';''',
'''  const trafSum = n.slots.reduce((s, sl) => s + ((_traffic[sl.qnum] || {}).kbps || 0), 0);
  const connsSum = n.slots.reduce((s, sl) => s + ((_traffic[sl.qnum] || {}).conns || 0), 0);
  const isPort = n.key === '__in' || n.key === '__out';''')

# 10. tooltip in-pool row: append connections (Russian labels as JS unicode escapes)
rex(r"(trafSum\.toFixed\(1\) \+ ' kbps')( : )",
    lambda m: m.group(1) + r" + (connsSum ? ' \u00b7 ' + connsSum + ' \u0441\u043e\u0435\u0434.' : '')" + m.group(2))

# 11. tooltip slots row: per-slot connection counts
rex(r"(?m)^(  if\(n\.slots\.length\) rows \+= row\(')([^']*)(', n\.slots\.map\(sl => ')([^']*)(' \+ sl\.index\)\.join\(' '\)\);)$",
    lambda m: m.group(1) + m.group(2) + m.group(3) + "{ const c = ((_traffic[sl.qnum] || {}).conns || 0); return '" + m.group(4) + "' + sl.index + (c ? ':' + c : ''); }).join(' '));")

# 12. detail: connsSum
rep('''  const trafSum = n.slots.reduce((s, sl) => s + ((_traffic[sl.qnum] || {}).kbps || 0), 0);
  const hasFail = n.slots.some(sl => sl.healthy === false);''',
'''  const trafSum = n.slots.reduce((s, sl) => s + ((_traffic[sl.qnum] || {}).kbps || 0), 0);
  const connsSum = n.slots.reduce((s, sl) => s + ((_traffic[sl.qnum] || {}).conns || 0), 0);
  const hasFail = n.slots.some(sl => sl.healthy === false);''')

# 13. detail: new row (label as JS unicode escapes)
rex(r"(?m)^(  g \+= drow\('[^']*', n\.slotCount\);\n)",
    lambda m: m.group(1) + r"  g += drow('\u0430\u043a\u0442\u0438\u0432\u043d\u044b\u0445 \u0441\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u0439', connsSum);" + "\n")

wr(PATH, src)
print("OK %s (%d rules)" % (PATH, i))
