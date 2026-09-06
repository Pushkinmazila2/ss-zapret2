// Валидация панели: JS-синтаксис + конвейер графа (только активные, порты, рёбра).
const fs = require('fs');
const html = fs.readFileSync('panel/index.html', 'utf8');
const lines = html.split(/\r?\n/);

// ── 1) весь <script>: синтаксис ──
const start = lines.findIndex(l => l.trim() === '<script>');
const end   = lines.findIndex((l, i) => i > start && l.trim() === '</script>');
const src   = lines.slice(start + 1, end).join('\n');
new Function(src);
console.log('S01 script syntax OK, lines:', end - start - 1);

// ── 2) вырезаем чистые функции из реального файла ──
const p0 = src.indexOf('const _CAT_ORDER');          // начало парсера
const pA = src.indexOf('function activeStrategies'); // конец парсера
const pB = src.indexOf('function buildEdges');       // начало рёбер
const pE = src.indexOf('// ── Draw');                // конец buildEdges
const parserSrc = src.slice(p0, pA);
const edgesSrc  = src.slice(pB, pE);

// окружение, в котором работает buildEdges из index.html
const _slots=[], _strategies=[], _nodes=[], _traffic={};
let _edges=[];
function activeStrategies(){
  const names=[...new Set(_slots.filter(s=>s&&s.strategy).map(s=>s.strategy))];
  const byName={}; for(const s of _strategies) byName[s.name]=s;
  return names.map(nm=>byName[nm]).filter(Boolean);
}
function vecColor(){ return '#000'; }
const IN_COLOR='#4fd6ff', OUT_COLOR='#27c97a';

const api = new Function('_slots','_strategies','_nodes','_traffic','activeStrategies','vecColor','IN_COLOR','OUT_COLOR',
  parserSrc + '\n' + edgesSrc +
  '\nreturn { parseStrategyAttrs, buildEdges };')(
  _slots,_strategies,_nodes,_traffic,activeStrategies,vecColor,IN_COLOR,OUT_COLOR);
const { parseStrategyAttrs, buildEdges } = api;

// ── 3) зеркало rebuildNodes (только агрегация; отрисовка не нужна) ──
function rebuildMirror(){
  const usage = new Map();
  for(const s of activeStrategies()){
    s._attrs = parseStrategyAttrs(s.nfqws_opt);
    for(const a of s._attrs){
      let u = usage.get(a.key);
      if(!u){ u={count:0, strategies:new Set()}; usage.set(a.key,u); }
      u.count++; u.strategies.add(s.name);
    }
  }
  _nodes.length = 0;
  for(const [key,u] of usage){
    _nodes.push({ key, cat:key.split(':')[0], count:u.count, strategies:[...u.strategies] });
  }
  const act = activeStrategies();
  if(act.length){
    _nodes.push({ key:'__in',  cat:'in',  count:act.length, strategies:[] });
    _nodes.push({ key:'__out', cat:'out', count:act.length, strategies:[] });
  }
}

// ── 4) данные: 3 активные + 1 резервная ──
const DATA = {
  s1: '--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:ip_autottl=-4,3-20:tls_mod=rnd,dupsid,padencap:repeats=1',
  s2: '--payload=tls_client_hello --lua-desync=fake:blob=0x00000000:badsum:repeats=1 --lua-desync=fakeddisorder:pos=midsld:badsum',
  s3: '--payload=tls_client_hello --lua-desync=fake:blob=0x00000000:tcp_seq=1000000:repeats=1 --lua-desync=fakeddisorder:pos=midsld:tcp_seq=1000000',
  s4: '--dpi-desync=fake-frag+fakedsplit --dpi-desync-any-protocol --filter-tcp=80',  // резервная/неактивная
};
for(const [name, opt] of Object.entries(DATA)) _strategies.push({ name, nfqws_opt: opt });
for(let i = 0; i < 3; i++) _slots.push({ index:i, qnum:300+i, strategy:'s'+(i+1), healthy:true });

rebuildMirror();
buildEdges();
const keys = _nodes.map(n => n.key);
console.log('S02 nodes:', keys.join(', '));

// ── проверки ──
const fail = (m) => { console.log('FAIL', m); process.exitCode = 1; };
const pass = (m) => console.log('PASS', m);

// a) только активные стратегии (у s4 уникальные параметры не появляются)
const s4keys = ['desync-mode:fake-frag+fakedsplit', 'desync:dpi-desync-any-protocol', 'filter:filter-tcp=80'];
(s4keys.every(k => !keys.includes(k))) ? pass('S03 резервная стратегия не попала в граф')
                                       : fail('S03 недостаточно: ' + s4keys.filter(k=>keys.includes(k)).join(','));

// б) порты входа/выхода
(keys.includes('__in') && keys.includes('__out')) ? pass('S04 порты __in/__out присутствуют')
                                                  : fail('S04 порты отсутствуют');

// в) общие хаб-точки
const nPayload = _nodes.find(n => n.key === 'payload:tls_client_hello');
const nBlob    = _nodes.find(n => n.key === 'desync:blob=0x00000000');
const nTlsMod  = _nodes.find(n => n.key === 'desync:tls_mod=rnd,dupsid,padencap');
(nPayload && nPayload.count === 3) ? pass('S05 payload=tls_client_hello используется 3 активными (count=' + nPayload.count + ')') : fail('S05 payload');
(nBlob && nBlob.count === 2) ? pass('S06 blob=0x00000000 у 2 стратегий') : fail('S06 blob');
(nTlsMod && nTlsMod.count === 1) ? pass('S07 tls_mod=rnd,dupsid,padencap только у s1') : fail('S07 tls_mod');

// г) рёбра: вход→первый параметр, последний→выход, цепочки между параметрами
const eIn  = _edges.find(e => e.from.key === '__in');
const eOut = _edges.find(e => e.to.key === '__out');
const chain = _edges.filter(e => e.from.key !== '__in' && e.to.key !== '__out');
(eIn && eIn.to.key === 'payload:tls_client_hello') ? pass('S08 вход→payload (' + eIn.strength + ' kbps)') : fail('S08 ребро входа: ' + (eIn ? eIn.to.key : 'нет'));
(eOut) ? pass('S09 последний параметр→выход') : fail('S09 ребро выхода');
(chain.length > 0) ? pass('S10 цепочечных рёбер: ' + chain.length) : fail('S10 нет цепочек');

// д) порядок в цепочке: первый токен — payload (категория сортируется первой)
const firstS1 = parseStrategyAttrs(DATA.s1)[0];
(firstS1.label === 'payload=tls_client_hello') ? pass('S11 первый атрибут s1: ' + firstS1.label) : fail('S11 первый атрибут');

if(!process.exitCode) console.log('ALL PASS');