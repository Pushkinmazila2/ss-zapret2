// Валидация панели: синтаксис JS + тест парсера атрибутов на примере юзера.
const fs   = require('fs');
const html = fs.readFileSync('panel/index.html', 'utf8');
const lines = html.split(/\r?\n/);

// 1) извлекаем весь <script> и проверяем синтаксис
const start = lines.findIndex(l => l.trim() === '<script>');
const end   = lines.findIndex((l, i) => i > start && l.trim() === '</script>');
const src   = lines.slice(start + 1, end).join('\n');
new Function(src);   // бросит SyntaxError при ошибке
console.log('S01 script syntax OK, lines:', end - start - 1);

// 2) извлекаем парсер и тестируем на примере пользователя
const p0 = src.indexOf('const _CAT_ORDER');
const p1 = src.indexOf('// ════', p0);
const parser = src.slice(p0, p1);
const { parseStrategyAttrs } = new Function(parser + '; return { parseStrategyAttrs };')();

const strs = [
  {
    name: 's1',
    opt: '--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:ip_autottl=-4,3-20:tls_mod=rnd,dupsid,padencap:repeats=1',
  },
  {
    name: 's2',
    opt: '--payload=tls_client_hello --lua-desync=fake:blob=0x00000000:badsum:repeats=1 --lua-desync=fakeddisorder:pos=midsld:badsum',
  },
  {
    name: 's3',
    opt: '--payload=tls_client_hello --lua-desync=fake:blob=0x00000000:tcp_seq=1000000:repeats=1 --lua-desync=fakeddisorder:pos=midsld:tcp_seq=1000000',
  },
];

const sets = {};
for(const s of strs){
  sets[s.name] = parseStrategyAttrs(s.opt).map(a => a.label);
  console.log('S02', s.name, '->', sets[s.name].join(' | '));
}

// пересечения (одинаковые точки)
const all = (s) => new Set(sets[s]);
const common123 = [...all('s1')].filter(x => all('s2').has(x) && all('s3').has(x));
const common23   = [...all('s2')].filter(x => all('s3').has(x));
console.log('S03 точки общие у 3 стратегий:', common123.join(', ') || '(нет)');
console.log('S04 точки общие у s2 и s3:', common23.join(', '));

// ожидания: общие у 3 — payload, desync=fake, repeats=1; общие у s2/s3 — blob=0x00000000, pos=midsld
const exp3 = new Set(['payload=tls_client_hello', 'desync=fake', 'repeats=1']);
const exp23 = new Set(['blob=0x00000000', 'pos=midsld']);
const ok3  = exp3.every(x => common123.includes(x));
const ok23 = exp23.every(x => common23.includes(x));
console.log(ok3 ? 'PASS' : 'FAIL', 'S03');
console.log(ok23 ? 'PASS' : 'FAIL', 'S04');
process.exit(ok3 && ok23 ? 0 : 1);