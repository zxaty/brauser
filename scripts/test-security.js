'use strict';
// Проверки исправлений безопасности, не требующие сети и Electron.
// Запуск:  node scripts/test-security.js [путь к tor]
// С путём к бинарнику Tor дополнительно проверяется, что собранная
// конфигурация принимается самим Tor (tor --verify-config).

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { parseProxy } = require('../src/proxy');
const { TorManager } = require('../src/tor');

const torBin = process.argv[2];
// Tor из поставки Tor Browser несёт свои библиотеки рядом с бинарником.
if (torBin && process.platform !== 'win32') process.env.LD_LIBRARY_PATH = path.dirname(torBin);
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'brauser-test-'));
const tor = new TorManager({ dataDir });
const paths = { tor: torBin || 'tor', lyrebird: path.join(dataDir, 'none'), geoipDir: dataDir };
const build = (options) => tor._buildConfig(paths, options);
let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log('ok  ' + name); };

check('перенос строки в пароле прокси отклоняется', () => {
  assert.strictEqual(parseProxy('http://u:p%0ACookieAuthentication%200@127.0.0.1:8080'), null);
  assert.strictEqual(parseProxy('socks5://u%0D%0AControlPort%209:p@127.0.0.1:1080'), null);
  assert.strictEqual(parseProxy('http://u:p%00@127.0.0.1:8080'), null);
  assert.strictEqual(parseProxy('http://u:%E2%80%A8x@127.0.0.1:8080'), null);
});

check('оборванная %-последовательность и слишком длинные данные отклоняются', () => {
  assert.strictEqual(parseProxy('http://u:p%E0%A4%A@127.0.0.1:8080'), null);
  assert.strictEqual(parseProxy('http://u:' + 'a'.repeat(256) + '@127.0.0.1:8080'), null);
});

check('обычные адреса прокси разбираются как раньше', () => {
  assert.deepStrictEqual(
    (({ scheme, host, port, username, password }) => ({ scheme, host, port, username, password }))(parseProxy('socks5://user:pa%20ss%23@proxy.example.org:1080')),
    { scheme: 'socks5', host: 'proxy.example.org', port: 1080, username: 'user', password: 'pa ss#' },
  );
  assert.strictEqual(parseProxy('127.0.0.1:8080').scheme, 'http');
  assert.strictEqual(parseProxy('socks5://[::1]:9050').host, '[::1]');
});

check('конфигурация с отклонённым прокси не собирается', () => {
  assert.throws(() => build({ upstreamProxy: 'http://u:p%0ACookieAuthentication%200@127.0.0.1:8080' }), /прокси/);
});

check('ни одна строка конфигурации не содержит управляющих символов', () => {
  const config = build({ upstreamProxy: 'socks5://us er:p"a\\ss%20%23x@127.0.0.1:1080', bridges: 'obfs4 1.2.3.4:443 AAAA\r\n\rBridge 5.6.7.8:443', exitCountry: 'de' });
  for (const line of config.trimEnd().split('\n')) assert.ok(!/[\p{Cc}\p{Zl}\p{Zp}]/u.test(line), line);
  assert.ok(config.includes('Socks5ProxyPassword "p\\"a\\\\ss #x"'), config);
  assert.ok(config.includes('CookieAuthentication 1'));
  assert.strictEqual((config.match(/^CookieAuthentication/gm) || []).length, 1);
});

check('управляющий символ в мосте останавливает сборку конфигурации', () => {
  assert.throws(() => build({ bridges: 'obfs4 1.2.3.4:443' + String.fromCharCode(11) + 'CookieAuthentication 0' }), /недопустимые символы/);
});

check('код страны выхода не пропускает лишнего', () => {
  assert.ok(!build({ exitCountry: 'de\nControlPort 1' }).includes('ExitNodes'));
});

if (torBin) {
  check('Tor принимает собранную конфигурацию из stdin', () => {
    const config = build({ upstreamProxy: 'socks5://us er:p"a\\ss%20%23x@127.0.0.1:1080', exitCountry: 'de' });
    const res = spawnSync(torBin, ['--verify-config', '-f', '-'], { input: config, encoding: 'utf8' });
    assert.strictEqual(res.status, 0, res.stdout + res.stderr);
  });
  check('Tor читает пароль прокси ровно таким, каким он задан', () => {
    const config = build({ upstreamProxy: 'http://user:p%22a%5Css%20%23x@127.0.0.1:8080' });
    const res = spawnSync(torBin, ['--verify-config', '-f', '-', '--dump-config', 'short'], { input: config, encoding: 'utf8' });
    assert.ok((res.stdout + res.stderr).includes('HTTPSProxyAuthenticator "user:p\\"a\\\\ss #x"'), res.stdout + res.stderr);
  });
}

// ---------------------------------------------------------------- пути и мосты

const WIN = process.platform === 'win32';
const verify = (config) => spawnSync(torBin, ['--verify-config', '-f', '-'], { input: config, encoding: 'utf8', env: { ...process.env, LD_LIBRARY_PATH: path.dirname(torBin) } });
// Имена каталогов, которые раньше ломали или искажали конфигурацию.
const oddNames = ['с пробелом и юникодом', "it's#1"].concat(WIN ? [] : ['quo"te', 'back\\slash']);

for (const name of oddNames) {
  check(`путь данных «${name}» записывается в конфигурацию без искажений`, () => {
    const odd = path.join(dataDir, name);
    fs.mkdirSync(odd, { recursive: true });
    fs.writeFileSync(path.join(odd, 'geoip'), '');
    const t = new TorManager({ dataDir: odd });
    const config = t._buildConfig({ tor: torBin || 'tor', lyrebird: path.join(odd, 'none'), geoipDir: odd }, {});
    if (!torBin) return;
    const res = spawnSync(torBin, ['--verify-config', '-f', '-', '--dump-config', 'short'], { input: config, encoding: 'utf8', env: { ...process.env, LD_LIBRARY_PATH: path.dirname(torBin) } });
    assert.strictEqual(res.status, 0, res.stdout + res.stderr);
    // Tor должен увидеть ровно тот путь, который мы задали.
    const expected = path.join(odd, 'control_auth_cookie');
    const dumped = (res.stdout.match(/^CookieAuthFile (.*)$/m) || [])[1] || '';
    // Tor печатает значение в кавычках с C-экранированием: \" \\ и \ooo для байтов вне ASCII.
    const bytes = [];
    const body = dumped.startsWith('"') ? dumped.slice(1, -1) : dumped;
    for (let i = 0; i < body.length; i++) {
      const oct = body[i] === '\\' && /^[0-7]{3}$/.test(body.slice(i + 1, i + 4));
      if (oct) { bytes.push(parseInt(body.slice(i + 1, i + 4), 8)); i += 3; }
      else if (body[i] === '\\' && dumped.startsWith('"')) { bytes.push(body.charCodeAt(++i)); }
      else bytes.push(...Buffer.from(body[i]));
    }
    const unquoted = Buffer.from(bytes).toString('utf8');
    assert.strictEqual(unquoted, expected);
  });
}

check('транспорт мостов задаётся относительным путём без кавычек', () => {
  const torDir = path.join(dataDir, 'папка с пробелом', 'Tor');
  const exe = WIN ? 'lyrebird.exe' : 'lyrebird';
  fs.mkdirSync(path.join(torDir, 'PluggableTransports'), { recursive: true });
  fs.writeFileSync(path.join(torDir, 'PluggableTransports', exe), '');
  const config = tor._buildConfig({ tor: path.join(torDir, 'tor'), lyrebird: path.join(torDir, 'PluggableTransports', exe), geoipDir: dataDir }, { bridges: 'obfs4 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abc iat-mode=0' });
  assert.ok(config.includes(`ClientTransportPlugin meek_lite,obfs2,obfs3,obfs4,scramblesuit,webtunnel exec ./PluggableTransports/${exe}\n`), config);
  if (torBin) assert.strictEqual(verify(config).status, 0, verify(config).stdout);
});

// ---------------------------------------------------------------- разбор ответов control-порта

const { ReplyReader } = require('../src/tor');
const readAll = (chunks) => {
  const replies = [];
  let overflow = false;
  const reader = new ReplyReader((r) => replies.push(r), () => { overflow = true; });
  for (const c of chunks) reader.push(c);
  return { replies, overflow };
};

check('многострочные ответы, блоки данных и события разбираются по отдельности', () => {
  const { replies } = readAll([
    '250-version=0.4.9\r\n250 OK\r\n',
    '250+circuit-status=\r\n1 BUILT $AAAA~a\r\n..starts-with-dot\r\n250 not-a-status-line\r\n.\r\n250 OK\r\n',
    '650 STREAM 5 SENTCONN', 'ECT 7 example.org:443\r\n552 Unrecognized\r\n',
  ]);
  assert.deepStrictEqual(replies.map((r) => r.code), ['250', '250', '650', '552']);
  assert.deepStrictEqual(replies[1].lines, ['circuit-status=', '1 BUILT $AAAA~a', '.starts-with-dot', '250 not-a-status-line', 'OK']);
  assert.strictEqual(replies[2].lines[0], 'STREAM 5 SENTCONNECT 7 example.org:443');
});

check('бесконечный ответ обрывается по пределу размера', () => {
  const big = 'x'.repeat(1024 * 1024);
  const { replies, overflow } = readAll(['250+data=\r\n', big, big, big, big, big]);
  assert.strictEqual(overflow, true);
  assert.strictEqual(replies.length, 0);
});

if (!WIN) {
  check('сокеты Tor лежат в коротком каталоге только для владельца', () => {
    const t = new TorManager({ dataDir: path.join(dataDir, 'с пробелом и юникодом') });
    assert.strictEqual(t.transport, 'unix');
    t._prepareSocketDir();
    const other = new TorManager({ dataDir });
    other._prepareSocketDir();
    // Без личного каталога сеанса имя случайное: два менеджера не делят один каталог.
    if (!process.env.XDG_RUNTIME_DIR) assert.notStrictEqual(other.socketDir, t.socketDir);
    other.dispose();
    const st = fs.lstatSync(t.ipc.dir);
    assert.ok(st.isDirectory() && st.uid === process.getuid() && (st.mode & 0o077) === 0, t.ipc.dir);
    assert.ok(/^[A-Za-z0-9._/+-]+$/.test(t.ipc.dir) && Buffer.byteLength(t.ipc.control) <= 100, t.ipc.dir);
    // Каталог, открытый посторонним и чужой для нас, использовать нельзя; свой — закрывается.
    fs.chmodSync(t.ipc.dir, 0o777);
    t._prepareSocketDir();
    assert.strictEqual(fs.lstatSync(t.ipc.dir).mode & 0o077, 0);
    const dir = t.socketDir;
    fs.rmSync(dir, { recursive: true, force: true });
    fs.symlinkSync(dataDir, dir);
    assert.throws(() => t._prepareSocketDir(), /каталог сокетов/);
    fs.rmSync(t.socketDir, { force: true });
  });
}

fs.rmSync(dataDir, { recursive: true, force: true });
console.log(`\nвсе проверки пройдены: ${passed}`);
