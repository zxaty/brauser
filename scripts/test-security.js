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

fs.rmSync(dataDir, { recursive: true, force: true });
console.log(`\nвсе проверки пройдены: ${passed}`);
