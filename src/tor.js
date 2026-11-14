'use strict';
// Запуск и управление собственным процессом Tor.
// Браузер не использует системный Tor: он поднимает свой экземпляр на
// отдельных портах и общается с ним через control-порт.

const { EventEmitter } = require('node:events');
const { spawn } = require('node:child_process');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');

const SOCKS_PORT = 9250;
const CONTROL_PORT = 9251;

const fwd = (p) => p.replace(/\\/g, '/');

class TorManager extends EventEmitter {
  constructor({ dataDir, appDir }) {
    super();
    this.dataDir = dataDir;
    this.appDir = appDir;
    this.proc = null;
    this.status = 'stopped'; // stopped | missing | starting | ready | error
    this.progress = 0;
    this.message = '';
    this.lastNewnym = 0;
    this.events = null;       // постоянное соединение с control-портом для событий
    this.lastCircuitId = null; // цепочка, по которой ушло последнее соединение
  }

  get socksRules() { return `socks5://127.0.0.1:${SOCKS_PORT}`; }

  _set(status, message = '', progress = this.progress) {
    this.status = status;
    this.message = message;
    this.progress = progress;
    this.emit('change');
  }

  findBinary(custom) {
    const exe = process.platform === 'win32' ? 'tor.exe' : 'tor';
    const candidates = [
      custom,
      path.join(this.appDir, process.platform === 'linux' ? 'tor-linux' : 'tor', 'tor', exe),
      path.join(this.appDir, 'tor', 'tor', exe),
      path.join(this.appDir, 'tor', exe),
    ].filter(Boolean);
    for (const c of candidates) {
      try { if (fs.statSync(c).isFile()) return c; } catch { /* нет файла */ }
    }
    return null;
  }

  // На Linux файл может оказаться без права на запуск (например, пакет собран
  // под Windows) и лежать в каталоге только для чтения. Тогда копируем Tor
  // в папку данных пользователя и запускаем оттуда.
  _ensureExecutable(bin) {
    if (process.platform === 'win32') return bin;
    const srcDir = path.dirname(bin);
    const check = (dir) => {
      for (const rel of [path.basename(bin), path.join('pluggable_transports', 'lyrebird')]) {
        const p = path.join(dir, rel);
        if (fs.existsSync(p)) fs.accessSync(p, fs.constants.X_OK);
      }
    };
    try { check(srcDir); return bin; } catch { /* нет права на запуск */ }
    const chmodAll = (dir) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) chmodAll(p); else fs.chmodSync(p, 0o755);
      }
    };
    try { chmodAll(srcDir); check(srcDir); return bin; } catch { /* каталог только для чтения */ }
    const copyDir = path.join(path.dirname(this.dataDir), 'tor-bin');
    fs.rmSync(copyDir, { recursive: true, force: true });
    fs.cpSync(srcDir, copyDir, { recursive: true });
    chmodAll(copyDir);
    return path.join(copyDir, path.basename(bin));
  }

  start({ torPath, bridges } = {}) {
    if (this.proc) return;
    const found = this.findBinary(torPath);
    let bin = found;
    if (!bin) {
      this._set('missing', 'tor.exe не найден — положите Tor Expert Bundle в папку tor/ или укажите путь в настройках', 0);
      return;
    }
    fs.mkdirSync(this.dataDir, { recursive: true });

    const lines = [
      `SocksPort 127.0.0.1:${SOCKS_PORT}`,
      `ControlPort 127.0.0.1:${CONTROL_PORT}`,
      'CookieAuthentication 1',
      `DataDirectory "${fwd(this.dataDir)}"`,
    ];
    const bundleRoot = path.dirname(path.dirname(found));
    try { bin = this._ensureExecutable(found); } catch (e) {
      this._set('error', 'Не удалось подготовить Tor к запуску: ' + e.message, 0);
      return;
    }
    for (const [opt, file] of [['GeoIPFile', 'geoip'], ['GeoIPv6File', 'geoip6']]) {
      const p = path.join(bundleRoot, 'data', file);
      if (fs.existsSync(p)) lines.push(`${opt} "${fwd(p)}"`);
    }
    const bridgeLines = String(bridges || '').split(/\r?\n/).map((l) => l.trim().replace(/^bridge\s+/i, '')).filter(Boolean);
    if (bridgeLines.length) {
      const pt = path.join(path.dirname(bin), 'pluggable_transports', process.platform === 'win32' ? 'lyrebird.exe' : 'lyrebird');
      lines.push('UseBridges 1');
      if (fs.existsSync(pt)) lines.push(`ClientTransportPlugin meek_lite,obfs4,scramblesuit,webtunnel exec "${fwd(pt)}"`);
      for (const b of bridgeLines) lines.push(`Bridge ${b}`);
    }
    const torrc = path.join(this.dataDir, 'torrc');
    fs.writeFileSync(torrc, lines.join('\n') + '\n');

    this._set('starting', 'Запуск Tor…', 0);
    // Linux-сборка Tor несёт свои библиотеки (libevent, libssl) рядом с бинарником.
    const env = { ...process.env };
    if (process.platform !== 'win32') env.LD_LIBRARY_PATH = [path.dirname(bin), env.LD_LIBRARY_PATH].filter(Boolean).join(':');
    const proc = spawn(bin, ['-f', torrc], { windowsHide: true, env });
    this.proc = proc;

    let buf = '';
    const onData = (chunk) => {
      buf += chunk.toString();
      const parts = buf.split(/\r?\n/);
      buf = parts.pop();
      for (const line of parts) {
        const m = line.match(/Bootstrapped (\d+)%[^:]*:\s*(.*)$/);
        if (m) {
          const pct = Number(m[1]);
          if (pct >= 100) { this._set('ready', 'Подключено', 100); this._watchStreams(); }
          else this._set('starting', m[2], pct);
        } else if (/\[err\]/.test(line)) {
          this.message = line.replace(/^.*\[err\]\s*/, '');
          this.emit('change');
        }
      }
    };
    proc.stdout.on('data', onData);
    proc.stderr.on('data', onData);
    proc.on('error', (err) => {
      if (this.proc === proc) this.proc = null;
      this._set('error', 'Не удалось запустить Tor: ' + err.message, 0);
    });
    proc.on('exit', (code) => {
      if (this.proc !== proc) return;
      this.proc = null;
      if (this.status !== 'stopped') {
        this._set('error', `Tor завершился (код ${code})${this.message ? ': ' + this.message : ''}`, 0);
      }
    });
  }

  // Подписка на события потоков: так мы знаем, по какой именно цепочке
  // реально ушёл последний запрос, и показываем в схеме её, а не случайную.
  _watchStreams() {
    if (this.events) return;
    let cookie;
    try { cookie = fs.readFileSync(path.join(this.dataDir, 'control_auth_cookie')).toString('hex'); } catch { return; }
    const sock = net.connect(CONTROL_PORT, '127.0.0.1');
    this.events = sock;
    let buf = '';
    sock.on('connect', () => sock.write(`AUTHENTICATE ${cookie}\r\nSETEVENTS STREAM\r\n`));
    sock.on('data', (d) => {
      buf += d.toString();
      const lines = buf.split(/\r?\n/);
      buf = lines.pop();
      for (const line of lines) {
        const m = line.match(/^650 STREAM \d+ SUCCEEDED (\d+) /);
        if (m && m[1] !== '0') this.lastCircuitId = m[1];
      }
    });
    const drop = () => { if (this.events === sock) this.events = null; };
    sock.on('error', drop);
    sock.on('close', drop);
  }

  stop() {
    if (this.events) { this.events.destroy(); this.events = null; }
    this.lastCircuitId = null;
    const proc = this.proc;
    this.proc = null;
    if (proc) { try { proc.kill(); } catch { /* уже завершён */ } }
    if (this.status !== 'missing') this._set('stopped', '', 0);
  }

  // Отправляет команды на control-порт и возвращает сырой ответ Tor.
  control(commands) {
    const cookie = fs.readFileSync(path.join(this.dataDir, 'control_auth_cookie')).toString('hex');
    return new Promise((resolve, reject) => {
      const sock = net.connect(CONTROL_PORT, '127.0.0.1');
      let out = '';
      const timer = setTimeout(() => { sock.destroy(); reject(new Error('Tor не ответил на control-порту')); }, 5000);
      sock.on('connect', () => sock.write([`AUTHENTICATE ${cookie}`, ...commands, 'QUIT', ''].join('\r\n')));
      sock.on('data', (d) => { out += d.toString(); });
      sock.on('error', (e) => { clearTimeout(timer); reject(e); });
      sock.on('close', () => {
        clearTimeout(timer);
        /^250 OK/m.test(out) ? resolve(out) : reject(new Error('Tor отклонил команду: ' + out.trim().split(/\r?\n/)[0]));
      });
    });
  }

  // Возвращает текущую цепочку: входной, промежуточный и выходной узлы с IP и
  // страной. Если известен внешний IP, выбирается цепочка с таким выходом,
  // иначе — самая свежая.
  async circuit(exitIpHint) {
    if (this.status !== 'ready') return null;
    const raw = await this.control(['GETINFO circuit-status']);
    const circuits = [];
    for (const line of raw.split(/\r?\n/)) {
      const m = line.match(/^(\d+) BUILT (\S+) (.*)$/);
      // CONFLUX_LINKED — «сдвоенные» цепочки новых версий Tor, обычный трафик часто идёт по ним.
      if (!m || !/PURPOSE=(GENERAL|CONFLUX_LINKED)\b/.test(m[3])) continue;
      const hops = m[2].split(',').map((h) => {
        const [fp, nickname] = h.replace(/^\$/, '').split(/[~=]/);
        return { fp, nickname: nickname || '' };
      });
      if (hops.length < 3 || hops.some((h) => !/^[0-9A-F]{40}$/i.test(h.fp))) continue;
      circuits.push({ id: m[1], hops, created: (m[3].match(/TIME_CREATED=(\S+)/) || [])[1] || '' });
    }
    if (!circuits.length) return null;

    const fps = [...new Set(circuits.flatMap((c) => c.hops.map((h) => h.fp)))];
    const ipByFp = {};
    let current = null;
    for (const line of (await this.control(fps.map((fp) => `GETINFO ns/id/${fp}`))).split(/\r?\n/)) {
      const head = line.match(/ns\/id\/([0-9A-F]{40})=/i);
      if (head) { current = head[1].toUpperCase(); continue; }
      if (current && line.startsWith('r ')) {
        const ip = line.split(' ').find((t) => /^\d{1,3}(\.\d{1,3}){3}$/.test(t));
        if (ip) ipByFp[current] = ip;
        current = null;
      }
    }

    const ips = [...new Set(Object.values(ipByFp))];
    const countryByIp = {};
    if (ips.length) {
      const out = await this.control(ips.map((ip) => `GETINFO ip-to-country/${ip}`)).catch(() => '');
      for (const m of out.matchAll(/ip-to-country\/([\d.]+)=(\w+)/g)) {
        if (m[2] !== '??') countryByIp[m[1]] = m[2].toUpperCase();
      }
    }

    const withIps = circuits.map((c) => ({
      ...c,
      hops: c.hops.map((h) => {
        const ip = ipByFp[h.fp.toUpperCase()] || null;
        return { nickname: h.nickname, ip, country: (ip && countryByIp[ip]) || null };
      }),
    }));
    const used = withIps.find((c) => c.id === this.lastCircuitId);
    const byIp = exitIpHint && withIps.find((c) => c.hops[c.hops.length - 1].ip === exitIpHint);
    const chosen = used || byIp || withIps.sort((a, b) => (a.created < b.created ? 1 : -1))[0];
    return { exact: !!(used || byIp), hops: chosen.hops };
  }

  // Просит Tor построить новые цепочки — следующий запрос пойдёт с другого IP.
  async newnym() {
    if (this.status !== 'ready') throw new Error('Tor ещё не подключён');
    // Tor сам ограничивает NEWNYM одним разом в ~10 секунд.
    const wait = this.lastNewnym + 10_000 - Date.now();
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    const cookie = fs.readFileSync(path.join(this.dataDir, 'control_auth_cookie')).toString('hex');
    await new Promise((resolve, reject) => {
      const sock = net.connect(CONTROL_PORT, '127.0.0.1');
      let out = '';
      const timer = setTimeout(() => { sock.destroy(); reject(new Error('Tor не ответил на control-порту')); }, 5000);
      sock.on('connect', () => sock.write(`AUTHENTICATE ${cookie}\r\nSIGNAL NEWNYM\r\nQUIT\r\n`));
      sock.on('data', (d) => { out += d.toString(); });
      sock.on('error', (e) => { clearTimeout(timer); reject(e); });
      sock.on('close', () => {
        clearTimeout(timer);
        const ok = (out.match(/^250 OK/gm) || []).length >= 2;
        ok ? resolve() : reject(new Error('Tor отклонил команду: ' + out.trim().split(/\r?\n/)[0]));
      });
    });
    this.lastNewnym = Date.now();
    // Даём Tor секунду на постройку новой цепочки.
    await new Promise((r) => setTimeout(r, 1500));
  }
}

module.exports = { TorManager, SOCKS_PORT, CONTROL_PORT };
