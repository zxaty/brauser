'use strict';
// Запуск и управление процессом Tor. Бинарник берётся из установленного
// Tor Browser; движок браузера подключается к этому же процессу, а панель
// управляет им через control-порт (смена цепочек, схема маршрута, мосты).

const { EventEmitter } = require('node:events');
const { spawn } = require('node:child_process');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const { parseProxy } = require('./proxy');

const SOCKS_PORT = 9250;
const CONTROL_PORT = 9251;

const fwd = (p) => p.replace(/\\/g, '/');

class TorManager extends EventEmitter {
  constructor({ dataDir }) {
    super();
    this.dataDir = dataDir;
    this.proc = null;
    this.status = 'stopped'; // stopped | starting | ready | error
    this.progress = 0;
    this.message = '';
    this.lastNewnym = 0;
    this.events = null;          // постоянное соединение с control-портом для событий
    this.relayCache = new Map(); // отпечаток узла -> { ip, country }
  }

  get cookieFile() { return path.join(this.dataDir, 'control_auth_cookie'); }

  _set(status, message = '', progress = this.progress) {
    this.status = status;
    this.message = message;
    this.progress = progress;
    this.emit('change');
  }

  // paths: { tor, lyrebird, geoipDir } — из раскладки Tor Browser.
  start(paths, { bridges, exitCountry, upstreamProxy } = {}) {
    if (this.proc) return;
    if (!fs.existsSync(paths.tor)) {
      this._set('error', 'Не найден файл Tor: ' + paths.tor, 0);
      return;
    }
    fs.mkdirSync(this.dataDir, { recursive: true });
    try { fs.rmSync(this.cookieFile, { force: true }); } catch { /* не критично */ }

    const lines = [
      `SocksPort 127.0.0.1:${SOCKS_PORT}`,
      `ControlPort 127.0.0.1:${CONTROL_PORT}`,
      'CookieAuthentication 1',
      `CookieAuthFile "${fwd(this.cookieFile)}"`,
      `DataDirectory "${fwd(this.dataDir)}"`,
    ];
    for (const [opt, file] of [['GeoIPFile', 'geoip'], ['GeoIPv6File', 'geoip6']]) {
      const p = path.join(paths.geoipDir, file);
      if (fs.existsSync(p)) lines.push(`${opt} "${fwd(p)}"`);
    }

    const bridgeLines = String(bridges || '').split(/\r?\n/).map((l) => l.trim().replace(/^bridge\s+/i, '')).filter(Boolean);
    if (bridgeLines.length) {
      lines.push('UseBridges 1');
      if (fs.existsSync(paths.lyrebird)) lines.push(`ClientTransportPlugin meek_lite,obfs4,scramblesuit,webtunnel exec "${fwd(paths.lyrebird)}"`);
      for (const b of bridgeLines) lines.push(`Bridge ${b}`);
    }

    if (/^[a-z]{2}$/i.test(exitCountry || '')) {
      lines.push(`ExitNodes {${exitCountry.toLowerCase()}}`, 'StrictNodes 1');
    }

    // Прокси ПЕРЕД Tor: провайдер видит соединение с прокси, а не с сетью Tor.
    const up = parseProxy(upstreamProxy);
    if (up) {
      const addr = `${up.host}:${up.port}`;
      if (up.scheme === 'socks5') {
        lines.push(`Socks5Proxy ${addr}`);
        if (up.username) lines.push(`Socks5ProxyUsername ${up.username}`, `Socks5ProxyPassword ${up.password}`);
      } else if (up.scheme === 'socks4') {
        lines.push(`Socks4Proxy ${addr}`);
      } else {
        lines.push(`HTTPSProxy ${addr}`);
        if (up.username) lines.push(`HTTPSProxyAuthenticator ${up.username}:${up.password}`);
      }
    }

    const torrc = path.join(this.dataDir, 'torrc');
    fs.writeFileSync(torrc, lines.join('\n') + '\n');

    this._set('starting', 'Запуск Tor…', 0);
    // Linux-сборка Tor несёт свои библиотеки (libevent, libssl) рядом с бинарником.
    const env = { ...process.env };
    if (process.platform !== 'win32') env.LD_LIBRARY_PATH = [path.dirname(paths.tor), env.LD_LIBRARY_PATH].filter(Boolean).join(':');
    const proc = spawn(paths.tor, ['-f', torrc], { windowsHide: true, env });
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
        } else if (/\[(err|warn)\]/.test(line) && this.status !== 'ready') {
          this.message = line.replace(/^.*\[(err|warn)\]\s*/, '');
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

  stop() {
    if (this.events) { this.events.destroy(); this.events = null; }
    const proc = this.proc;
    this.proc = null;
    if (proc) { try { proc.kill(); } catch { /* уже завершён */ } }
    this._set('stopped', '', 0);
  }

  // Подписка на события потоков: каждое соединение браузера сообщает, по какой
  // цепочке оно ушло и к какому сайту. На этом строится схема маршрута.
  _watchStreams() {
    if (this.events) return;
    let cookie;
    try { cookie = fs.readFileSync(this.cookieFile).toString('hex'); } catch { return; }
    const sock = net.connect(CONTROL_PORT, '127.0.0.1');
    this.events = sock;
    let buf = '';
    sock.on('connect', () => sock.write(`AUTHENTICATE ${cookie}\r\nSETEVENTS STREAM\r\n`));
    sock.on('data', (d) => {
      buf += d.toString();
      const lines = buf.split(/\r?\n/);
      buf = lines.pop();
      for (const line of lines) {
        // SENTCONNECT — момент, когда соединение отправлено по цепочке; здесь ещё
        // виден домен сайта (в более поздних событиях он заменяется на IP).
        const m = line.match(/^650 STREAM \d+ SENTCONNECT (\d+) (\S+)/);
        if (m && m[1] !== '0' && !/\.exit:\d+$/.test(m[2])) this.emit('stream', { circuitId: m[1], target: m[2].replace(/:\d+$/, '') });
      }
    });
    const drop = () => { if (this.events === sock) this.events = null; };
    sock.on('error', drop);
    sock.on('close', drop);
  }

  // Отправляет команды на control-порт и возвращает сырой ответ Tor.
  control(commands) {
    const cookie = fs.readFileSync(this.cookieFile).toString('hex');
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

  // Узлы цепочки с заданным номером: входной, промежуточный, выходной — с IP и страной.
  async circuit(circuitId) {
    if (this.status !== 'ready') return null;
    const raw = await this.control(['GETINFO circuit-status']);
    let hops = null;
    for (const line of raw.split(/\r?\n/)) {
      const m = line.match(/^(\d+) BUILT (\S+)/);
      if (!m || m[1] !== String(circuitId)) continue;
      hops = m[2].split(',').map((h) => {
        const [fp, nickname] = h.replace(/^\$/, '').split(/[~=]/);
        return { fp: fp.toUpperCase(), nickname: nickname || '' };
      });
    }
    if (!hops || hops.some((h) => !/^[0-9A-F]{40}$/.test(h.fp))) return null;

    const unknown = hops.filter((h) => !this.relayCache.has(h.fp)).map((h) => h.fp);
    if (unknown.length) {
      const ipByFp = {};
      let current = null;
      const ns = await this.control(unknown.map((fp) => `GETINFO ns/id/${fp}`)).catch(() => '');
      for (const line of ns.split(/\r?\n/)) {
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
      for (const fp of unknown) {
        const ip = ipByFp[fp] || null;
        // Мосты в общем списке узлов не значатся — их адрес остаётся неизвестным.
        if (ip) this.relayCache.set(fp, { ip, country: countryByIp[ip] || null });
      }
    }
    return hops.map((h) => ({ nickname: h.nickname, ...(this.relayCache.get(h.fp) || { ip: null, country: null }) }));
  }

  // Просит Tor построить новые цепочки — следующие соединения пойдут с других IP.
  async newnym() {
    if (this.status !== 'ready') throw new Error('Tor ещё не подключён');
    // Tor сам ограничивает NEWNYM одним разом в ~10 секунд.
    const wait = this.lastNewnym + 10_000 - Date.now();
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    await this.control(['SIGNAL NEWNYM']);
    this.lastNewnym = Date.now();
  }
}

module.exports = { TorManager, SOCKS_PORT, CONTROL_PORT };
