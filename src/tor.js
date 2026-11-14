'use strict';
// Запуск и управление процессом Tor. Бинарник берётся из установленного
// Tor Browser; движок браузера подключается к этому же процессу, а панель
// управляет им через control-порт (смена цепочек, схема маршрута, мосты).

const { EventEmitter } = require('node:events');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const { parseProxy } = require('./proxy');

const SOCKS_PORT = 9250;
const CONTROL_PORT = 9251;

// Константы SAFECOOKIE из спецификации control-протокола Tor.
const SERVER_TO_CONTROLLER = 'Tor safe cookie authentication server-to-controller hash';
const CONTROLLER_TO_SERVER = 'Tor safe cookie authentication controller-to-server hash';

const fwd = (p) => p.replace(/\\/g, '/');
// Значение директивы в кавычках, с экранированием по правилам torrc.
const quote = (s) => '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
const hasControlChars = (s) => /[\p{Cc}\p{Zl}\p{Zp}]/u.test(s);

// Разбирает поток control-порта на отдельные ответы. Ответ заканчивается
// строкой «NNN текст»; «NNN-текст» — промежуточная строка; «NNN+текст»
// открывает блок данных, который длится до строки из одной точки.
class ReplyReader {
  constructor(onReply) {
    this.onReply = onReply;
    this.buf = '';
    this.lines = [];
    this.inData = false;
  }

  push(chunk) {
    this.buf += chunk;
    let i;
    while ((i = this.buf.indexOf('\n')) !== -1) {
      const line = this.buf.slice(0, i).replace(/\r$/, '');
      this.buf = this.buf.slice(i + 1);
      this._line(line);
    }
  }

  _line(line) {
    if (this.inData) {
      if (line === '.') this.inData = false;
      else this.lines.push(line.startsWith('..') ? line.slice(1) : line);
      return;
    }
    const m = line.match(/^(\d{3})([ +-])(.*)$/);
    if (!m) return;
    this.lines.push(m[3]);
    if (m[2] === '+') { this.inData = true; return; }
    if (m[2] === ' ') {
      const reply = { code: m[1], lines: this.lines };
      this.lines = [];
      this.onReply(reply);
    }
  }
}

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

  // Linux и macOS: SOCKS и control работают через Unix-сокеты в папке данных Tor,
  // доступной только владельцу, — другой пользователь той же машины подключиться
  // к ним не может. На Windows (и если путь не годится для сокета) остаётся TCP
  // на 127.0.0.1, который пользователей ОС не различает.
  get ipc() {
    if (process.platform === 'win32' || process.env.BRAUSER_TOR_TCP) return null;
    const socks = path.join(this.dataDir, 'socks.sock');
    const control = path.join(this.dataDir, 'control.sock');
    // Путь сокета ограничен ~107 байтами; пробелы и кавычки потребовали бы особого синтаксиса torrc.
    if (Buffer.byteLength(control) > 100 || /[\s"'\\#]/.test(this.dataDir)) return null;
    return { socks, control };
  }

  // Как движку и панели подключаться к этому Tor.
  get connection() {
    const ipc = this.ipc;
    return ipc
      ? { cookieFile: this.cookieFile, socksPath: ipc.socks, controlPath: ipc.control }
      : { cookieFile: this.cookieFile, socksPort: SOCKS_PORT, controlPort: CONTROL_PORT };
  }

  _set(status, message = '', progress = this.progress) {
    this.status = status;
    this.message = message;
    this.progress = progress;
    this.emit('change');
  }

  // Собирает конфигурацию Tor. Возвращает текст или бросает ошибку, если в
  // настройках есть то, что нельзя безопасно записать в конфигурацию.
  _buildConfig(paths, { bridges, exitCountry, upstreamProxy } = {}) {
    const ipc = this.ipc;
    const lines = [
      ipc ? `SocksPort unix:${ipc.socks}` : `SocksPort 127.0.0.1:${SOCKS_PORT}`,
      ipc ? `ControlPort unix:${ipc.control}` : `ControlPort 127.0.0.1:${CONTROL_PORT}`,
      'CookieAuthentication 1',
      `CookieAuthFile "${fwd(this.cookieFile)}"`,
      `DataDirectory "${fwd(this.dataDir)}"`,
    ];
    for (const [opt, file] of [['GeoIPFile', 'geoip'], ['GeoIPv6File', 'geoip6']]) {
      const p = path.join(paths.geoipDir, file);
      if (fs.existsSync(p)) lines.push(`${opt} "${fwd(p)}"`);
    }

    const bridgeLines = String(bridges || '').split(/[\r\n]+/).map((l) => l.trim().replace(/^bridge\s+/i, '')).filter(Boolean);
    if (bridgeLines.length) {
      lines.push('UseBridges 1');
      if (fs.existsSync(paths.lyrebird)) lines.push(`ClientTransportPlugin meek_lite,obfs4,scramblesuit,webtunnel exec "${fwd(paths.lyrebird)}"`);
      for (const b of bridgeLines) lines.push(`Bridge ${b}`);
    }

    if (/^[a-z]{2}$/i.test(exitCountry || '')) {
      lines.push(`ExitNodes {${exitCountry.toLowerCase()}}`, 'StrictNodes 1');
    }

    // Прокси ПЕРЕД Tor: провайдер видит соединение с прокси, а не с сетью Tor.
    // parseProxy уже отклоняет управляющие символы в логине и пароле; значения
    // дополнительно пишутся в кавычках, чтобы пробел или # не обрезали их.
    if (String(upstreamProxy || '').trim()) {
      const up = parseProxy(upstreamProxy);
      if (!up) throw new Error('адрес прокси перед Tor не распознан или содержит недопустимые символы');
      const addr = `${up.host}:${up.port}`;
      if (up.scheme === 'socks5') {
        lines.push(`Socks5Proxy ${addr}`);
        if (up.username) lines.push(`Socks5ProxyUsername ${quote(up.username)}`, `Socks5ProxyPassword ${quote(up.password)}`);
      } else if (up.scheme === 'socks4') {
        lines.push(`Socks4Proxy ${addr}`);
      } else {
        lines.push(`HTTPSProxy ${addr}`);
        if (up.username) {
          if (up.username.includes(':')) throw new Error('логин HTTP-прокси не может содержать двоеточие');
          lines.push(`HTTPSProxyAuthenticator ${quote(up.username + ':' + up.password)}`);
        }
      }
    }

    // Последний рубеж: ни одна строка конфигурации не должна содержать перенос
    // строки или другой управляющий символ, откуда бы значение ни пришло.
    if (lines.some(hasControlChars)) throw new Error('в настройках Tor есть недопустимые символы');
    return lines.join('\n') + '\n';
  }

  // paths: { tor, lyrebird, geoipDir } — из раскладки Tor Browser.
  start(paths, options = {}) {
    if (this.proc) return;
    if (!fs.existsSync(paths.tor)) {
      this._set('error', 'Не найден файл Tor: ' + paths.tor, 0);
      return;
    }
    let config;
    try {
      config = this._buildConfig(paths, options);
    } catch (e) {
      this._set('error', 'Tor не запущен: ' + e.message, 0);
      return;
    }

    // Папка данных Tor — только для владельца (на Windows права задаёт профиль пользователя).
    fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    try { fs.chmodSync(this.dataDir, 0o700); } catch { /* не критично */ }
    try { fs.rmSync(this.cookieFile, { force: true }); } catch { /* не критично */ }
    // Прежние версии писали конфигурацию (с паролем прокси) в файл — убираем его.
    try { fs.rmSync(path.join(this.dataDir, 'torrc'), { force: true }); } catch { /* не критично */ }
    for (const stale of ['socks.sock', 'control.sock']) {
      try { fs.rmSync(path.join(this.dataDir, stale), { force: true }); } catch { /* не критично */ }
    }

    this._dropEvents(); // соединение с прежним процессом Tor, если он упал сам
    this._set('starting', 'Запуск Tor…', 0);
    // Linux-сборка Tor несёт свои библиотеки (libevent, libssl) рядом с бинарником.
    const env = { ...process.env };
    if (process.platform !== 'win32') env.LD_LIBRARY_PATH = [path.dirname(paths.tor), env.LD_LIBRARY_PATH].filter(Boolean).join(':');
    // Конфигурация передаётся через stdin («-f -») и на диск не попадает.
    const proc = spawn(paths.tor, ['-f', '-'], { windowsHide: true, env, stdio: ['pipe', 'pipe', 'pipe'] });
    this.proc = proc;
    proc.stdin.on('error', () => { /* процесс не запустился — об этом сообщит событие error/exit */ });
    proc.stdin.end(config);

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

  _dropEvents() {
    const events = this.events;
    this.events = null;
    if (events && events.close) events.close();
  }

  stop() {
    this._dropEvents();
    const proc = this.proc;
    this.proc = null;
    if (proc) { try { proc.kill(); } catch { /* уже завершён */ } }
    this._set('stopped', '', 0);
  }

  // Открывает соединение с control-портом и проходит аутентификацию SAFECOOKIE.
  // Сам cookie по сети не передаётся: обе стороны обмениваются HMAC от него, и
  // сначала сервер доказывает, что знает cookie. Подставной процесс, занявший
  // порт, проверку не пройдёт и ничего секретного не получит.
  // Возвращает { send(команда) -> Promise<{ code, lines }>, close() }.
  _connect({ onEvent, timeoutMs = 5000 } = {}) {
    return new Promise((resolve, reject) => {
      let cookie;
      try { cookie = fs.readFileSync(this.cookieFile); } catch (e) { reject(new Error('нет файла cookie Tor: ' + e.message)); return; }
      if (cookie.length !== 32) { reject(new Error('файл cookie Tor повреждён')); return; }

      const ipc = this.ipc;
      const sock = ipc ? net.connect({ path: ipc.control }) : net.connect(CONTROL_PORT, '127.0.0.1');
      const pending = [];
      let closed = false;
      let failure = null;
      const fail = (err) => {
        if (closed) return;
        closed = true;
        failure = err;
        sock.destroy();
        for (const p of pending.splice(0)) p.reject(err);
        reject(err); // не действует, если соединение уже установлено
      };
      const reader = new ReplyReader((reply) => {
        // 6xx — асинхронные события, а не ответы на команды.
        if (reply.code[0] === '6') { if (onEvent) onEvent(reply); return; }
        const p = pending.shift();
        if (p) p.resolve(reply);
      });
      const send = (command) => new Promise((res, rej) => {
        if (closed) { rej(failure || new Error('соединение с Tor закрыто')); return; }
        if (hasControlChars(command)) { rej(new Error('недопустимые символы в команде Tor')); return; }
        pending.push({ resolve: res, reject: rej });
        sock.write(command + '\r\n');
      });
      const close = () => { if (!closed) { closed = true; sock.destroy(); for (const p of pending.splice(0)) p.reject(new Error('соединение с Tor закрыто')); } };

      sock.setEncoding('utf8');
      sock.setTimeout(timeoutMs, () => fail(new Error('Tor не ответил на control-порту')));
      sock.on('data', (d) => reader.push(d));
      sock.on('error', (e) => fail(e));
      sock.on('close', () => fail(new Error('соединение с Tor закрыто')));
      sock.on('connect', async () => {
        try {
          const clientNonce = crypto.randomBytes(32);
          const challenge = await send('AUTHCHALLENGE SAFECOOKIE ' + clientNonce.toString('hex'));
          const m = challenge.code === '250' && challenge.lines.join(' ').match(/SERVERHASH=([0-9A-F]{64}) SERVERNONCE=([0-9A-F]{64})/i);
          if (!m) throw new Error('control-порт не поддержал SAFECOOKIE');
          const material = Buffer.concat([cookie, clientNonce, Buffer.from(m[2], 'hex')]);
          const expected = crypto.createHmac('sha256', SERVER_TO_CONTROLLER).update(material).digest();
          if (!crypto.timingSafeEqual(expected, Buffer.from(m[1], 'hex'))) {
            throw new Error('control-порт не прошёл проверку подлинности: на порту не наш Tor');
          }
          const proof = crypto.createHmac('sha256', CONTROLLER_TO_SERVER).update(material).digest('hex');
          const auth = await send('AUTHENTICATE ' + proof);
          if (auth.code !== '250') throw new Error('Tor отклонил аутентификацию: ' + auth.code);
          resolve({ send, close, setTimeout: (ms) => sock.setTimeout(ms) });
        } catch (e) { fail(e); }
      });
    });
  }

  // Подписка на события потоков: каждое соединение браузера сообщает, по какой
  // цепочке оно ушло и к какому сайту. На этом строится схема маршрута.
  async _watchStreams() {
    if (this.events) return;
    const marker = {};
    this.events = marker; // занято, пока идёт подключение
    try {
      const conn = await this._connect({
        onEvent: (reply) => {
          // SENTCONNECT — момент, когда соединение отправлено по цепочке; здесь ещё
          // виден домен сайта (в более поздних событиях он заменяется на IP).
          const m = reply.lines[0].match(/^STREAM \d+ SENTCONNECT (\d+) (\S+)/);
          if (m && m[1] !== '0' && !/\.exit:\d+$/.test(m[2])) this.emit('stream', { circuitId: m[1], target: m[2].replace(/:\d+$/, '') });
        },
      });
      const reply = await conn.send('SETEVENTS STREAM');
      if (reply.code !== '250') throw new Error('Tor отклонил подписку на события: ' + reply.code);
      conn.setTimeout(0); // событий может не быть сколько угодно долго
      if (this.events === marker) this.events = conn; else conn.close(); // пока подключались, Tor остановили
    } catch {
      if (this.events === marker) this.events = null; // схема маршрута просто не будет обновляться
    }
  }

  // Выполняет команды на control-порту по очереди и проверяет ответ на КАЖДУЮ.
  // Возвращает строки успешных ответов одним текстом. Отказ в любой команде —
  // ошибка; с tolerant: true отказавшие команды пропускаются (для справочных
  // запросов, где часть ключей может быть неизвестна Tor).
  async control(commands, { tolerant = false } = {}) {
    const conn = await this._connect();
    try {
      const lines = [];
      for (const command of commands) {
        const reply = await conn.send(command);
        if (reply.code[0] === '2') { lines.push(...reply.lines); continue; }
        if (!tolerant) throw new Error(`Tor отклонил команду ${command.split(' ')[0]}: ${reply.code} ${reply.lines[reply.lines.length - 1] || ''}`.trim());
      }
      return lines.join('\n');
    } finally {
      conn.close();
    }
  }

  // Узлы цепочки с заданным номером: входной, промежуточный, выходной — с IP и страной.
  async circuit(circuitId) {
    if (this.status !== 'ready') return null;
    const raw = await this.control(['GETINFO circuit-status']);
    let hops = null;
    for (const line of raw.split('\n')) {
      // Одна цепочка приходит строкой «circuit-status=N BUILT …», несколько — блоком строк.
      const m = line.match(/^(?:circuit-status=)?(\d+) BUILT (\S+)/);
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
      const ns = await this.control(unknown.map((fp) => `GETINFO ns/id/${fp}`), { tolerant: true }).catch(() => '');
      for (const line of ns.split('\n')) {
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
        const out = await this.control(ips.map((ip) => `GETINFO ip-to-country/${ip}`), { tolerant: true }).catch(() => '');
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
  // Бросает ошибку, если Tor отказал: панель не должна сообщать об успехе зря.
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
