'use strict';
// Запуск и управление процессом Tor. Бинарник берётся из установленного
// Tor Browser; движок браузера подключается к этому же процессу, а панель
// управляет им через control-порт (смена цепочек, схема маршрута, мосты).

const { EventEmitter } = require('node:events');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const net = require('node:net');
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');
const { parseProxy } = require('./proxy');

const SOCKS_PORT = 9250;
const CONTROL_PORT = 9251;

// Константы SAFECOOKIE из спецификации control-протокола Tor.
const SERVER_TO_CONTROLLER = 'Tor safe cookie authentication server-to-controller hash';
const CONTROLLER_TO_SERVER = 'Tor safe cookie authentication controller-to-server hash';

const WIN = process.platform === 'win32';
const MAX_REPLY_CHARS = 4 * 1024 * 1024;

// Значение директивы в кавычках, с экранированием по правилам torrc.
const quote = (s) => '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
// Путь для конфигурации: всегда в кавычках и с экранированием, без какой-либо
// замены символов — Tor получает ровно тот путь, который есть на диске.
const quotePath = (p) => quote(p);
const hasControlChars = (s) => /[\p{Cc}\p{Zl}\p{Zp}]/u.test(s);

// Разбирает поток control-порта на отдельные ответы. Ответ заканчивается
// строкой «NNN текст»; «NNN-текст» — промежуточная строка; «NNN+текст»
// открывает блок данных, который длится до строки из одной точки.
class ReplyReader {
  constructor(onReply, onOverflow) {
    this.onReply = onReply;
    this.onOverflow = onOverflow;
    this.buf = '';
    this.lines = [];
    this.inData = false;
    this.size = 0; // символов в ещё не завершённом ответе
  }

  push(chunk) {
    // Настоящие ответы Tor на наши команды — килобайты. Предел не даёт
    // подставному собеседнику занять память бесконечным ответом.
    this.size += chunk.length;
    if (this.size > MAX_REPLY_CHARS) { this.buf = ''; this.lines = []; this.onOverflow(); return; }
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
      this.size = this.buf.length;
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
    this.socketDir = null;       // каталог Unix-сокетов (выбирается один раз за запуск приложения)
    this.ownsSocketDir = false;  // каталог создан нами во временной папке — убрать при выходе
    this.events = null;          // постоянное соединение с control-портом для событий
    this.relayCache = new Map(); // отпечаток узла -> { ip, country }
  }

  get cookieFile() { return path.join(this.dataDir, 'control_auth_cookie'); }

  // Как Tor доступен локально. Linux и macOS — Unix-сокеты в каталоге только для
  // владельца: другой пользователь той же машины подключиться не может. Windows —
  // TCP на 127.0.0.1, который пользователей ОС не различает. Перейти на TCP в
  // Linux/macOS можно только явно, переменной BRAUSER_TOR_TCP=1: если сокеты
  // создать нельзя, Tor не запускается, а не откатывается на TCP молча.
  get transport() {
    return WIN || process.env.BRAUSER_TOR_TCP === '1' ? 'tcp' : 'unix';
  }

  // Сокеты лежат не в папке данных (её путь может быть длинным или с пробелами),
  // а в коротком отдельном каталоге. Каталог выбирается один раз за запуск
  // приложения: уже открытый браузер помнит его путь, и после перезапуска Tor
  // сокеты должны появиться там же. Бросает ошибку, если каталог недоступен.
  get ipc() {
    if (this.transport !== 'unix') return null;
    if (!this.socketDir) this._prepareSocketDir();
    const dir = this.socketDir;
    return { dir, socks: path.join(dir, 'socks.sock'), control: path.join(dir, 'control.sock') };
  }

  // Создаёт (или перепроверяет) каталог сокетов и убеждается, что он наш и
  // закрыт для остальных. Бросает ошибку, если это не так.
  _prepareSocketDir() {
    if (!this.socketDir) {
      // Личный каталог сеанса, если система его даёт: в нём чужих имён быть не может.
      const runtime = process.env.XDG_RUNTIME_DIR;
      let ownRuntime = false;
      try {
        const st = runtime && path.isAbsolute(runtime) ? fs.statSync(runtime) : null;
        ownRuntime = !!st && st.isDirectory() && st.uid === process.getuid() && (st.mode & 0o077) === 0;
      } catch { /* каталога нет */ }
      let dir;
      if (ownRuntime) {
        dir = path.join(runtime, 'brauser-tor');
        try { fs.mkdirSync(dir, { mode: 0o700 }); } catch (e) { if (e.code !== 'EEXIST') throw e; }
      } else {
        // Запасной вариант — каталог со случайным именем в общем временном:
        // его нельзя занять заранее, и создаётся он сразу с правами 0700.
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'brauser-tor-'));
        this.ownsSocketDir = true;
      }
      // Путь сокета ограничен ~107 байтами; спецсимволы потребовали бы особого синтаксиса torrc.
      if (!/^[A-Za-z0-9._/+-]+$/.test(dir) || Buffer.byteLength(path.join(dir, 'control.sock')) > 100) {
        if (this.ownsSocketDir) fs.rmSync(dir, { recursive: true, force: true });
        this.ownsSocketDir = false;
        throw new Error('путь для сокетов Tor не подходит: ' + dir);
      }
      this.socketDir = dir;
    }
    const dir = this.socketDir;
    let st = fs.lstatSync(dir); // lstat: символическая ссылка вместо каталога не пройдёт
    if (st.isDirectory() && st.uid === process.getuid() && (st.mode & 0o077) !== 0) {
      fs.chmodSync(dir, 0o700);
      st = fs.lstatSync(dir);
    }
    if (!st.isDirectory() || st.uid !== process.getuid() || (st.mode & 0o077) !== 0) {
      throw new Error('каталог сокетов Tor занят другим пользователем или открыт посторонним: ' + dir);
    }
    for (const stale of ['socks.sock', 'control.sock']) fs.rmSync(path.join(dir, stale), { force: true });
  }

  // Убирает за собой каталог сокетов, созданный во временной папке. Вызывается при выходе.
  dispose() {
    if (this.ownsSocketDir && this.socketDir) {
      try { fs.rmSync(this.socketDir, { recursive: true, force: true }); } catch { /* не критично */ }
    }
    this.socketDir = null;
    this.ownsSocketDir = false;
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
      `CookieAuthFile ${quotePath(this.cookieFile)}`,
      `DataDirectory ${quotePath(this.dataDir)}`,
    ];
    for (const [opt, file] of [['GeoIPFile', 'geoip'], ['GeoIPv6File', 'geoip6']]) {
      const p = path.join(paths.geoipDir, file);
      if (fs.existsSync(p)) lines.push(`${opt} ${quotePath(p)}`);
    }

    const bridgeLines = String(bridges || '').split(/[\r\n]+/).map((l) => l.trim().replace(/^bridge\s+/i, '')).filter(Boolean);
    if (bridgeLines.length) {
      lines.push('UseBridges 1');
      // Tor делит эту директиву по пробелам и кавычек внутри не понимает, поэтому
      // путь к программе-транспорту задаётся относительно папки Tor (она же —
      // рабочая папка процесса, см. start): в нём нет ни пробелов, ни спецсимволов.
      if (fs.existsSync(paths.lyrebird)) {
        const rel = path.relative(path.dirname(paths.tor), paths.lyrebird).split(path.sep).join('/');
        if (/^[A-Za-z0-9._/-]+$/.test(rel) && !rel.startsWith('..')) {
          // Те же две строки, что задаёт сам Tor Browser: обычные транспорты и snowflake.
          lines.push(`ClientTransportPlugin meek_lite,obfs2,obfs3,obfs4,scramblesuit,webtunnel exec ./${rel}`);
          lines.push(`ClientTransportPlugin snowflake exec ./${rel}`);
        }
      }
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
      // Сокеты недоступны — Tor не запускается. Молчаливого отката на TCP нет.
      if (this.transport === 'unix') this._prepareSocketDir();
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

    this._dropEvents(); // соединение с прежним процессом Tor, если он упал сам
    this._set('starting', 'Запуск Tor…', 0);
    // Linux-сборка Tor несёт свои библиотеки (libevent, libssl) рядом с бинарником.
    const env = { ...process.env };
    if (!WIN) env.LD_LIBRARY_PATH = [path.dirname(paths.tor), env.LD_LIBRARY_PATH].filter(Boolean).join(':');
    // Конфигурация передаётся через stdin («-f -») и на диск не попадает.
    // Рабочая папка — папка Tor: от неё отсчитывается путь к транспорту мостов.
    const proc = spawn(paths.tor, ['-f', '-'], { windowsHide: true, env, cwd: path.dirname(paths.tor), stdio: ['pipe', 'pipe', 'pipe'] });
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
  // timeoutMs — предел молчания сокета; deadlineMs — предел на всё соединение
  // целиком (его нельзя растянуть, присылая данные по капле); onClosed
  // вызывается, когда уже установленное соединение оборвалось.
  _connect({ onEvent, onClosed, timeoutMs = 5000, deadlineMs = 15000 } = {}) {
    return new Promise((resolve, reject) => {
      let cookie;
      try { cookie = fs.readFileSync(this.cookieFile); } catch (e) { reject(new Error('нет файла cookie Tor: ' + e.message)); return; }
      if (cookie.length !== 32) { reject(new Error('файл cookie Tor повреждён')); return; }

      const ipc = this.ipc;
      const sock = ipc ? net.connect({ path: ipc.control }) : net.connect(CONTROL_PORT, '127.0.0.1');
      const pending = [];
      let closed = false;
      let established = false;
      let failure = null;
      let deadline = null;
      const fail = (err) => {
        if (closed) return;
        closed = true;
        failure = err;
        clearTimeout(deadline);
        sock.destroy();
        for (const p of pending.splice(0)) p.reject(err);
        reject(err); // не действует, если соединение уже установлено
        if (established && onClosed) onClosed(err);
      };
      deadline = setTimeout(() => fail(new Error('Tor не уложился в отведённое время на control-порту')), deadlineMs);
      const reader = new ReplyReader((reply) => {
        // 6xx — асинхронные события, а не ответы на команды.
        if (reply.code[0] === '6') { if (onEvent) onEvent(reply); return; }
        const p = pending.shift();
        if (p) p.resolve(reply);
      }, () => fail(new Error('слишком большой ответ на control-порту')));
      const send = (command) => new Promise((res, rej) => {
        if (closed) { rej(failure || new Error('соединение с Tor закрыто')); return; }
        if (hasControlChars(command)) { rej(new Error('недопустимые символы в команде Tor')); return; }
        pending.push({ resolve: res, reject: rej });
        sock.write(command + '\r\n');
      });
      const close = () => {
        if (closed) return;
        closed = true;
        clearTimeout(deadline);
        sock.destroy();
        for (const p of pending.splice(0)) p.reject(new Error('соединение с Tor закрыто'));
      };

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
          established = true;
          resolve({
            send,
            close,
            // Для долгоживущей подписки на события: снять оба ограничения по времени.
            keepOpen: () => { clearTimeout(deadline); sock.setTimeout(0); },
          });
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
    let conn = null;
    // Подписка оборвалась или не установилась, а Tor работает — пробуем снова,
    // иначе схема маршрута перестала бы обновляться до перезапуска Tor.
    const retryLater = () => {
      const proc = this.proc;
      setTimeout(() => { if (this.proc === proc && proc && this.status === 'ready' && !this.events) this._watchStreams(); }, 3000);
    };
    try {
      conn = await this._connect({
        onEvent: (reply) => {
          // SENTCONNECT — момент, когда соединение отправлено по цепочке; здесь ещё
          // виден домен сайта (в более поздних событиях он заменяется на IP).
          const m = reply.lines[0].match(/^STREAM \d+ SENTCONNECT (\d+) (\S+)/);
          if (m && m[1] !== '0' && !/\.exit:\d+$/.test(m[2])) this.emit('stream', { circuitId: m[1], target: m[2].replace(/:\d+$/, '') });
        },
        onClosed: () => {
          if (this.events !== conn) return; // соединение закрыли мы сами
          this.events = null;
          retryLater();
        },
      });
      const reply = await conn.send('SETEVENTS STREAM');
      if (reply.code !== '250') throw new Error('Tor отклонил подписку на события: ' + reply.code);
      conn.keepOpen(); // событий может не быть сколько угодно долго
      if (this.events === marker) this.events = conn; else conn.close(); // пока подключались, Tor остановили
    } catch {
      if (conn) conn.close();
      if (this.events === marker) { this.events = null; retryLater(); }
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

module.exports = { TorManager, ReplyReader, SOCKS_PORT, CONTROL_PORT };
