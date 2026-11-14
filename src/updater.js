'use strict';
// Автообновление. Порядок действий и то, на чём держится доверие:
//
//  1. Скачивается манифест последнего выпуска и его подпись.
//  2. Подпись проверяется открытым ключом, зашитым в приложение (src/update-key.js).
//     Без верной подписи манифест отвергается: взлома репозитория или подмены
//     релиза недостаточно, чтобы подсунуть обновление.
//  3. Версия в манифесте должна быть новее текущей — откат на старую версию
//     (с известными ошибками) не принимается.
//  4. Установщик скачивается и сверяется по размеру и SHA-256 из манифеста.
//  5. Только после этого запускается установка.
//
// В режиме Secured все запросы идут через Tor (SOCKS-порт нашего Tor), так что
// сервер видит выходной узел, а не пользователя. В Basic — напрямую, как и
// остальной трафик этого режима.

const { EventEmitter } = require('node:events');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const https = require('node:https');
const net = require('node:net');
const tls = require('node:tls');
const fs = require('node:fs');
const path = require('node:path');

const WIN = process.platform === 'win32';
const MANIFEST_URL = 'https://github.com/zxaty/brauser/releases/latest/download/brauser-update.json';
// Куда разрешено ходить за файлами выпуска (GitHub перенаправляет на свои хранилища).
const ALLOWED_HOSTS = /^(github\.com|[a-z0-9-]+\.githubusercontent\.com)$/;
const MAX_MANIFEST = 64 * 1024;
const MAX_INSTALLER = 1024 * 1024 * 1024;

// ---------------------------------------------------------------- манифест

const parseVersion = (v) => {
  const m = /^(\d{1,5})\.(\d{1,5})\.(\d{1,5})$/.exec(String(v));
  return m ? m.slice(1).map(Number) : null;
};

// > 0, если a новее b.
function compareVersions(a, b) {
  const x = parseVersion(a);
  const y = parseVersion(b);
  if (!x || !y) throw new Error('некорректный номер версии');
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
}

// Проверяет подпись и содержимое манифеста. Возвращает { version, file } для
// текущей системы или бросает ошибку. bytes — манифест как он скачан, signature —
// подпись в base64, publicKeyPem — зашитый открытый ключ.
function verifyManifest(bytes, signature, publicKeyPem, platform = process.platform) {
  let sig;
  try { sig = Buffer.from(String(signature).trim(), 'base64'); } catch { sig = Buffer.alloc(0); }
  if (sig.length !== 64 || !crypto.verify(null, bytes, crypto.createPublicKey(publicKeyPem), sig)) {
    throw new Error('подпись выпуска не подтверждена');
  }
  // Содержимому можно верить только после проверки подписи.
  let manifest;
  try { manifest = JSON.parse(bytes.toString('utf8')); } catch { throw new Error('манифест выпуска повреждён'); }
  if (!manifest || manifest.name !== 'brauser' || !parseVersion(manifest.version)) throw new Error('манифест выпуска некорректен');
  const file = manifest.files && manifest.files[platform];
  if (!file) throw new Error('в выпуске нет установщика для этой системы');
  if (typeof file.name !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$/.test(file.name)
    || !/^[0-9a-f]{64}$/.test(file.sha256) || !Number.isInteger(file.size) || file.size <= 0 || file.size > MAX_INSTALLER) {
    throw new Error('манифест выпуска некорректен');
  }
  return { version: manifest.version, file: { name: file.name, sha256: file.sha256, size: file.size } };
}

// ---------------------------------------------------------------- сеть

// Соединение с host:port через SOCKS5 нашего Tor. socks — { socksPort } или
// { socksPath }. Логин и пароль случайные: Tor выделяет под них отдельную
// цепочку, не общую с вкладками браузера.
function socksConnect(socks, host, port, timeoutMs = 60_000) {
  return new Promise((resolve, reject) => {
    const sock = socks.socksPath ? net.connect({ path: socks.socksPath }) : net.connect(socks.socksPort, '127.0.0.1');
    let buf = Buffer.alloc(0);
    let waiting = null;
    const fail = (e) => { sock.destroy(); reject(e); };
    const timer = setTimeout(() => fail(new Error('Tor не ответил при соединении для обновления')), timeoutMs);
    const need = (n) => new Promise((res) => { waiting = { n, res }; pump(); });
    const pump = () => {
      if (waiting && buf.length >= waiting.n) {
        const { n, res } = waiting;
        waiting = null;
        const chunk = buf.subarray(0, n);
        buf = buf.subarray(n);
        res(chunk);
      }
    };
    sock.on('data', (d) => { buf = Buffer.concat([buf, d]); pump(); });
    sock.on('error', fail);
    sock.on('close', () => fail(new Error('соединение с Tor закрыто')));
    sock.on('connect', async () => {
      try {
        const user = Buffer.from('brauser-update');
        const pass = Buffer.from(crypto.randomBytes(12).toString('hex'));
        sock.write(Buffer.from([5, 1, 2])); // только вход по логину и паролю
        const hello = await need(2);
        if (hello[0] !== 5 || hello[1] !== 2) throw new Error('Tor отклонил способ входа SOCKS');
        sock.write(Buffer.concat([Buffer.from([1, user.length]), user, Buffer.from([pass.length]), pass]));
        const auth = await need(2);
        if (auth[1] !== 0) throw new Error('Tor отклонил вход SOCKS');
        const name = Buffer.from(host);
        const req = Buffer.alloc(7 + name.length);
        req.set([5, 1, 0, 3, name.length]);
        name.copy(req, 5);
        req.writeUInt16BE(port, 5 + name.length);
        sock.write(req);
        const head = await need(4);
        if (head[1] !== 0) throw new Error(`Tor не смог соединиться с ${host} (код ${head[1]})`);
        const rest = head[3] === 1 ? 6 : head[3] === 4 ? 18 : (await need(1))[0] + 2;
        await need(rest);
        clearTimeout(timer);
        sock.removeAllListeners('data');
        sock.removeAllListeners('error');
        sock.removeAllListeners('close');
        if (buf.length) sock.unshift(buf);
        resolve(sock);
      } catch (e) { clearTimeout(timer); fail(e); }
    });
  });
}

// GET по HTTPS с переходом по перенаправлениям. socks — как в socksConnect, либо
// null для прямого соединения. onResponse(res) получает поток ответа 200.
async function httpsGet(url, socks, onResponse, redirects = 0) {
  const u = new URL(url);
  if (u.protocol !== 'https:' || !ALLOWED_HOSTS.test(u.hostname)) throw new Error('недопустимый адрес обновления: ' + u.hostname);
  const options = { host: u.hostname, port: 443, path: u.pathname + u.search, method: 'GET', agent: false, headers: { 'User-Agent': 'Mozilla/5.0', Accept: '*/*', Connection: 'close' } };
  if (socks) {
    const raw = await socksConnect(socks, u.hostname, 443);
    const secure = tls.connect({ socket: raw, servername: u.hostname });
    await new Promise((res, rej) => { secure.once('secureConnect', res); secure.once('error', rej); });
    options.createConnection = () => secure;
  }
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      const { statusCode, headers } = res;
      if ([301, 302, 303, 307, 308].includes(statusCode) && headers.location) {
        res.resume();
        if (redirects >= 5) { reject(new Error('слишком много перенаправлений')); return; }
        resolve(httpsGet(new URL(headers.location, url).href, socks, onResponse, redirects + 1));
        return;
      }
      if (statusCode !== 200) { res.resume(); reject(new Error(`сервер обновлений ответил ${statusCode}`)); return; }
      Promise.resolve(onResponse(res)).then(resolve, reject);
    });
    req.setTimeout(120_000, () => req.destroy(new Error('сервер обновлений не отвечает')));
    req.on('error', reject);
    req.end();
  });
}

const fetchSmall = (url, socks, maxBytes) => httpsGet(url, socks, (res) => new Promise((resolve, reject) => {
  const chunks = [];
  let size = 0;
  res.on('data', (d) => { size += d.length; if (size > maxBytes) { res.destroy(); reject(new Error('ответ сервера обновлений слишком большой')); } else chunks.push(d); });
  res.on('end', () => resolve(Buffer.concat(chunks)));
  res.on('error', reject);
}));

// ---------------------------------------------------------------- установка

// Часть, выполняемая от root при установке .deb (та же логика, что в install.sh):
// пакет копируется в каталог root, контрольная сумма сверяется уже у копии, и
// ставится именно она — подменить файл после проверки обычный пользователь не может.
const ROOT_STAGE = `
set -eu
src=$1; sum=$2; name=$3
umask 077
work=$(mktemp -d /var/tmp/brauser-update.XXXXXXXX)
trap "rm -rf \\"$work\\"" EXIT
cp -- "$src" "$work/$name"
echo "$sum  $work/$name" | sha256sum -c --status - || { echo "контрольная сумма пакета не совпадает" >&2; exit 3; }
chmod 755 "$work"
chmod 644 "$work/$name"
DEBIAN_FRONTEND=noninteractive apt-get install -y "$work/$name"
`;

class Updater extends EventEmitter {
  // getSocks() возвращает { socksPort } / { socksPath } для запросов через Tor,
  // null для прямых запросов или бросает ошибку, если сеть сейчас недоступна.
  constructor({ currentVersion, publicKey, workDir, getSocks, manifestUrl = MANIFEST_URL }) {
    super();
    this.currentVersion = currentVersion;
    this.publicKey = publicKey;
    this.workDir = workDir;
    this.getSocks = getSocks;
    this.manifestUrl = manifestUrl;
    this.state = { status: 'idle', version: null, progress: 0, message: '' };
    this.available = null; // { version, file } после успешной проверки
    this.busy = false;
  }

  _set(patch) {
    this.state = { ...this.state, ...patch };
    this.emit('change');
  }

  // Проверяет, есть ли новая версия. Возвращает номер версии или null.
  async check() {
    if (this.busy) return null;
    this.busy = true;
    this._set({ status: 'checking', message: '' });
    try {
      const socks = this.getSocks();
      const manifest = await fetchSmall(this.manifestUrl, socks, MAX_MANIFEST);
      const signature = await fetchSmall(this.manifestUrl + '.sig', socks, 1024);
      const found = verifyManifest(manifest, signature.toString('utf8'), this.publicKey);
      if (compareVersions(found.version, this.currentVersion) <= 0) {
        this.available = null;
        this._set({ status: 'uptodate', version: null });
        return null;
      }
      this.available = found;
      this._set({ status: 'available', version: found.version });
      return found.version;
    } catch (e) {
      this._set({ status: 'error', message: 'Проверка обновлений не удалась: ' + e.message });
      return null;
    } finally {
      this.busy = false;
    }
  }

  // Скачивает проверенный установщик найденной версии. Возвращает путь к файлу.
  async download() {
    const found = this.available;
    if (!found) throw new Error('нет проверенного обновления');
    const socks = this.getSocks();
    const url = new URL(found.file.name, this.manifestUrl).href;
    fs.mkdirSync(this.workDir, { recursive: true, mode: 0o700 });
    for (const old of fs.readdirSync(this.workDir)) fs.rmSync(path.join(this.workDir, old), { recursive: true, force: true });
    const dir = fs.mkdtempSync(path.join(this.workDir, 'u-'));
    const file = path.join(dir, found.file.name);
    this._set({ status: 'downloading', progress: 0, message: '' });
    const hash = crypto.createHash('sha256');
    let size = 0;
    await httpsGet(url, socks, (res) => new Promise((resolve, reject) => {
      const out = fs.createWriteStream(file, { mode: 0o700, flags: 'wx' });
      let shown = -1;
      res.on('data', (d) => {
        size += d.length;
        if (size > found.file.size) { res.destroy(); out.destroy(); reject(new Error('файл больше заявленного в манифесте')); return; }
        hash.update(d);
        const pct = Math.floor((size / found.file.size) * 100);
        if (pct !== shown) { shown = pct; this._set({ progress: pct }); }
      });
      res.on('error', reject);
      out.on('error', reject);
      out.on('finish', resolve);
      res.pipe(out);
    }));
    if (size !== found.file.size || hash.digest('hex') !== found.file.sha256) {
      fs.rmSync(dir, { recursive: true, force: true });
      throw new Error('скачанный установщик не совпал с манифестом выпуска');
    }
    return file;
  }

  // Скачивает и устанавливает обновление. dryRun — только скачать и проверить.
  // Возвращает 'installed' (Linux: нужен перезапуск), 'restarting' (Windows:
  // установщик запущен и сам перезапустит приложение) или 'verified' при dryRun.
  async install({ dryRun = false } = {}) {
    if (this.busy) return null;
    this.busy = true;
    try {
      const file = await this.download();
      if (dryRun) { this._set({ status: 'available', message: 'Установщик скачан и проверен' }); return 'verified'; }
      this._set({ status: 'installing', progress: 100, message: '' });
      if (WIN) {
        // Установщик работает молча, сам закрывает приложение и запускает новую версию.
        spawn(file, ['/S', '--force-run'], { detached: true, stdio: 'ignore' }).unref();
        return 'restarting';
      }
      await this._installDeb(file, this.available);
      fs.rmSync(path.dirname(file), { recursive: true, force: true });
      this.available = null;
      this._set({ status: 'installed', message: '' });
      return 'installed';
    } catch (e) {
      this._set({ status: 'error', message: 'Обновление не установлено: ' + e.message });
      return null;
    } finally {
      this.busy = false;
    }
  }

  _installDeb(file, found) {
    return new Promise((resolve, reject) => {
      const stage = ['sh', '-c', ROOT_STAGE, 'brauser-update', file, found.file.sha256, found.file.name];
      // От обычного пользователя права запрашивает системное окно (polkit).
      const [cmd, args] = process.getuid() === 0 ? [stage[0], stage.slice(1)] : ['pkexec', stage];
      const p = spawn(cmd, args, { stdio: ['ignore', 'ignore', 'pipe'] });
      let err = '';
      p.stderr.on('data', (d) => { err = (err + d).slice(-400); });
      p.on('error', (e) => reject(new Error(e.code === 'ENOENT' ? 'не найдена программа pkexec — установите обновление командой из README' : e.message)));
      p.on('exit', (code) => {
        if (code === 0) resolve();
        else if (code === 126 || code === 127) reject(new Error('установка отменена: пароль не введён'));
        else reject(new Error((err.trim().split('\n').pop() || 'установщик пакетов завершился с ошибкой') + ` (код ${code})`));
      });
    });
  }
}

module.exports = { Updater, verifyManifest, compareVersions, socksConnect, fetchSmall, MANIFEST_URL };
