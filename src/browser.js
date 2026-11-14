'use strict';
// Движок: официальный Tor Browser. Мы распаковываем его в папку данных
// пользователя (там он может сам обновляться) и запускаем, указав через
// переменные окружения, что Tor уже запущен панелью. Архив из поставки
// запускается только после сверки SHA-256 с закреплённым в src/bundles.js.

const { EventEmitter } = require('node:events');
const { spawn, spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { BUNDLES } = require('./bundles');

const WIN = process.platform === 'win32';

class BrowserEngine extends EventEmitter {
  // root — куда ставится Tor Browser; bundleDirs — где искать архив из поставки.
  constructor({ root, bundleDirs }) {
    super();
    this.root = root;
    this.bundleDirs = bundleDirs;
    this.proc = null;
    this.installing = false;
    this.error = '';
  }

  get paths() {
    const browserDir = path.join(this.root, 'Browser');
    const torDir = path.join(browserDir, 'TorBrowser', 'Tor');
    return {
      browserDir,
      exe: path.join(browserDir, WIN ? 'firefox.exe' : 'start-tor-browser'),
      tor: path.join(torDir, WIN ? 'tor.exe' : 'tor'),
      lyrebird: path.join(torDir, 'PluggableTransports', WIN ? 'lyrebird.exe' : 'lyrebird'),
      // Базы стран лежат в Data/Tor (Linux) или рядом с tor.exe (Windows).
      geoipDir: [path.join(browserDir, 'TorBrowser', 'Data', 'Tor'), torDir].find((d) => fs.existsSync(path.join(d, 'geoip'))) || torDir,
    };
  }

  get installed() { return fs.existsSync(this.paths.exe) && fs.existsSync(this.paths.tor); }
  get running() { return !!this.proc; }

  // Архив ищется только под закреплённым именем: другой файл, даже похожий, не подойдёт.
  _findBundle() {
    const bundle = BUNDLES[process.platform];
    if (!bundle) return null;
    for (const dir of this.bundleDirs) {
      const file = path.join(dir, bundle.file);
      if (fs.existsSync(file)) return { file, sha256: bundle.sha256 };
    }
    return null;
  }

  // Сверяет SHA-256 архива с закреплённым. Подменённый или повреждённый архив
  // не будет ни запущен, ни распакован.
  _verifyBundle({ file, sha256 }) {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash('sha256');
      fs.createReadStream(file)
        .on('data', (chunk) => hash.update(chunk))
        .on('error', reject)
        .on('end', () => {
          const actual = hash.digest('hex');
          if (actual === sha256) resolve();
          else reject(new Error(`архив Tor Browser не прошёл проверку подлинности (SHA-256 ${actual.slice(0, 16)}… не совпадает с закреплённым)`));
        });
    });
  }

  // Первая установка: распаковка архива Tor Browser из поставки.
  async ensureInstalled() {
    if (this.installed) return;
    const found = this._findBundle();
    if (!found) throw new Error('В поставке нет архива Tor Browser');
    const bundle = found.file;
    this.installing = true;
    this.emit('change');
    try {
      await this._verifyBundle(found);
      fs.rmSync(this.root, { recursive: true, force: true });
      fs.mkdirSync(this.root, { recursive: true });
      // Windows: «портативный» установщик Tor Browser, тихий режим, папка через /D=
      // (по правилам NSIS этот ключ идёт последним и без кавычек).
      const [cmd, args, opts] = WIN
        ? [bundle, ['/S', `/D=${this.root}`], { windowsVerbatimArguments: true }]
        : ['tar', ['-xJf', bundle, '-C', this.root, '--strip-components=1'], {}];
      await new Promise((resolve, reject) => {
        const p = spawn(cmd, args, { windowsHide: true, stdio: 'ignore', ...opts });
        p.on('error', reject);
        p.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`распаковка завершилась с кодом ${code}`))));
      });
      if (!this.installed) throw new Error('после распаковки не найден Tor Browser в ' + this.root);
    } finally {
      this.installing = false;
      this.emit('change');
    }
  }

  // connection — TorManager.connection: файл cookie и либо Unix-сокеты, либо TCP-порты.
  launch(connection, url) {
    if (this.proc) return;
    this.error = '';
    const env = {
      ...process.env,
      // Tor Browser не запускает свой Tor, а подключается к нашему.
      TOR_PROVIDER: 'none',
      TOR_SKIP_LAUNCH: '1',
      TOR_CONTROL_COOKIE_AUTH_FILE: connection.cookieFile,
    };
    // Прежние значения из окружения не должны увести движок к чужому Tor.
    for (const k of ['TOR_SOCKS_HOST', 'TOR_SOCKS_PORT', 'TOR_SOCKS_IPC_PATH', 'TOR_CONTROL_HOST', 'TOR_CONTROL_PORT', 'TOR_CONTROL_IPC_PATH', 'TOR_CONTROL_PASSWD']) delete env[k];
    if (connection.socksPath) {
      env.TOR_SOCKS_IPC_PATH = connection.socksPath;
      env.TOR_CONTROL_IPC_PATH = connection.controlPath;
    } else {
      env.TOR_SOCKS_HOST = '127.0.0.1';
      env.TOR_SOCKS_PORT = String(connection.socksPort);
      env.TOR_CONTROL_HOST = '127.0.0.1';
      env.TOR_CONTROL_PORT = String(connection.controlPort);
    }
    const args = [];
    if (WIN) args.push('-wait-for-browser'); // иначе процесс-загрузчик сразу завершится
    if (url) args.push(url);
    const proc = spawn(this.paths.exe, args, { env, cwd: this.paths.browserDir, detached: !WIN, stdio: 'ignore' });
    this.proc = proc;
    proc.on('error', (e) => {
      if (this.proc === proc) this.proc = null;
      this.error = 'Не удалось запустить браузер: ' + e.message;
      this.emit('change');
    });
    const startedAt = Date.now();
    proc.on('exit', (code) => {
      this.lastExit = { code, afterMs: Date.now() - startedAt };
      if (this.proc === proc) this.proc = null;
      this.emit('change');
    });
    this.emit('change');
  }

  stop() {
    const proc = this.proc;
    this.proc = null;
    if (!proc || !proc.pid) return;
    try {
      if (WIN) spawnSync('taskkill', ['/pid', String(proc.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
      else process.kill(-proc.pid, 'SIGTERM'); // вся группа процессов браузера
    } catch { /* уже завершён */ }
  }
}

module.exports = { BrowserEngine };
