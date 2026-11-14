'use strict';
// Движок: официальный Tor Browser без изменений. Мы только распаковываем его
// в папку данных пользователя (там он может сам обновляться) и запускаем,
// указав через переменные окружения, что Tor уже запущен панелью.

const { EventEmitter } = require('node:events');
const { spawn, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { SOCKS_PORT, CONTROL_PORT } = require('./tor');

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

  _findBundle() {
    const pattern = WIN ? /^tor-browser-windows-x86_64-portable-.*\.exe$/ : /^tor-browser-linux-x86_64-.*\.tar\.xz$/;
    for (const dir of this.bundleDirs) {
      let names = [];
      try { names = fs.readdirSync(dir); } catch { continue; }
      const hit = names.filter((n) => pattern.test(n)).sort().pop();
      if (hit) return path.join(dir, hit);
    }
    return null;
  }

  // Первая установка: распаковка архива Tor Browser из поставки.
  async ensureInstalled() {
    if (this.installed) return;
    const bundle = this._findBundle();
    if (!bundle) throw new Error('В поставке нет архива Tor Browser');
    this.installing = true;
    this.emit('change');
    try {
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

  launch(cookieFile, url) {
    if (this.proc) return;
    this.error = '';
    const env = {
      ...process.env,
      // Tor Browser не запускает свой Tor, а подключается к нашему.
      TOR_PROVIDER: 'none',
      TOR_SKIP_LAUNCH: '1',
      TOR_SOCKS_HOST: '127.0.0.1',
      TOR_SOCKS_PORT: String(SOCKS_PORT),
      TOR_CONTROL_HOST: '127.0.0.1',
      TOR_CONTROL_PORT: String(CONTROL_PORT),
      TOR_CONTROL_COOKIE_AUTH_FILE: cookieFile,
    };
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
