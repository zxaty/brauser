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

  // Читает архив в память и сверяет SHA-256 с закреплённым. Дальше используются
  // именно эти проверенные байты, а не файл по тому же пути: подменить архив
  // между проверкой и запуском нельзя. Подменённый или повреждённый архив не
  // будет ни запущен, ни распакован.
  async _readVerifiedBundle({ file, sha256 }) {
    const data = await fs.promises.readFile(file);
    const actual = crypto.createHash('sha256').update(data).digest('hex');
    if (actual !== sha256) {
      throw new Error(`архив Tor Browser не прошёл проверку подлинности (SHA-256 ${actual.slice(0, 16)}… не совпадает с закреплённым)`);
    }
    return data;
  }

  // Первая установка: распаковка архива Tor Browser из поставки.
  async ensureInstalled() {
    if (this.installed) return;
    const found = this._findBundle();
    if (!found) throw new Error('В поставке нет архива Tor Browser');
    this.installing = true;
    this.emit('change');
    // Windows: проверенные байты установщика кладутся в новый каталог со случайным
    // именем внутри папки данных пользователя и запускаются оттуда — файл из
    // поставки после проверки больше не читается, а имя нельзя угадать заранее.
    // От процесса с правами того же пользователя это не защищает: он и так
    // может изменить уже установленный движок.
    let setupDir = null;
    try {
      const data = await this._readVerifiedBundle(found);
      fs.rmSync(this.root, { recursive: true, force: true });
      fs.mkdirSync(this.root, { recursive: true });
      await new Promise((resolve, reject) => {
        let p;
        if (WIN) {
          setupDir = fs.mkdtempSync(path.join(path.dirname(this.root), 'setup-'));
          const setup = path.join(setupDir, 'tor-browser-setup.exe');
          fs.writeFileSync(setup, data, { mode: 0o700, flag: 'wx' }); // только новый файл
          // Перечитываем записанное: запускаться должен ровно проверенный образ.
          if (crypto.createHash('sha256').update(fs.readFileSync(setup)).digest('hex') !== found.sha256) {
            throw new Error('временный файл установщика изменён до запуска');
          }
          // «Портативный» установщик Tor Browser: тихий режим, папка через /D=
          // (по правилам NSIS этот ключ идёт последним и без кавычек).
          p = spawn(setup, ['/S', `/D=${this.root}`], { windowsHide: true, stdio: 'ignore', windowsVerbatimArguments: true });
        } else {
          // Linux: проверенные байты подаются распаковщику на вход.
          p = spawn('tar', ['-xJf', '-', '-C', this.root, '--strip-components=1'], { stdio: ['pipe', 'ignore', 'ignore'] });
          p.stdin.on('error', reject);
          p.stdin.end(data);
        }
        p.on('error', reject);
        p.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`распаковка завершилась с кодом ${code}`))));
      });
      if (!this.installed) throw new Error('после распаковки не найден Tor Browser в ' + this.root);
    } finally {
      if (setupDir) { try { fs.rmSync(setupDir, { recursive: true, force: true }); } catch { /* не критично */ } }
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
    if (WIN) {
      // --allow-remote: разрешить этому экземпляру принимать адреса от повторного
      // запуска (так работает «Открыть в Secured»); без него Tor Browser их отвергает.
      args.push('--allow-remote');
      args.push('-wait-for-browser'); // иначе процесс-загрузчик сразу завершится
    }
    if (url) args.push(url);
    const proc = spawn(this.paths.exe, args, { env, cwd: this.paths.browserDir, detached: !WIN, stdio: 'ignore' });
    this.proc = proc;
    this.launchEnv = env;
    proc.on('error', (e) => {
      if (this.proc === proc) this.proc = null;
      this.error = 'Не удалось запустить браузер: ' + e.message;
      this.emit('change');
    });
    const startedAt = Date.now();
    proc.on('exit', (code) => {
      const afterMs = Date.now() - startedAt;
      this.lastExit = { code, afterMs };
      if (this.proc !== proc) return; // остановлен нами
      // Движок иногда сам перезапускается сразу после старта: исходный процесс
      // завершается, а браузер продолжает работать в новом. Поэтому «закрыт»
      // определяем не по одному процессу, а по тому, жив ли движок вообще.
      this._followRestart(proc, { quickExit: afterMs < 20_000 });
    });
    this.emit('change');
  }

  // Можно ли передать адрес уже работающему движку. На Windows — да: второй вызов
  // исполняемого файла отдаёт адрес работающему экземпляру. На Linux Tor Browser
  // отключает D-Bus, через который Firefox принимает такие команды, — нельзя.
  get canHandOff() { return WIN; }

  // Открывает адрес в защищённом браузере: запускает движок или открывает новую
  // вкладку в уже работающем. Возвращает false, если движок работает, а передать
  // ему адрес на этой системе нельзя.
  open(connection, url) {
    if (!this.proc) { this.launch(connection, url); return true; }
    if (!this.canHandOff) return false;
    try {
      spawn(this.paths.exe, ['--allow-remote', url], { env: this.launchEnv, cwd: this.paths.browserDir, detached: true, stdio: 'ignore' }).unref();
      return true;
    } catch { return false; }
  }

  // Работает ли сейчас хоть один процесс движка, запущенный из нашей установки.
  _alive(proc) {
    if (WIN) {
      // Работающий Firefox держит файл блокировки профиля открытым монопольно.
      const lock = path.join(this.paths.browserDir, 'TorBrowser', 'Data', 'Browser', 'profile.default', 'parent.lock');
      try { fs.closeSync(fs.openSync(lock, 'r+')); return false; } catch (e) { return e.code !== 'ENOENT'; }
    }
    // Linux: браузер запущен отдельной группой процессов; сигнал 0 проверяет, остался ли в ней кто-то.
    try { process.kill(-proc.pid, 0); return true; } catch { return false; }
  }

  _followRestart(proc, { quickExit }) {
    // Новому процессу нужно время, чтобы занять профиль; ждём дольше, если
    // исходный завершился подозрительно быстро.
    let checksLeft = quickExit ? 16 : 3;
    let adopted = false;
    const tick = () => {
      if (this.proc !== proc) return; // остановлен нами
      if (this._alive(proc)) {
        if (!adopted) {
          adopted = true;
          proc.adopted = true;
          this.emit('change');
        }
        checksLeft = 2; // после перезапуска «закрыт» — это два пустых замера подряд
        setTimeout(tick, 2000);
      } else if (--checksLeft > 0) {
        setTimeout(tick, 500);
      } else {
        this.proc = null;
        this.emit('change');
      }
    };
    tick();
  }

  stop() {
    const proc = this.proc;
    this.proc = null;
    if (!proc || !proc.pid) return;
    try {
      if (!WIN) { process.kill(-proc.pid, 'SIGTERM'); return; } // вся группа процессов; Firefox по SIGTERM выходит штатно
      // Windows: сначала просим закрыться по-хорошему (как при нажатии на крестик):
      // принудительное завершение Firefox засчитывает как аварию и может испортить профиль.
      // После самоперезапуска номера процессов неизвестны — ищем их по точному пути
      // к исполняемому файлу, чтобы не задеть другой Firefox.
      const exe = this.paths.exe.replace(/'/g, "''");
      const ours = `Get-CimInstance Win32_Process -Filter "Name='firefox.exe'" | Where-Object { $_.ExecutablePath -eq '${exe}' }`;
      const ps = (command, timeout) => spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', command], { windowsHide: true, stdio: 'ignore', timeout });
      if (proc.adopted) ps(`(${ours}) | ForEach-Object { $p = Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue; if ($p) { [void]$p.CloseMainWindow() } }`, 15_000);
      else spawnSync('taskkill', ['/pid', String(proc.pid), '/T'], { windowsHide: true, stdio: 'ignore' });
      // Ждём до шести секунд, пока движок освободит профиль.
      const until = Date.now() + 6000;
      while (Date.now() < until && this._alive(proc)) spawnSync(process.execPath, ['-e', 'setTimeout(()=>{},250)'], { stdio: 'ignore', env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' } });
      if (!this._alive(proc)) return;
      // Не закрылся сам — завершаем принудительно.
      spawnSync('taskkill', ['/pid', String(proc.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
      if (this._alive(proc)) ps(`(${ours}) | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }`, 20_000);
    } catch { /* уже завершён */ }
  }
}

module.exports = { BrowserEngine };
