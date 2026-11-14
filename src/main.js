'use strict';
// Brauser — панель управления. Страницы открывает немодифицированный движок
// Tor Browser (src/browser.js), подключённый к Tor, который запускает и
// контролирует панель (src/tor.js). Здесь — окно панели, настройки и данные
// для схемы маршрута.

const { app, BrowserWindow, session, ipcMain, Menu } = require('electron');
const path = require('node:path');
const fs = require('node:fs');

const { TorManager } = require('./tor');
const { BrowserEngine } = require('./browser');
const { parseProxy } = require('./proxy');
const basic = require('./basic');

const SELFTEST = process.argv.includes('--selftest');
const TRACE = process.env.BRAUSER_TRACE;
const trace = (m) => { if (TRACE) fs.appendFileSync(TRACE, m + '\n'); };

const DEFAULTS = {
  mode: 'secured',    // secured — движок Tor Browser через Tor; basic — обычный браузер напрямую
  bridges: '',        // мосты, по одному в строке
  exitCountry: '',    // двухбуквенный код страны выхода, пусто — любая
  upstreamProxy: '',  // прокси перед Tor
  checkIp: true,      // показывать свой IP на схеме (один прямой запрос к ipwho.is)
  autoLaunch: true,   // открывать браузер, как только Tor подключился
};

let win = null;
let settings = { ...DEFAULTS };
let tor = null;
let engine = null;
let fatal = '';
let realIp = null;   // настоящий IP пользователя — только для начала схемы
let circuit = null;  // { target, hops } — цепочка последнего соединения
let recent = [];     // последние сайты и их выходные узлы (только в памяти)

// ---------------------------------------------------------------- настройки

const settingsFile = () => path.join(app.getPath('userData'), 'settings.json');

function loadSettings() {
  try {
    const saved = JSON.parse(fs.readFileSync(settingsFile(), 'utf8'));
    settings = { ...DEFAULTS };
    for (const k of Object.keys(DEFAULTS)) if (typeof saved[k] === typeof DEFAULTS[k]) settings[k] = saved[k];
  } catch { settings = { ...DEFAULTS }; }
  if (!['secured', 'basic'].includes(settings.mode)) settings.mode = 'secured';
  if (SELFTEST) settings = { ...DEFAULTS, autoLaunch: false, bridges: process.env.BRAUSER_BRIDGES || '' };
}

function saveSettings() {
  if (SELFTEST) return;
  try { fs.writeFileSync(settingsFile(), JSON.stringify(settings, null, 2)); } catch { /* не критично */ }
}

// ---------------------------------------------------------------- состояние для интерфейса

let statePending = false;
function sendState() {
  if (statePending || !win || win.isDestroyed()) return;
  statePending = true;
  setImmediate(() => {
    statePending = false;
    if (!win || win.isDestroyed()) return;
    const up = parseProxy(settings.upstreamProxy);
    win.webContents.send('state', {
      fatal,
      installing: engine.installing,
      tor: { status: tor.status, progress: tor.progress, message: tor.message },
      browser: { running: engine.running, error: engine.error },
      route: {
        real: settings.checkIp ? realIp : null,
        upstream: up ? { scheme: up.scheme, host: up.host, port: up.port } : null,
        circuit,
      },
      recent,
      settings,
    });
  });
}

function notify(text) {
  if (win && !win.isDestroyed()) win.webContents.send('notice', text);
}

// ---------------------------------------------------------------- Tor и движок

function startTor() {
  circuit = null;
  tor.start(engine.paths, settings);
}

// Настоящий IP нужен только чтобы показать начало маршрута. Запрос идёт
// напрямую, мимо Tor, поэтому делается один раз и только если показ IP включён.
async function probeRealIp() {
  if (!settings.checkIp || realIp) return;
  try {
    const direct = session.fromPartition('direct-probe');
    await direct.setProxy({ mode: 'direct' });
    const res = await direct.fetch('https://ipwho.is/', { signal: AbortSignal.timeout(8000), cache: 'no-store' });
    const d = await res.json();
    if (d && d.ip) realIp = { ip: d.ip, country: d.country_code || null };
  } catch { /* без него схема просто покажет «ваш IP» */ }
  sendState();
}

let streamTimer = null;
let lastStream = null;
function onStream(stream) {
  trace('stream ' + stream.target + ' circuit ' + stream.circuitId);
  lastStream = stream;
  clearTimeout(streamTimer);
  streamTimer = setTimeout(async () => {
    const { circuitId, target } = lastStream;
    let hops = null;
    try { hops = await tor.circuit(circuitId); } catch { /* цепочка уже закрыта */ }
    if (!hops) return;
    circuit = { target, hops };
    const exit = hops[hops.length - 1];
    recent = [{ target, ip: exit.ip, country: exit.country }, ...recent.filter((r) => r.target !== target)].slice(0, 8);
    sendState();
  }, 300);
}

function launchBrowser(url) {
  if (engine.running) return notify('Браузер уже открыт');
  if (tor.status !== 'ready') return notify('Tor ещё не подключён — браузер откроется после подключения');
  engine.launch(tor.cookieFile, url);
}

// Tor и движок нужны только режиму Secured — в Basic ничего лишнего не запускается.
let booting = null;
function boot() {
  if (!booting) booting = bootSecured().finally(() => { booting = null; });
  return booting;
}

async function bootSecured() {
  if (tor.status === 'starting' || tor.status === 'ready') return;
  fatal = '';
  try {
    await engine.ensureInstalled();
  } catch (e) {
    fatal = 'Не удалось подготовить движок Tor Browser: ' + e.message;
    sendState();
    return;
  }
  startTor();
}

// ---------------------------------------------------------------- окно и IPC

function createWindow() {
  win = new BrowserWindow({
    width: 1040,
    height: 760,
    minWidth: 760,
    minHeight: 520,
    backgroundColor: '#14161a',
    autoHideMenuBar: true,
    show: !SELFTEST,
    webPreferences: {
      preload: path.join(__dirname, 'ui', 'preload.js'),
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  win.setMenuBarVisibility(false);
  Menu.setApplicationMenu(null);
  win.loadFile(path.join(__dirname, 'ui', 'index.html'));
  win.webContents.on('console-message', (e) => trace('ui console: ' + e.message));
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (e) => e.preventDefault());
  win.on('closed', () => { win = null; app.quit(); });
}

function registerIpc() {
  ipcMain.handle('state:get', () => { sendState(); });
  ipcMain.handle('browser:launch', () => launchBrowser());
  ipcMain.handle('basic:open', () => { basic.open(); });
  ipcMain.handle('mode:set', (_e, mode) => {
    if (!['secured', 'basic'].includes(mode) || mode === settings.mode) return;
    settings.mode = mode;
    saveSettings();
    if (mode === 'secured') boot();
    else if (!engine.running) tor.stop(); // защищённый браузер закрыт — Tor больше не нужен
    sendState();
  });
  basic.registerIpc(ipcMain);
  ipcMain.handle('tor:newnym', async () => {
    try {
      await tor.newnym();
      circuit = null;
      notify('Готово: следующие соединения пойдут по новым цепочкам');
    } catch (e) { notify(e.message); }
    sendState();
  });
  ipcMain.handle('tor:restart', () => { tor.stop(); startTor(); });

  ipcMain.handle('settings:set', (_e, patch) => {
    const next = { ...settings };
    if (typeof patch.bridges === 'string') next.bridges = patch.bridges.slice(0, 20000);
    if (typeof patch.exitCountry === 'string' && /^([a-z]{2})?$/i.test(patch.exitCountry)) next.exitCountry = patch.exitCountry.toLowerCase();
    if (typeof patch.upstreamProxy === 'string') {
      const value = patch.upstreamProxy.trim();
      if (value && !parseProxy(value)) notify('Адрес прокси не распознан — оставлен прежний');
      else next.upstreamProxy = value;
    }
    for (const k of ['checkIp', 'autoLaunch']) if (typeof patch[k] === 'boolean') next[k] = patch[k];

    const torChanged = ['bridges', 'exitCountry', 'upstreamProxy'].some((k) => next[k] !== settings[k]);
    settings = next;
    saveSettings();
    if (!settings.checkIp) realIp = null;
    else probeRealIp();
    if (torChanged && engine.installed) { tor.stop(); startTor(); }
    sendState();
  });
}

async function runSelfTest() {
  const result = { installed: engine.installed, fatal };
  const waitFor = async (cond, ms) => {
    for (let t = 0; t < ms && !cond(); t += 500) await new Promise((r) => setTimeout(r, 500));
    return cond();
  };
  await waitFor(() => tor.status === 'ready' || tor.status === 'error' || fatal, 180_000);
  result.tor = { status: tor.status, message: tor.message };
  if (tor.status === 'ready') {
    const targets = [];
    tor.on('stream', (s) => targets.push(s.target));
    engine.launch(tor.cookieFile, 'https://check.torproject.org/');
    // Движок должен выйти в сеть через НАШ Tor: ждём его соединение с проверочным сайтом.
    result.usedOurTor = await waitFor(() => targets.includes('check.torproject.org'), 120_000);
    result.browserRunning = engine.running;
    await new Promise((r) => setTimeout(r, 1500));
    result.targets = [...new Set(targets)].slice(0, 12);
    result.circuit = circuit;
    if (process.env.BRAUSER_SHOT) {
      win.show();
      await new Promise((r) => setTimeout(r, 1200));
      fs.writeFileSync(process.env.BRAUSER_SHOT, (await win.webContents.capturePage()).toPNG());
    }
  }
  // Режим Basic: окно с вкладкой открывается, User-Agent без упоминания Electron.
  const bw = basic.open({ show: false });
  const tab = [...basic.tabs.values()][0];
  await tab.loaded;
  result.basic = {
    title: tab.view.webContents.getTitle(),
    userAgent: await tab.view.webContents.executeJavaScript('navigator.userAgent'),
    ui: await bw.webContents.executeJavaScript("({ tabs: document.querySelectorAll('.tab').length, chip: document.getElementById('chip').textContent })"),
  };
  result.panel = await win.webContents.executeJavaScript("({ pill: document.getElementById('pill').textContent, nodes: [...document.querySelectorAll('#routeflow .node .role')].map((n) => n.textContent), recent: document.querySelectorAll('#recent .site').length })");
  console.log('SELFTEST ' + JSON.stringify(result, null, 2));
  app.quit();
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });

  app.whenReady().then(async () => {
    loadSettings();
    const userData = app.getPath('userData');
    engine = new BrowserEngine({
      root: path.join(userData, 'tor-browser'),
      bundleDirs: [path.join(process.resourcesPath, 'tor-browser-bundle'), path.join(app.getAppPath(), 'vendor')],
    });
    tor = new TorManager({ dataDir: path.join(userData, 'tor-data') });

    let wasReady = false;
    tor.on('change', () => {
      const ready = tor.status === 'ready';
      if (ready && !wasReady) {
        probeRealIp();
        if (settings.autoLaunch && settings.mode === 'secured' && !engine.running) engine.launch(tor.cookieFile);
      }
      wasReady = ready;
      sendState();
    });
    tor.on('stream', onStream);
    engine.on('change', () => {
      // Защищённый браузер закрыли, а режим уже Basic — останавливаем и Tor.
      if (!engine.running && settings.mode === 'basic' && tor.status !== 'stopped') tor.stop();
      sendState();
    });

    registerIpc();
    createWindow();
    probeRealIp();
    const started = settings.mode === 'secured' ? boot() : Promise.resolve();
    if (SELFTEST) { await started; runSelfTest().catch((e) => { console.log('SELFTEST FAILED ' + (e && e.stack || e)); app.quit(); }); }
  });

  // Закрытие панели завершает всё; окно Basic можно закрывать отдельно.
  app.on('window-all-closed', () => app.quit());
  // Панель закрывается вместе с движком: без нашего Tor он всё равно не выйдет в сеть.
  app.on('before-quit', () => { if (engine) engine.stop(); if (tor) tor.stop(); });
}
