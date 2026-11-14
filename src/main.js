'use strict';
const { app, BrowserWindow, WebContentsView, session, ipcMain, Menu } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const { pathToFileURL } = require('node:url');

const { createPersona } = require('./persona');
const { buildInjection } = require('./inject');
const { TorManager } = require('./tor');
const { isBlocked } = require('./blocklist');
const { parseProxyList } = require('./proxy');

const SELFTEST = process.argv.includes('--selftest');
const START_URL = pathToFileURL(path.join(__dirname, 'ui', 'start.html')).href;
const TOOLBAR_H = 84;
const TRACE = process.env.BRAUSER_TRACE;
const trace = (m) => { if (TRACE) fs.appendFileSync(TRACE, m + '\n'); };

const DEFAULTS = {
  mode: 'direct',        // direct | tor | proxy
  proxies: [],           // строки вида socks5://host:port
  proxyIndex: 0,
  rotateMinutes: 0,      // 0 — автосмена IP выключена
  torPath: '',
  bridges: '',
  blockTrackers: true,
  spoof: true,
  timezone: 'auto',      // auto | utc | system
  checkIp: true,
};

// WebRTC не должен ходить в обход прокси и светить реальный IP.
app.commandLine.appendSwitch('force-webrtc-ip-handling-policy', 'disable_non_proxied_udp');

let win = null;
let settings = { ...DEFAULTS };
let tor = null;
let identity = null;
let identityCount = 0;
let busy = false;
let panelOpen = false;
let rotateTimer = null;
let realIp = null;   // настоящий IP пользователя (узнаётся один раз, только для схемы маршрута)
let circuit = null;  // текущая цепочка Tor
let activeId = null;
let nextTabId = 1;
const tabs = new Map(); // id -> { id, view }

// ---------------------------------------------------------------- настройки

const settingsFile = () => path.join(app.getPath('userData'), 'settings.json');

function loadSettings() {
  try {
    settings = { ...DEFAULTS, ...JSON.parse(fs.readFileSync(settingsFile(), 'utf8')) };
  } catch { settings = { ...DEFAULTS }; }
  if (SELFTEST) settings = { ...DEFAULTS, checkIp: false };
  if (SELFTEST && process.argv.includes('--tor')) settings = { ...settings, mode: 'tor', checkIp: true, bridges: process.env.BRAUSER_BRIDGES || '' };
}

function saveSettings() {
  if (SELFTEST) return;
  try { fs.writeFileSync(settingsFile(), JSON.stringify(settings, null, 2)); } catch { /* не критично */ }
}

// ---------------------------------------------------------------- состояние для интерфейса

function tabInfo({ id, view }) {
  const wc = view.webContents;
  const url = wc.getURL();
  const internal = !url || url === START_URL;
  return {
    id,
    title: internal ? 'Новая вкладка' : (wc.getTitle() || url),
    url: internal ? '' : url,
    loading: wc.isLoading(),
    canGoBack: wc.navigationHistory.canGoBack(),
    canGoForward: wc.navigationHistory.canGoForward(),
  };
}

let statePending = false;
function sendState() {
  if (statePending || !win || win.isDestroyed()) return;
  statePending = true;
  setImmediate(() => {
    statePending = false;
    if (!win || win.isDestroyed()) return;
    const proxies = parseProxyList(settings.proxies);
    win.webContents.send('state', {
      tabs: [...tabs.values()].map(tabInfo),
      activeId,
      busy,
      settings,
      tor: { status: tor.status, progress: tor.progress, message: tor.message },
      proxyCount: proxies.length,
      route: identity && {
        real: settings.mode === 'direct' ? (identity.ip ? { ip: identity.ip, country: identity.country } : null) : (settings.checkIp ? realIp : null),
        circuit,
        proxy: identity.proxy ? { scheme: identity.proxy.scheme, host: identity.proxy.host, port: identity.proxy.port } : null,
        exit: identity.ip ? { ip: identity.ip, country: identity.country } : null,
      },
      identity: identity && {
        n: identity.n,
        ip: identity.ip,
        country: identity.country,
        timezone: effectiveTimezone() || 'системный',
        blocked: identity.blocked,
        proxy: identity.proxy ? identity.proxy.label : null,
        persona: {
          userAgent: identity.persona.userAgent,
          platformVersion: identity.persona.uaMetadata.platformVersion,
          cores: identity.persona.hardwareConcurrency,
          memory: identity.persona.deviceMemory,
          screen: `${identity.persona.screen.width}×${identity.persona.screen.height}`,
          gpu: identity.persona.gpu.renderer,
        },
      },
    });
  });
}

function notify(text) {
  if (win && !win.isDestroyed()) win.webContents.send('notice', text);
}

// ---------------------------------------------------------------- сеть

function currentProxy() {
  const list = parseProxyList(settings.proxies);
  if (!list.length) return null;
  return list[settings.proxyIndex % list.length];
}

async function applyProxy() {
  const ses = identity.ses;
  identity.proxy = null;
  if (settings.mode === 'tor') {
    // Запасного «прямого» маршрута нет: если Tor не работает, сеть просто недоступна.
    await ses.setProxy({ proxyRules: tor.socksRules, proxyBypassRules: '<-loopback>' });
  } else if (settings.mode === 'proxy' && currentProxy()) {
    identity.proxy = currentProxy();
    await ses.setProxy({ proxyRules: identity.proxy.rules, proxyBypassRules: '<-loopback>' });
  } else {
    await ses.setProxy({ mode: 'direct' });
  }
  await ses.closeAllConnections();
}

// Узнаём внешний IP (и часовой пояс по нему) запросом через текущую сессию,
// то есть через тот же прокси/Tor, что и страницы.
async function lookupIp() {
  await lookupExitIp();
  await refreshRoute();
}

// Данные для схемы маршрута: узлы цепочки Tor и настоящий IP пользователя.
async function refreshRoute() {
  circuit = null;
  if (settings.mode === 'tor' && tor.status === 'ready') {
    try { circuit = await tor.circuit(identity.ip); } catch { circuit = null; }
  }
  // Настоящий IP нужен только чтобы показать начало маршрута. Запрос идёт
  // напрямую, мимо прокси, поэтому делается один раз и только если показ IP включён.
  if (settings.checkIp && settings.mode !== 'direct' && !realIp) {
    try {
      const direct = session.fromPartition('direct-probe');
      await direct.setProxy({ mode: 'direct' });
      const res = await direct.fetch('https://ipwho.is/', { signal: AbortSignal.timeout(8000), cache: 'no-store' });
      const d = await res.json();
      if (d && d.ip) realIp = { ip: d.ip, country: d.country_code || null };
    } catch { /* без него схема просто покажет «ваш IP» */ }
  }
}

async function lookupExitIp() {
  const id = identity;
  id.ip = null; id.country = null; id.geoTimezone = null;
  if (!settings.checkIp) return;
  if (settings.mode === 'tor' && tor.status !== 'ready') return;
  const get = async (url) => {
    const res = await id.ses.fetch(url, { signal: AbortSignal.timeout(12_000), cache: 'no-store' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return res.json();
  };
  try {
    const d = await get('https://ipwho.is/');
    if (!d || d.success === false || !d.ip) throw new Error('нет данных');
    id.ip = d.ip;
    id.country = d.country_code || null;
    id.geoTimezone = (d.timezone && d.timezone.id) || null;
  } catch {
    try { id.ip = (await get('https://api.ipify.org?format=json')).ip || null; } catch { /* сеть недоступна */ }
  }
}

function effectiveTimezone() {
  if (!identity || !settings.spoof) return null;
  if (settings.timezone === 'system') return null;
  if (settings.timezone === 'utc') return 'UTC';
  // auto: напрямую — системный пояс (он и так совпадает с IP),
  // через прокси/Tor — пояс выходного IP, а если он неизвестен — UTC.
  if (settings.mode === 'direct') return null;
  return identity.geoTimezone || 'UTC';
}

async function rotateNetwork() {
  if (settings.mode === 'tor') {
    await tor.newnym();
  } else if (settings.mode === 'proxy') {
    const n = parseProxyList(settings.proxies).length;
    if (n) { settings.proxyIndex = (settings.proxyIndex + 1) % n; saveSettings(); }
  }
}

function syncTor() {
  if (settings.mode === 'tor') tor.start({ torPath: settings.torPath, bridges: settings.bridges });
  else tor.stop();
}

function syncRotateTimer() {
  clearInterval(rotateTimer);
  rotateTimer = null;
  const min = Number(settings.rotateMinutes) || 0;
  if (min > 0 && settings.mode !== 'direct') {
    rotateTimer = setInterval(() => { rotateIp(true); }, min * 60_000);
  }
}

// ---------------------------------------------------------------- личность

function configureSession(id) {
  const { ses, persona } = id;
  ses.setUserAgent(persona.userAgent, persona.languages);

  // Сайтам по умолчанию не даём ни геолокацию, ни камеру, ни уведомления.
  const harmless = new Set(['fullscreen', 'clipboard-sanitized-write', 'pointerLock']);
  ses.setPermissionRequestHandler((_wc, permission, cb) => cb(harmless.has(permission)));
  ses.setPermissionCheckHandler((_wc, permission) => harmless.has(permission));

  ses.webRequest.onBeforeRequest({ urls: ['http://*/*', 'https://*/*', 'ws://*/*', 'wss://*/*'] }, (details, cb) => {
    if (settings.blockTrackers && details.resourceType !== 'mainFrame') {
      let host = '';
      try { host = new URL(details.url).hostname; } catch { /* странный URL — пропускаем */ }
      if (isBlocked(host)) {
        id.blocked++;
        sendState();
        return cb({ cancel: true });
      }
    }
    cb({});
  });
}

async function newIdentity({ rotate = true } = {}) {
  if (busy) return;
  busy = true;
  sendState();
  try {
    const old = identity;
    closeAllTabs();
    if (rotate) {
      try { await rotateNetwork(); } catch (e) { notify(e.message); }
    }
    const [w, h] = win.getContentSize();
    identityCount++;
    identity = {
      n: identityCount,
      // Раздел без префикса persist: живёт только в памяти — куки и кэш на диск не пишутся.
      ses: session.fromPartition(`identity-${Date.now()}-${identityCount}`, { cache: true }),
      persona: createPersona({ minWidth: w, minHeight: h }),
      blocked: 0,
      ip: null, country: null, geoTimezone: null, proxy: null,
    };
    configureSession(identity);
    trace('proxy');
    await applyProxy();
    trace('lookup');
    await lookupIp();
    trace('tab');
    await createTab();
    trace('tab done');
    if (old) {
      old.ses.clearStorageData().catch(() => {});
      old.ses.clearCache().catch(() => {});
    }
  } finally {
    busy = false;
    sendState();
  }
}

// Мягкая смена IP: вкладки и куки остаются, меняется только маршрут.
async function rotateIp(silent = false) {
  if (busy || !identity) return;
  if (settings.mode === 'direct') {
    if (!silent) notify('В прямом режиме IP сменить нельзя — включите Tor или прокси в настройках');
    return;
  }
  busy = true;
  sendState();
  try {
    await rotateNetwork();
    await applyProxy();
    await lookupIp();
    await refreshTimezone();
    if (!silent) notify(identity.ip ? `Новый IP: ${identity.ip}` : 'Маршрут сменён');
  } catch (e) {
    notify(e.message);
  } finally {
    busy = false;
    sendState();
  }
}

async function refreshTimezone() {
  const tz = effectiveTimezone();
  if (!tz) return;
  for (const { view } of tabs.values()) {
    const dbg = view.webContents.debugger;
    if (dbg.isAttached()) await dbg.sendCommand('Emulation.setTimezoneOverride', { timezoneId: tz }).catch(() => {});
  }
}

// ---------------------------------------------------------------- подмена отпечатка

async function setupSpoofing(wc) {
  if (!settings.spoof) return;
  const dbg = wc.debugger;
  try { dbg.attach('1.3'); } catch { return; }

  const p = identity.persona;
  const tz = effectiveTimezone();
  const script = buildInjection(p);

  const apply = async (sessionId, isFrame) => {
    const send = async (method, params) => { trace('cdp> ' + method + ' ' + (sessionId || 'root')); await dbg.sendCommand(method, params, sessionId).catch((e) => trace('cdp! ' + method + ' ' + e.message)); trace('cdp< ' + method); };
    await send('Emulation.setUserAgentOverride', {
      userAgent: p.userAgent,
      acceptLanguage: p.languages,
      platform: p.platform,
      userAgentMetadata: p.uaMetadata,
    });
    if (tz) await send('Emulation.setTimezoneOverride', { timezoneId: tz });
    await send('Emulation.setLocaleOverride', { locale: p.locale });
    await send('Emulation.setHardwareConcurrencyOverride', { hardwareConcurrency: p.hardwareConcurrency });
    if (isFrame) {
      await send('Page.enable');
      await send('Page.addScriptToEvaluateOnNewDocument', { source: script, runImmediately: true });
    }
    else await send('Runtime.evaluate', { expression: script });
    // Вложенные фреймы с других сайтов и воркеры живут в отдельных процессах —
    // подключаемся к каждому и придерживаем его запуск, пока не применим подмену.
    await send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true });
    await send('Runtime.runIfWaitingForDebugger');
  };

  dbg.on('message', (_e, method, params) => {
    if (method !== 'Target.attachedToTarget') return;
    const type = params.targetInfo.type;
    apply(params.sessionId, type === 'iframe' || type === 'page');
  });
  await apply(undefined, true);
}

// ---------------------------------------------------------------- вкладки

function layout() {
  if (!win || win.isDestroyed()) return;
  const [w, h] = win.getContentSize();
  for (const { id, view } of tabs.values()) {
    const visible = id === activeId && !panelOpen;
    view.setVisible(visible);
    if (visible) view.setBounds({ x: 0, y: TOOLBAR_H, width: w, height: Math.max(0, h - TOOLBAR_H) });
  }
}

function toUrl(input) {
  const s = String(input || '').trim();
  if (!s) return START_URL;
  if (/^https?:\/\//i.test(s)) return s;
  if (/^[a-z][a-z0-9+.-]*:/i.test(s) && !/^[^\s/:]+:\d+/.test(s)) {
    // Прочие схемы (file:, javascript:, chrome: …) из адресной строки не открываем.
    return 'https://duckduckgo.com/?q=' + encodeURIComponent(s);
  }
  if (!/\s/.test(s) && /^(localhost|[^\s/?#]+\.[^\s/?#.]{2,})(:\d+)?([/?#].*)?$/i.test(s)) return 'https://' + s;
  return 'https://duckduckgo.com/?q=' + encodeURIComponent(s);
}

async function createTab(url) {
  const view = new WebContentsView({
    webPreferences: {
      session: identity.ses,
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  const wc = view.webContents;
  const tab = { id: nextTabId++, view };
  tabs.set(tab.id, tab);

  wc.setWebRTCIPHandlingPolicy('disable_non_proxied_udp');
  wc.setWindowOpenHandler(({ url: target }) => {
    if (/^https?:\/\//i.test(target)) createTab(target);
    return { action: 'deny' };
  });
  wc.on('will-navigate', (event, target) => {
    if (!/^https?:\/\//i.test(target) && target !== START_URL) event.preventDefault();
  });
  for (const ev of ['page-title-updated', 'did-navigate', 'did-navigate-in-page', 'did-start-loading', 'did-stop-loading']) {
    wc.on(ev, sendState);
  }

  win.contentView.addChildView(view);
  activateTab(tab.id);
  // Команды отладчика выполняются только когда у вкладки уже есть процесс
  // отрисовки, поэтому сначала открываем пустую страницу, применяем подмену
  // и лишь затем идём по настоящему адресу.
  if (settings.spoof) {
    await wc.loadURL('about:blank').catch(() => {});
    if (wc.isDestroyed()) return tab;
    await setupSpoofing(wc);
    if (wc.isDestroyed()) return tab;
    wc.once('did-finish-load', () => { if (!wc.isDestroyed()) wc.navigationHistory.clear(); });
  }
  tab.loaded = wc.loadURL(url || START_URL).catch(() => {});
  return tab;
}

function activateTab(id) {
  if (!tabs.has(id)) return;
  activeId = id;
  layout();
  sendState();
}

function destroyTab(tab) {
  tabs.delete(tab.id);
  try { win.contentView.removeChildView(tab.view); } catch { /* окно уже закрыто */ }
  if (!tab.view.webContents.isDestroyed()) tab.view.webContents.close();
}

function closeTab(id) {
  const tab = tabs.get(id);
  if (!tab) return;
  const ids = [...tabs.keys()];
  const idx = ids.indexOf(id);
  destroyTab(tab);
  if (!tabs.size) { activeId = null; createTab(); return; }
  if (activeId === id) activateTab(ids[idx + 1] ?? ids[idx - 1]);
  else sendState();
}

function closeAllTabs() {
  for (const tab of [...tabs.values()]) destroyTab(tab);
  activeId = null;
}

const activeWc = () => (tabs.get(activeId) ? tabs.get(activeId).view.webContents : null);

// ---------------------------------------------------------------- окно и IPC

function createWindow() {
  win = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 720,
    minHeight: 480,
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
  win.loadFile(path.join(__dirname, 'ui', 'index.html'));
  win.on('resize', layout);
  win.webContents.on('console-message', (e) => trace('ui console: ' + e.message));
  win.on('closed', () => { win = null; });

  Menu.setApplicationMenu(Menu.buildFromTemplate([
    {
      label: 'Браузер',
      submenu: [
        { label: 'Новая вкладка', accelerator: 'CmdOrCtrl+T', click: () => identity && !busy && createTab() },
        { label: 'Закрыть вкладку', accelerator: 'CmdOrCtrl+W', click: () => activeId && closeTab(activeId) },
        { label: 'Адресная строка', accelerator: 'CmdOrCtrl+L', click: () => { win.webContents.focus(); win.webContents.send('focus-address'); } },
        { label: 'Обновить', accelerator: 'CmdOrCtrl+R', click: () => activeWc() && activeWc().reload() },
        { label: 'Сменить IP', accelerator: 'CmdOrCtrl+Shift+I', click: () => rotateIp() },
        { label: 'Новая личность', accelerator: 'CmdOrCtrl+Shift+N', click: () => newIdentity() },
        { type: 'separator' },
        { role: 'quit', label: 'Выход' },
      ],
    },
    { role: 'editMenu', label: 'Правка' },
  ]));
}

function registerIpc() {
  ipcMain.handle('state:get', () => { sendState(); });
  ipcMain.handle('tab:new', () => { if (identity && !busy) createTab(); });
  ipcMain.handle('tab:close', (_e, id) => closeTab(id));
  ipcMain.handle('tab:activate', (_e, id) => activateTab(id));
  ipcMain.handle('nav:go', (_e, input) => {
    const wc = activeWc();
    if (!wc) return;
    wc.loadURL(toUrl(input)).catch(() => {});
    wc.focus();
  });
  ipcMain.handle('nav:back', () => { const wc = activeWc(); if (wc && wc.navigationHistory.canGoBack()) wc.navigationHistory.goBack(); });
  ipcMain.handle('nav:forward', () => { const wc = activeWc(); if (wc && wc.navigationHistory.canGoForward()) wc.navigationHistory.goForward(); });
  ipcMain.handle('nav:reload', () => { const wc = activeWc(); if (wc) wc.isLoading() ? wc.stop() : wc.reload(); });
  ipcMain.handle('identity:new', () => newIdentity());
  ipcMain.handle('ip:rotate', () => rotateIp());
  ipcMain.handle('panel:set', (_e, open) => { panelOpen = !!open; layout(); });

  ipcMain.handle('settings:set', async (_e, patch) => {
    const clean = {};
    if (['direct', 'tor', 'proxy'].includes(patch.mode)) clean.mode = patch.mode;
    if (Array.isArray(patch.proxies)) clean.proxies = patch.proxies.map(String).map((s) => s.trim()).filter(Boolean).slice(0, 500);
    if (patch.rotateMinutes !== undefined) clean.rotateMinutes = Math.max(0, Math.min(1440, Number(patch.rotateMinutes) || 0));
    if (typeof patch.torPath === 'string') clean.torPath = patch.torPath.trim();
    if (typeof patch.bridges === 'string') clean.bridges = patch.bridges;
    if (['auto', 'utc', 'system'].includes(patch.timezone)) clean.timezone = patch.timezone;
    for (const k of ['blockTrackers', 'spoof', 'checkIp']) if (typeof patch[k] === 'boolean') clean[k] = patch[k];

    if (clean.mode === 'proxy' && !parseProxyList(clean.proxies ?? settings.proxies).length) {
      notify('Список прокси пуст или в нём нет корректных строк — режим не изменён');
      delete clean.mode;
    }

    const before = settings;
    settings = { ...settings, ...clean };
    if (JSON.stringify(before.proxies) !== JSON.stringify(settings.proxies)) settings.proxyIndex = 0;
    saveSettings();

    const torChanged = before.torPath !== settings.torPath || before.bridges !== settings.bridges;
    if (torChanged && settings.mode === 'tor') tor.stop();
    syncTor();
    syncRotateTimer();

    // Всё, что меняет маршрут или отпечаток, требует новой личности:
    // иначе старые куки свяжут прежний IP с новым.
    const needsIdentity = ['mode', 'spoof', 'timezone'].some((k) => before[k] !== settings[k])
      || JSON.stringify(before.proxies) !== JSON.stringify(settings.proxies) && settings.mode === 'proxy';
    if (needsIdentity) await newIdentity({ rotate: false });
    else sendState();
  });
}

// Прокси с логином и паролем (поддерживается для HTTP/HTTPS-прокси).
app.on('login', (event, _wc, _details, authInfo, callback) => {
  if (authInfo.isProxy && identity && identity.proxy && identity.proxy.username) {
    event.preventDefault();
    callback(identity.proxy.username, identity.proxy.password);
  }
});

async function runSelfTest(tab) {
  const wc = tab.view.webContents;
  trace('selftest loading=' + wc.isLoading() + ' url=' + wc.getURL());
  await tab.loaded;
  trace('selftest exec');
  const result = await wc.executeJavaScript(`(async () => {
    const c = document.createElement('canvas'); c.width = 200; c.height = 50;
    const x = c.getContext('2d'); x.fillStyle = '#f60'; x.fillRect(10, 10, 100, 30); x.fillStyle = '#069'; x.font = '16px Arial'; x.fillText('brauser', 20, 30);
    const gl = document.createElement('canvas').getContext('webgl');
    const ext = gl && gl.getExtension('WEBGL_debug_renderer_info');
    const hints = navigator.userAgentData ? await navigator.userAgentData.getHighEntropyValues(['platformVersion', 'fullVersionList']) : null;
    return {
      userAgent: navigator.userAgent,
      brands: navigator.userAgentData && navigator.userAgentData.brands.map((b) => b.brand),
      platformVersion: hints && hints.platformVersion,
      languages: navigator.languages,
      cores: navigator.hardwareConcurrency,
      memory: navigator.deviceMemory,
      screen: [screen.width, screen.height, screen.availHeight],
      gpu: ext && gl.getParameter(ext.UNMASKED_RENDERER_WEBGL),
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      canvasStable: c.toDataURL() === c.toDataURL(),
      canvasHash: c.toDataURL().length + ':' + c.toDataURL().slice(-24),
      looksNative: [HTMLCanvasElement.prototype.toDataURL, WebGLRenderingContext.prototype.getParameter, Function.prototype.toString]
        .every((f) => /\\[native code\\]/.test(Function.prototype.toString.call(f))),
    };
  })()`);
  return result;
}

app.whenReady().then(async () => {
  loadSettings();
  app.configureHostResolver({
    secureDnsMode: 'automatic',
    secureDnsServers: ['https://cloudflare-dns.com/dns-query', 'https://dns.quad9.net/dns-query'],
  });

  tor = new TorManager({ dataDir: path.join(app.getPath('userData'), 'tor-data'), appDir: app.isPackaged ? process.resourcesPath : app.getAppPath() }); // в установленной версии Tor лежит в resources/tor
  let wasReady = false;
  tor.on('change', async () => {
    sendState();
    const ready = tor.status === 'ready';
    if (ready && !wasReady && identity && settings.mode === 'tor') {
      wasReady = true;
      await lookupIp();
      await refreshTimezone();
      sendState();
    }
    if (!ready) wasReady = false;
  });

  registerIpc();
  createWindow();
  syncTor();
  syncRotateTimer();
  await newIdentity({ rotate: false });

  if (SELFTEST) {
    try {
      const first = await runSelfTest([...tabs.values()][0]);
      const persona1 = identity.persona;
      await newIdentity({ rotate: false });
      const second = await runSelfTest([...tabs.values()][0]);
      if (process.env.BRAUSER_SMOKE_URL) {
        // Доп. проверка: страница с чужим фреймом и воркером не должна зависать.
        const wc = [...tabs.values()][0].view.webContents;
        await wc.loadURL(process.env.BRAUSER_SMOKE_URL);
        await new Promise((r) => setTimeout(r, 3000));
        second.smoke = await wc.executeJavaScript('window.__result');
        second.smokeExpected = { memory: identity.persona.deviceMemory, cores: identity.persona.hardwareConcurrency, blocked: identity.blocked };
      }
      if (settings.mode === 'tor') {
        // Ждём подключения Tor (до 2 минут), затем дважды меняем цепочку.
        for (let i = 0; i < 240 && tor.status === 'starting'; i++) await new Promise((r) => setTimeout(r, 500));
        second.tor = { status: tor.status, progress: tor.progress, message: tor.message, ips: [] };
        if (tor.status === 'ready') {
          await lookupIp();
          second.tor.ips.push([identity.ip, identity.country, effectiveTimezone()]);
          for (let i = 0; i < 2; i++) { await rotateIp(true); second.tor.ips.push([identity.ip, identity.country, effectiveTimezone()]); }
        }
      }
      second.route = { circuit, realKnown: !!realIp };
      await new Promise((r) => setTimeout(r, 300));
      second.ui = await win.webContents.executeJavaScript(`(async () => {
        document.getElementById('gear').click();
        await new Promise((r) => setTimeout(r, 200));
        return {
          tabs: [...document.querySelectorAll('.tab .title')].map((n) => n.textContent),
          chip: document.getElementById('chip').textContent,
          panelOpen: !document.getElementById('panel').hidden,
          mode: document.querySelector('input[name=mode]:checked')?.value,
          personaRows: document.querySelectorAll('#persona dt').length,
          torStatus: document.getElementById('torstatus').textContent,
        };
      })()`);
      if (process.env.BRAUSER_SHOT) {
        win.show();
        await new Promise((r) => setTimeout(r, 1200));
        fs.writeFileSync(process.env.BRAUSER_SHOT, (await win.webContents.capturePage()).toPNG());
      }
      console.log('SELFTEST ' + JSON.stringify({ expected: { cores: persona1.hardwareConcurrency, gpu: persona1.gpu.renderer, screen: persona1.screen.width }, first, second }, null, 2));
    } catch (e) {
      console.log('SELFTEST FAILED ' + (e && e.stack || e));
    }
    app.quit();
  }
});

app.on('window-all-closed', () => app.quit());
app.on('before-quit', () => { if (tor) tor.stop(); clearInterval(rotateTimer); });
