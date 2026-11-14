'use strict';
// Режим Basic: обычный быстрый браузер с вкладками на встроенном Chromium.
// Без Tor и без подмены отпечатка — соединение прямое, вход на сайты
// сохраняется между запусками. Из защиты только блокировка трекеров и
// запрет сайтам лезть к камере, гео и уведомлениям.

const { BrowserWindow, WebContentsView, session } = require('electron');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { isBlocked } = require('./blocklist');
const { searchUrl } = require('./search');

const START_URL = pathToFileURL(path.join(__dirname, 'ui', 'start.html')).href;
const TOOLBAR_H = 84;

let win = null;
let ses = null;
let activeId = null;
let nextTabId = 1;
let blocked = 0;
const tabs = new Map(); // id -> { id, view }

function getSession() {
  if (ses) return ses;
  ses = session.fromPartition('persist:basic');
  // Убираем из User-Agent упоминание Electron и названия приложения — так сайты
  // видят обычный Chrome и не ломаются.
  // Версию Chrome сокращаем до старшего номера, как это делает сам Chrome.
  ses.setUserAgent(ses.getUserAgent().replace(/\s(?:Electron|brauser)\/\S+/gi, '').replace(/Chrome\/(\d+)\.[\d.]+/, 'Chrome/$1.0.0.0'));
  const harmless = new Set(['fullscreen', 'clipboard-sanitized-write', 'pointerLock']);
  ses.setPermissionRequestHandler((_wc, permission, cb) => cb(harmless.has(permission)));
  ses.setPermissionCheckHandler((_wc, permission) => harmless.has(permission));
  ses.webRequest.onBeforeRequest({ urls: ['http://*/*', 'https://*/*', 'ws://*/*', 'wss://*/*'] }, (details, cb) => {
    if (details.resourceType !== 'mainFrame') {
      let host = '';
      try { host = new URL(details.url).hostname; } catch { /* странный URL — пропускаем */ }
      if (isBlocked(host)) {
        blocked++;
        sendState();
        return cb({ cancel: true });
      }
    }
    cb({});
  });
  return ses;
}

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
  if (statePending || !win) return;
  statePending = true;
  setImmediate(() => {
    statePending = false;
    if (!win || win.isDestroyed()) return;
    win.webContents.send('basic-state', { tabs: [...tabs.values()].map(tabInfo), activeId, blocked });
  });
}

function layout() {
  if (!win || win.isDestroyed()) return;
  const [w, h] = win.getContentSize();
  for (const { id, view } of tabs.values()) {
    const visible = id === activeId;
    view.setVisible(visible);
    if (visible) view.setBounds({ x: 0, y: TOOLBAR_H, width: w, height: Math.max(0, h - TOOLBAR_H) });
  }
}

function toUrl(input) {
  const s = String(input || '').trim();
  if (!s) return START_URL;
  if (/^https?:\/\//i.test(s)) return s;
  // Прочие схемы (file:, javascript:, chrome: …) из адресной строки не открываем.
  if (!/\s/.test(s) && !/^[a-z][a-z0-9+.-]*:(?!\d)/i.test(s) && /^(localhost|[^\s/?#]+\.[^\s/?#.]{2,})(:\d+)?([/?#].*)?$/i.test(s)) return 'https://' + s;
  return searchUrl(s);
}

const activeWc = () => (tabs.get(activeId) ? tabs.get(activeId).view.webContents : null);

// Горячие клавиши работают и в интерфейсе, и внутри страниц.
function attachShortcuts(wc) {
  wc.on('before-input-event', (event, input) => {
    if (input.type !== 'keyDown' || !(input.control || input.meta) || input.alt) return;
    const key = input.key.toLowerCase();
    const actions = {
      t: () => createTab(),
      w: () => activeId && closeTab(activeId),
      l: () => { win.webContents.focus(); win.webContents.send('focus-address'); },
      r: () => activeWc() && activeWc().reload(),
    };
    if (actions[key]) { event.preventDefault(); actions[key](); }
  });
}

function createTab(url) {
  const view = new WebContentsView({
    webPreferences: { session: getSession(), sandbox: true, contextIsolation: true, nodeIntegration: false },
  });
  const wc = view.webContents;
  const tab = { id: nextTabId++, view };
  tabs.set(tab.id, tab);

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
  attachShortcuts(wc);

  win.contentView.addChildView(view);
  activateTab(tab.id);
  tab.loaded = wc.loadURL(url || START_URL).catch(() => {});
  return tab;
}

function activateTab(id) {
  if (!tabs.has(id)) return;
  activeId = id;
  layout();
  sendState();
}

function closeTab(id) {
  const tab = tabs.get(id);
  if (!tab) return;
  const ids = [...tabs.keys()];
  const idx = ids.indexOf(id);
  tabs.delete(id);
  try { win.contentView.removeChildView(tab.view); } catch { /* окно уже закрыто */ }
  if (!tab.view.webContents.isDestroyed()) tab.view.webContents.close();
  if (!tabs.size) { win.close(); return; }
  if (activeId === id) activateTab(ids[idx + 1] ?? ids[idx - 1]);
  else sendState();
}

function open({ show = true } = {}) {
  if (win) { if (win.isMinimized()) win.restore(); win.focus(); return win; }
  win = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 720,
    minHeight: 480,
    backgroundColor: '#14161a',
    autoHideMenuBar: true,
    show,
    title: 'Brauser — Basic',
    webPreferences: {
      preload: path.join(__dirname, 'ui', 'preload.js'),
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  win.setMenuBarVisibility(false);
  win.loadFile(path.join(__dirname, 'ui', 'basic.html'));
  win.webContents.on('will-navigate', (e) => e.preventDefault());
  attachShortcuts(win.webContents);
  win.on('resize', layout);
  win.on('closed', () => {
    for (const { view } of tabs.values()) if (!view.webContents.isDestroyed()) view.webContents.close();
    tabs.clear();
    activeId = null;
    win = null;
  });
  createTab();
  return win;
}

function registerIpc(ipcMain) {
  const fromBasic = (fn) => (event, arg) => { if (win && event.sender === win.webContents) return fn(arg); };
  ipcMain.handle('basic:state', fromBasic(() => sendState()));
  ipcMain.handle('tab:new', fromBasic(() => { createTab(); }));
  ipcMain.handle('tab:close', fromBasic((id) => closeTab(id)));
  ipcMain.handle('tab:activate', fromBasic((id) => activateTab(id)));
  ipcMain.handle('nav:go', fromBasic((input) => {
    const wc = activeWc();
    if (!wc) return;
    wc.loadURL(toUrl(input)).catch(() => {});
    wc.focus();
  }));
  ipcMain.handle('nav:back', fromBasic(() => { const wc = activeWc(); if (wc && wc.navigationHistory.canGoBack()) wc.navigationHistory.goBack(); }));
  ipcMain.handle('nav:forward', fromBasic(() => { const wc = activeWc(); if (wc && wc.navigationHistory.canGoForward()) wc.navigationHistory.goForward(); }));
  ipcMain.handle('nav:reload', fromBasic(() => { const wc = activeWc(); if (wc) wc.isLoading() ? wc.stop() : wc.reload(); }));
}

module.exports = { open, registerIpc, tabs, isOpen: () => !!win };
