'use strict';
const { contextBridge, ipcRenderer } = require('electron');

const CHANNELS = new Set([
  // панель управления
  'state:get', 'mode:set', 'browser:launch', 'basic:open', 'tor:newnym', 'tor:restart', 'settings:set', 'proxy:resolve', 'tor:newcircuit', 'bridges:builtin',
  // окно обычного браузера
  'basic:state', 'tab:new', 'tab:close', 'tab:activate', 'nav:go', 'nav:back', 'nav:forward', 'nav:reload', 'basic:to-secured',
]);

contextBridge.exposeInMainWorld('api', {
  call: (channel, arg) => {
    if (!CHANNELS.has(channel)) throw new Error('Неизвестный канал: ' + channel);
    return ipcRenderer.invoke(channel, arg);
  },
  onState: (cb) => ipcRenderer.on('state', (_e, state) => cb(state)),
  onBasicState: (cb) => ipcRenderer.on('basic-state', (_e, state) => cb(state)),
  onNotice: (cb) => ipcRenderer.on('notice', (_e, text) => cb(text)),
  onFocusAddress: (cb) => ipcRenderer.on('focus-address', () => cb()),
});
