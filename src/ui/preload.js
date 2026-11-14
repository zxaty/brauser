'use strict';
const { contextBridge, ipcRenderer } = require('electron');

const CHANNELS = new Set([
  'state:get', 'tab:new', 'tab:close', 'tab:activate',
  'nav:go', 'nav:back', 'nav:forward', 'nav:reload',
  'identity:new', 'ip:rotate', 'panel:set', 'settings:set',
]);

contextBridge.exposeInMainWorld('api', {
  call: (channel, arg) => {
    if (!CHANNELS.has(channel)) throw new Error('Неизвестный канал: ' + channel);
    return ipcRenderer.invoke(channel, arg);
  },
  onState: (cb) => ipcRenderer.on('state', (_e, state) => cb(state)),
  onNotice: (cb) => ipcRenderer.on('notice', (_e, text) => cb(text)),
  onFocusAddress: (cb) => ipcRenderer.on('focus-address', () => cb()),
});
