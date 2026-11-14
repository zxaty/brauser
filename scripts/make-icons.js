'use strict';
// Растеризует assets/brand/logo.svg в PNG нужных размеров.
// Запуск:  npx electron scripts/make-icons.js
const { app, BrowserWindow } = require('electron');
const fs = require('node:fs');
const path = require('node:path');

const brand = path.join(__dirname, '..', 'assets', 'brand');
const SIZES = [16, 32, 48, 64, 128, 192, 256, 384, 512];
const BASE = 1024;

app.disableHardwareAcceleration();
app.whenReady().then(async () => {
  // Один раз рисуем логотип крупно, остальные размеры получаем уменьшением.
  const win = new BrowserWindow({
    width: BASE, height: BASE, show: false, frame: false, transparent: true, useContentSize: true,
    webPreferences: { offscreen: true },
  });
  await win.loadFile(path.join(brand, 'logo.svg'));
  await new Promise((r) => setTimeout(r, 500));
  const base = await win.webContents.capturePage();
  for (const size of SIZES) {
    fs.writeFileSync(path.join(brand, `icon${size}.png`), base.resize({ width: size, height: size, quality: 'best' }).toPNG());
  }
  // Значок самого приложения для electron-builder.
  const build = path.join(__dirname, '..', 'build');
  fs.mkdirSync(build, { recursive: true });
  fs.copyFileSync(path.join(brand, 'icon512.png'), path.join(build, 'icon.png'));
  console.log('icons written, base ' + base.getSize().width);
  app.quit();
});
