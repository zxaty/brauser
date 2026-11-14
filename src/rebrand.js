'use strict';
// Оформление движка под Brauser: название, логотипы и стартовая страница.
// Меняется только «оболочка» Tor Browser — строки названия и картинки в архиве
// ресурсов интерфейса. Код, сетевые настройки и всё, что видят сайты, не
// трогается, поэтому отпечаток остаётся таким же, как у обычного Tor Browser.
//
// После автообновления движка архив ресурсов заменяется новым, и правки
// накладываются заново при следующем запуске (см. метку рядом с архивом).

const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { unzipSync, zipSync, strFromU8, strToU8 } = require('fflate');
const { searchTemplate } = require('./search');

const PATCH_VERSION = '2';
const BRAND = 'Brauser';

// Картинки внутри архива ресурсов -> файлы из assets/brand.
const IMAGES = {
  'about-logo.svg': 'logo.svg',
  'about-logo-small.svg': 'logo.svg',
  'about-logo.png': 'icon192.png',
  'about-logo@2x.png': 'icon384.png',
  'about-wordmark.svg': 'wordmark.svg',
  'icon16.png': 'icon16.png',
  'icon32.png': 'icon32.png',
  'icon48.png': 'icon48.png',
  'icon64.png': 'icon64.png',
  'icon128.png': 'icon128.png',
  'icon256.png': 'icon256.png',
};

const stamp = (file) => {
  const s = fs.statSync(file);
  return `${PATCH_VERSION}:${s.size}:${Math.round(s.mtimeMs)}`;
};

function patchResources(browserDir, assetsDir) {
  const omni = path.join(browserDir, 'browser', 'omni.ja');
  const marker = omni + '.brauser';
  let done = '';
  try { done = fs.readFileSync(marker, 'utf8'); } catch { /* ещё не накладывали */ }
  if (done === stamp(omni)) return false;

  const files = unzipSync(fs.readFileSync(omni));
  const out = {};
  for (const [name, data] of Object.entries(files)) {
    if (name.endsWith('/')) continue; // записи каталогов движку не нужны
    const base = name.slice(name.lastIndexOf('/') + 1);
    if (/\/branding\/brand\.ftl$/.test(name)) {
      // В каждом языке своё название («Браузер Tor» и т. п.), иногда со склонениями
      // на несколько строк — заменяем значение целиком.
      out[name] = strToU8(strFromU8(data).replace(/^(-brand-[a-z-]*name)[ \t]*=.*(?:\r?\n[ \t]+.*)*/gm, '$1 = ' + BRAND));
    } else if (/\/branding\/brand\.properties$/.test(name)) {
      out[name] = strToU8(strFromU8(data).replace(/^(brand[A-Za-z]*Name)[ \t]*=.*$/gm, '$1=' + BRAND));
    } else if (name.startsWith('chrome/browser/content/branding/') && IMAGES[base]) {
      out[name] = fs.readFileSync(path.join(assetsDir, IMAGES[base]));
    } else {
      out[name] = data;
    }
  }
  const tmp = omni + '.tmp';
  fs.writeFileSync(tmp, zipSync(out, { level: 6 }));
  fs.renameSync(tmp, omni);
  fs.writeFileSync(marker, stamp(omni));
  return true;
}

// Linux: значок окна (его показывает панель задач) лежит отдельными файлами.
function patchWindowIcons(browserDir, assetsDir) {
  const dir = path.join(browserDir, 'browser', 'chrome', 'icons', 'default');
  for (const size of [16, 32, 48, 64, 128]) {
    const target = path.join(dir, `default${size}.png`);
    if (fs.existsSync(target)) fs.copyFileSync(path.join(assetsDir, `icon${size}.png`), target);
  }
}

// Движок кэширует разобранные ресурсы интерфейса — после правки кэш сбрасываем.
function purgeStartupCache(browserDir) {
  const data = path.join(browserDir, 'TorBrowser', 'Data', 'Browser');
  for (const dir of [path.join(data, 'Caches', 'profile.default', 'startupCache'), path.join(data, 'profile.default', 'startupCache')]) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// Своя стартовая страница: локальный файл, в сеть при открытии не ходит.
function installStartPage(root, browserDir, startPage) {
  const target = path.join(root, 'brauser-start.html');
  fs.copyFileSync(startPage, target);
  const profile = path.join(browserDir, 'TorBrowser', 'Data', 'Browser', 'profile.default');
  fs.mkdirSync(profile, { recursive: true });
  const url = pathToFileURL(target).href;
  // В user.js меняется только наша строка: остальные настройки, которые там
  // мог оставить пользователь (в том числе настройки защиты), сохраняются.
  const file = path.join(profile, 'user.js');
  const MARK = '// brauser: стартовая страница';
  let kept = [];
  try {
    kept = fs.readFileSync(file, 'utf8').split(/\r?\n/).filter((line) => line.trim()
      && !line.includes(MARK)
      && !line.startsWith('// Создано Brauser')
      && !/^\s*user_pref\(\s*"browser\.startup\.homepage"\s*,/.test(line));
  } catch { /* файла ещё нет */ }
  fs.writeFileSync(file, [...kept, `user_pref("browser.startup.homepage", ${JSON.stringify(url)}); ${MARK}`, ''].join('\n'));
}

// Поиск из адресной строки: тот же DuckDuckGo, но с параметрами оформления и под
// нейтральным названием. Задаётся штатным механизмом политик движка.
function installSearchPolicy(browserDir, assetsDir) {
  const dir = path.join(browserDir, 'distribution');
  const file = path.join(dir, 'policies.json');
  let doc = {};
  try { doc = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { /* файла ещё нет */ }
  doc.policies = doc.policies || {};
  doc.policies.SearchEngines = {
    Add: [{
      Name: BRAND,
      URLTemplate: searchTemplate,
      Method: 'GET',
      IconURL: 'data:image/png;base64,' + fs.readFileSync(path.join(assetsDir, 'icon32.png')).toString('base64'),
      Alias: '@b',
      Description: 'Поиск ' + BRAND,
    }],
    Default: BRAND,
  };
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(file, JSON.stringify(doc, null, 2) + '\n');
}

// Возвращает true, если ресурсы движка были изменены в этот раз.
function apply({ root, assetsDir, startPage }) {
  const browserDir = path.join(root, 'Browser');
  const changed = patchResources(browserDir, assetsDir);
  if (changed) {
    patchWindowIcons(browserDir, assetsDir);
    purgeStartupCache(browserDir);
  }
  installStartPage(root, browserDir, startPage);
  installSearchPolicy(browserDir, assetsDir);
  return changed;
}

module.exports = { apply };
