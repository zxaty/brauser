'use strict';
// Закреплённые архивы движка Tor Browser. Приложение запускает или
// распаковывает архив из поставки, только если его SHA-256 совпадает с
// записанным здесь. Значения взяты из sha256sums-signed-build.txt на
// https://dist.torproject.org/torbrowser/<версия>/ .
//
// При переходе на новую версию Tor Browser меняются имя файла и хеш здесь —
// сборка (scripts/verify-vendor.js) и установка сверяются с этой таблицей.

const TOR_BROWSER_VERSION = '16.0.1';

const BUNDLES = {
  linux: {
    file: `tor-browser-linux-x86_64-${TOR_BROWSER_VERSION}.tar.xz`,
    sha256: '5b36ad610c20c81faa72caf27d1cd3a11f14a327c320b4cec581400016ba78b0',
  },
  win32: {
    file: `tor-browser-windows-x86_64-portable-${TOR_BROWSER_VERSION}.exe`,
    sha256: 'fbef840ba111409213dec2291e3594a43b82525545cdef0490a5750f24f5f232',
  },
};

module.exports = { BUNDLES, TOR_BROWSER_VERSION };
