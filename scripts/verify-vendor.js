'use strict';
// Сверяет архив Tor Browser в vendor/ с хешем, закреплённым в src/bundles.js.
// Запускается перед сборкой:  node scripts/verify-vendor.js <linux|win32>
// Без аргумента проверяет архив для текущей системы.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { BUNDLES } = require('../src/bundles');

const platform = process.argv[2] || process.platform;
const bundle = BUNDLES[platform];
if (!bundle) {
  console.error(`Для платформы «${platform}» архив Tor Browser не закреплён (src/bundles.js).`);
  process.exit(1);
}

const file = path.join(__dirname, '..', 'vendor', bundle.file);
if (!fs.existsSync(file)) {
  console.error(`Нет файла vendor/${bundle.file} — скачайте его с dist.torproject.org (см. README).`);
  process.exit(1);
}

const hash = crypto.createHash('sha256');
fs.createReadStream(file)
  .on('data', (chunk) => hash.update(chunk))
  .on('error', (e) => { console.error(e.message); process.exit(1); })
  .on('end', () => {
    const actual = hash.digest('hex');
    if (actual !== bundle.sha256) {
      console.error(`SHA-256 файла vendor/${bundle.file} не совпадает с закреплённым.\n  ожидается: ${bundle.sha256}\n  получено:  ${actual}`);
      process.exit(1);
    }
    console.log(`vendor/${bundle.file}: SHA-256 совпадает`);
  });
