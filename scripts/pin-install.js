'use strict';
// Закрепляет в install.sh версию и SHA-256 собранного .deb-пакета.
// Запускать после сборки пакета и ДО публикации релиза:
//   node scripts/pin-install.js
// install.sh после этого ставит именно этот файл и никакой другой.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const { version } = require('../package.json');
const deb = path.join(root, 'dist', `brauser_${version}_amd64.deb`);
if (!fs.existsSync(deb)) {
  console.error(`Нет файла dist/brauser_${version}_amd64.deb — сначала соберите пакет.`);
  process.exit(1);
}

const sha256 = crypto.createHash('sha256').update(fs.readFileSync(deb)).digest('hex');
const file = path.join(root, 'install.sh');
const before = fs.readFileSync(file, 'utf8');
const after = before
  .replace(/^version="[^"]*"$/m, `version="${version}"`)
  .replace(/^sha256="[^"]*"$/m, `sha256="${sha256}"`);
if (!after.includes(`version="${version}"`) || !after.includes(`sha256="${sha256}"`)) {
  console.error('В install.sh не найдены строки version= и sha256=.');
  process.exit(1);
}
fs.writeFileSync(file, after);
console.log(`install.sh: версия ${version}, sha256 ${sha256}`);
