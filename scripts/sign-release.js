'use strict';
// Создаёт и подписывает манифест выпуска для автообновления.
// Запускается после сборки обоих установщиков и ДО публикации релиза:
//   node scripts/sign-release.js
// Результат — dist/brauser-update.json и dist/brauser-update.json.sig;
// оба файла загружаются в релиз вместе с установщиками.
//
// Манифест перечисляет установщики этого выпуска с их размерами и SHA-256.
// Подписываются байты манифеста целиком, поэтому подменить в нём версию,
// имя файла или хеш, не имея закрытого ключа, нельзя.

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.join(__dirname, '..');
const { version } = require('../package.json');
const keyFile = process.env.BRAUSER_RELEASE_KEY || path.join(os.homedir(), '.brauser', 'release-key.pem');
if (!fs.existsSync(keyFile)) {
  console.error(`Нет закрытого ключа ${keyFile} — создайте его: node scripts/make-release-key.js`);
  process.exit(1);
}

const FILES = {
  win32: `Brauser-Setup-${version}.exe`,
  linux: `brauser_${version}_amd64.deb`,
};

const files = {};
for (const [platform, name] of Object.entries(FILES)) {
  const file = path.join(root, 'dist', name);
  if (!fs.existsSync(file)) {
    console.error(`Нет файла dist/${name} — сначала соберите оба установщика.`);
    process.exit(1);
  }
  const data = fs.readFileSync(file);
  files[platform] = { name, size: data.length, sha256: crypto.createHash('sha256').update(data).digest('hex') };
}

const manifest = Buffer.from(JSON.stringify({ name: 'brauser', version, date: new Date().toISOString().slice(0, 10), files }, null, 2) + '\n');
const privateKey = crypto.createPrivateKey(fs.readFileSync(keyFile));
const signature = crypto.sign(null, manifest, privateKey);

// Подпись должна проверяться ключом, зашитым в приложение: иначе выпуск никто не примет.
const publicKey = crypto.createPublicKey(require('../src/update-key'));
if (!crypto.verify(null, manifest, publicKey, signature)) {
  console.error('Закрытый ключ не соответствует открытому из src/update-key.js — подпись бесполезна.');
  process.exit(1);
}

fs.writeFileSync(path.join(root, 'dist', 'brauser-update.json'), manifest);
fs.writeFileSync(path.join(root, 'dist', 'brauser-update.json.sig'), signature.toString('base64') + '\n');
console.log(`Манифест выпуска ${version} подписан: dist/brauser-update.json(.sig)`);
for (const f of Object.values(files)) console.log(`  ${f.sha256}  ${f.name}`);
