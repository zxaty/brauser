'use strict';
// Создаёт ключ подписи выпусков (Ed25519). Запускается один раз:
//   node scripts/make-release-key.js
//
// Закрытый ключ кладётся ВНЕ репозитория — в ~/.brauser/release-key.pem.
// Им подписывается манифест каждого выпуска (scripts/sign-release.js).
// Открытый ключ записывается в src/update-key.js и попадает в приложение:
// автообновление принимает только выпуски с подписью этого ключа.
//
// Закрытый ключ нужно беречь и хранить его копию в надёжном месте:
//   - потеряете — уже установленные копии не смогут обновляться автоматически;
//   - утечёт — подпись перестанет что-либо гарантировать.
// Существующий ключ скрипт не перезаписывает.

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const dir = path.join(os.homedir(), '.brauser');
const keyFile = process.env.BRAUSER_RELEASE_KEY || path.join(dir, 'release-key.pem');
const pubFile = path.join(__dirname, '..', 'src', 'update-key.js');

if (fs.existsSync(keyFile)) {
  console.error(`Ключ уже существует: ${keyFile}\nПерезаписывать его нельзя — установленные копии доверяют именно ему.`);
  process.exit(1);
}

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
fs.mkdirSync(path.dirname(keyFile), { recursive: true, mode: 0o700 });
fs.writeFileSync(keyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });

const pem = publicKey.export({ type: 'spki', format: 'pem' }).trim();
fs.writeFileSync(pubFile, [
  "'use strict';",
  '// Открытый ключ подписи выпусков Brauser (Ed25519). Создан scripts/make-release-key.js.',
  '// Автообновление принимает манифест выпуска только с подписью парного закрытого',
  '// ключа, который хранится у автора вне репозитория.',
  '',
  'module.exports = `' + pem + '`;',
  '',
].join('\n'));

console.log(`Закрытый ключ: ${keyFile}`);
console.log(`Открытый ключ записан в src/update-key.js`);
console.log('Сделайте резервную копию закрытого ключа и никому его не передавайте.');
