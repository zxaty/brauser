#!/bin/sh
# Проверяет подлинность закреплённых хешей Tor Browser по PGP-подписи.
# Запускается при сборке Linux-пакета (scripts/build-linux.sh), вручную:
#   sh scripts/verify-signature.sh
#
# 1. Ключ разработчиков Tor Browser берётся из keys/ в репозитории, и его
#    отпечаток сверяется с записанным здесь.
# 2. Этим ключом проверяется подпись списка контрольных сумм выпуска.
# 3. Оба хеша из src/bundles.js (Linux и Windows) должны быть в этом списке.
# Так закреплённые в коде хеши подтверждаются подписью Tor Project, а не
# только тем, что файл однажды скачали с их сайта.
set -eu

FPR="EF6E286DDA85EA2A4BA7DE684E2C6E8793298290"
key="keys/tor-browser-developers.asc"
version=$(node -e "process.stdout.write(require('./src/bundles').TOR_BROWSER_VERSION)")
sums="vendor/sha256sums-signed-build.txt"
sig="$sums.asc"
base="https://dist.torproject.org/torbrowser/$version"

command -v gpg >/dev/null 2>&1 || { echo "Не найдена программа gpg." >&2; exit 1; }
mkdir -p vendor
[ -f "$sums" ] || wget -q -O "$sums" "$base/sha256sums-signed-build.txt"
[ -f "$sig" ] || wget -q -O "$sig" "$base/sha256sums-signed-build.txt.asc"

GNUPGHOME=$(mktemp -d)
export GNUPGHOME
trap 'rm -rf "$GNUPGHOME"' EXIT
chmod 700 "$GNUPGHOME"
gpg --batch --quiet --import "$key" 2>/dev/null

if ! gpg --batch --with-colons --fingerprint 2>/dev/null | grep -q "^fpr:::::::::$FPR:"; then
  echo "В $key лежит не тот ключ: ожидается отпечаток $FPR." >&2
  exit 1
fi

status=$(gpg --batch --status-fd 1 --verify "$sig" "$sums" 2>/dev/null || true)
if ! echo "$status" | grep -q "^\[GNUPG:\] GOODSIG " || ! echo "$status" | grep -Eq "^\[GNUPG:\] VALIDSIG .* $FPR\$"; then
  echo "Подпись списка контрольных сумм Tor Browser $version не подтверждена." >&2
  echo "$status" | grep -E "SIG|KEY" >&2 || true
  exit 1
fi

node -e "
const fs = require('fs');
const { BUNDLES } = require('./src/bundles');
const lines = fs.readFileSync('$sums', 'utf8').split('\n');
for (const [platform, b] of Object.entries(BUNDLES)) {
  if (!lines.includes(b.sha256 + '  ' + b.file)) {
    console.error('Хеш для ' + platform + ' (' + b.file + ') из src/bundles.js отсутствует в подписанном списке.');
    process.exit(1);
  }
}
"
echo "Tor Browser $version: подпись списка контрольных сумм верна, закреплённые хеши в нём есть."
