#!/bin/sh
# Установка Brauser на Linux Mint / Ubuntu / Debian (64-бит) одной командой:
#   wget -qO- https://raw.githubusercontent.com/zxaty/brauser/main/install.sh | sh
#
# Скрипт ставит одну конкретную версию: её номер и SHA-256 пакета закреплены
# ниже. Пакет скачивается по фиксированному адресу релиза и передаётся в apt
# только после сверки контрольной суммы — подменённый файл в релизе или по
# дороге установлен не будет. При выпуске новой версии обновляются обе строки
# (scripts/pin-install.js делает это по собранному пакету).
set -eu

repo="zxaty/brauser"
version="1.1.0"
sha256="ce066b27c4f9e0fe2264211bd35b4e22c305a9500dc9b8b2d6d2094522f957cf"

if [ "$(uname -m)" != "x86_64" ]; then
  echo "Brauser собран только для 64-битных процессоров x86 (у вас $(uname -m))." >&2
  exit 1
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  echo "Не найдена программа sha256sum — без неё пакет нельзя проверить." >&2
  exit 1
fi

file="brauser_${version}_amd64.deb"
url="https://github.com/$repo/releases/download/v$version/$file"

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
echo "Скачиваю $url"
wget -q --show-progress --https-only -O "$dir/$file" "$url"

if ! echo "$sha256  $dir/$file" | sha256sum -c --status -; then
  echo "Контрольная сумма пакета не совпадает с закреплённой — установка отменена." >&2
  echo "  ожидается: $sha256" >&2
  echo "  получено:  $(sha256sum "$dir/$file" | cut -d' ' -f1)" >&2
  exit 1
fi
echo "Контрольная сумма совпадает."

# apt читает пакет от имени пользователя _apt — открываем доступ на чтение.
chmod 755 "$dir"
chmod 644 "$dir/$file"

if [ "$(id -u)" -eq 0 ]; then
  apt install -y "$dir/$file"
else
  sudo apt install -y "$dir/$file"
fi

echo
echo "Готово. Запуск: brauser (или из меню приложений, раздел «Интернет»)."
