#!/bin/sh
# Установка Brauser на Linux Mint / Ubuntu / Debian (64-бит) одной командой:
#   wget -qO- https://raw.githubusercontent.com/zxaty/brauser/main/install.sh | sh
# Скачивает .deb из последнего релиза на GitHub и ставит его через apt.
set -e

repo="zxaty/brauser"

if [ "$(uname -m)" != "x86_64" ]; then
  echo "Brauser собран только для 64-битных процессоров x86 (у вас $(uname -m))." >&2
  exit 1
fi

url=$(wget -qO- "https://api.github.com/repos/$repo/releases/latest" | grep -o 'https://[^"]*amd64\.deb' | head -n 1)
if [ -z "$url" ]; then
  echo "Не удалось найти .deb в последнем релизе: https://github.com/$repo/releases" >&2
  exit 1
fi

tmp=$(mktemp --suffix=.deb)
trap 'rm -f "$tmp"' EXIT
echo "Скачиваю $url"
wget -q --show-progress -O "$tmp" "$url"
chmod 644 "$tmp"

if [ "$(id -u)" -eq 0 ]; then
  apt install -y "$tmp"
else
  sudo apt install -y "$tmp"
fi

echo
echo "Готово. Запуск: brauser (или из меню приложений, раздел «Интернет»)."
