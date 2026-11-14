#!/bin/sh
# Установка Brauser на Linux Mint / Ubuntu / Debian (64-бит) одной командой:
#   wget -qO- https://raw.githubusercontent.com/zxaty/brauser/main/install.sh | sh
#
# Скрипт ставит одну конкретную версию: её номер и SHA-256 пакета закреплены
# ниже. Пакет скачивается по фиксированному адресу релиза. Перед установкой он
# копируется в каталог, принадлежащий root, и контрольная сумма сверяется уже у
# этой копии: после проверки файл не может изменить никто, кроме root.
# При выпуске новой версии обновляются обе строки (scripts/pin-install.js
# делает это по собранному пакету).
set -eu

repo="zxaty/brauser"
version="1.2.0"
sha256="27d8416bb90473a151697646e0e80628ef5d1592dfe449a8b7f36824997f5375"

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

# Ранняя сверка — чтобы не просить пароль sudo ради заведомо негодного файла.
# Решающая сверка выполняется ниже, от имени root.
if ! echo "$sha256  $dir/$file" | sha256sum -c --status -; then
  echo "Контрольная сумма пакета не совпадает с закреплённой — установка отменена." >&2
  echo "  ожидается: $sha256" >&2
  echo "  получено:  $(sha256sum "$dir/$file" | cut -d' ' -f1)" >&2
  exit 1
fi

# Часть, выполняемая от имени root. Аргументы: исходный файл, SHA-256, имя пакета.
# Пакет копируется в новый каталог root (0700 на время проверки), сверяется и
# только потом открывается на чтение для apt. Устанавливается именно эта копия.
root_stage='
set -eu
src=$1; sum=$2; name=$3
umask 077
work=$(mktemp -d /var/tmp/brauser-install.XXXXXXXX)
trap "rm -rf \"$work\"" EXIT
cp -- "$src" "$work/$name"
if ! echo "$sum  $work/$name" | sha256sum -c --status -; then
  echo "Контрольная сумма пакета не совпадает с закреплённой — установка отменена." >&2
  exit 1
fi
echo "Контрольная сумма совпадает."
chmod 755 "$work"
chmod 644 "$work/$name"
apt install -y "$work/$name"
'

if [ "$(id -u)" -eq 0 ]; then
  sh -c "$root_stage" brauser-install "$dir/$file" "$sha256" "$file"
else
  sudo sh -c "$root_stage" brauser-install "$dir/$file" "$sha256" "$file"
fi

echo
echo "Готово. Запуск: brauser (или из меню приложений, раздел «Интернет»)."
