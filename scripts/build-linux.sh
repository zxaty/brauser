#!/bin/sh
# Сборка .deb-пакета. Запускать на Linux из корня проекта:
#   sh scripts/build-linux.sh
# На Windows этот скрипт запускается внутри Docker — см. scripts/build-linux.ps1.
# В vendor/ должен лежать архив tor-browser-linux-x86_64-*.tar.xz (см. README).
set -e

ls vendor/tor-browser-linux-x86_64-*.tar.xz >/dev/null
npm install --no-audit --no-fund
npx electron-builder --linux deb --x64
ls -lh dist/*.deb
