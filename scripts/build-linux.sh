#!/bin/sh
# Сборка .deb-пакета. Запускать на Linux из корня проекта:
#   sh scripts/build-linux.sh
# На Windows этот скрипт запускается внутри Docker — см. scripts/build-linux.ps1.
set -e

archive=$(ls vendor/tor-expert-bundle-linux-x86_64-*.tar.gz | head -n 1)
rm -rf tor-linux
mkdir tor-linux
tar -xzf "$archive" -C tor-linux

npm install --no-audit --no-fund
npx electron-builder --linux deb --x64
ls -lh dist/*.deb
