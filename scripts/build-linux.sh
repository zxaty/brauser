#!/bin/sh
# Сборка .deb-пакета. Запускать на Linux из корня проекта:
#   sh scripts/build-linux.sh
# На Windows этот скрипт запускается внутри Docker — см. scripts/build-linux.ps1.
# В vendor/ должен лежать архив Tor Browser, закреплённый в src/bundles.js (см. README).
set -e

node scripts/verify-vendor.js linux
npm install --no-audit --no-fund
npx electron-builder --linux deb --x64
ls -lh dist/*.deb
