# Сборка .deb-пакета для Linux (Mint, Ubuntu, Debian) с Windows через Docker.
# Нужен запущенный Docker Desktop. Запуск из корня проекта:  npm run dist:linux:docker
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
New-Item -ItemType Directory -Force (Join-Path $root 'dist') | Out-Null

# Проект монтируется только для чтения и копируется внутрь контейнера:
# на файловой системе Linux сохраняются права на запуск, которых нет в Windows.
$inner = 'mkdir /build && cd /src && tar --exclude=./node_modules --exclude=./dist --exclude=./tor --exclude=./tor-linux -cf - . | tar -xf - -C /build && cd /build && sh scripts/build-linux.sh && cp dist/*.deb /out/'
docker run --rm -v "${root}:/src:ro" -v "${root}\dist:/out" node:24-bookworm sh -c $inner
if ($LASTEXITCODE -ne 0) { throw "Сборка завершилась с ошибкой (код $LASTEXITCODE)" }
Get-ChildItem (Join-Path $root 'dist') -Filter *.deb | Select-Object Name, @{ n = 'MB'; e = { [math]::Round($_.Length / 1MB, 1) } }
