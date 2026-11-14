# Тест утечек режима Secured в контейнере (нужен запущенный Docker Desktop и собранный .deb).
# Запуск из корня проекта:  npm run test:leaks
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$version = (Get-Content (Join-Path $root 'package.json') -Raw | ConvertFrom-Json).version
$deb = "brauser_${version}_amd64.deb"
if (-not (Test-Path (Join-Path $root "dist\$deb"))) { throw "Нет dist\$deb — сначала соберите пакет: npm run dist:linux:docker" }

# NET_RAW и NET_ADMIN нужны только программе записи трафика внутри контейнера.
docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN -v "${root}\dist:/deb:ro" -v "${root}\scripts:/scripts:ro" ubuntu:24.04 sh /scripts/leak-test.sh "/deb/$deb"
exit $LASTEXITCODE
