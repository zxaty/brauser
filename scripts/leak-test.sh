#!/bin/sh
# Тест утечек режима Secured. Запускается ВНУТРИ контейнера от root
# (см. scripts/leak-test.ps1):  sh leak-test.sh /deb/brauser_X_amd64.deb
#
# Записывает весь сетевой трафик контейнера, пока Brauser в режиме Secured
# открывает сайты, и проверяет:
#   1) нет ни одного DNS-запроса и вообще ни одного UDP-пакета наружу;
#   2) все исходящие TCP-соединения идут только на узлы сети Tor
#      (адреса сверяются со списком узлов, который скачал сам Tor);
#   3) нет прямых соединений с адресами открытых сайтов.
# Код выхода 0 — утечек нет, 1 — есть, 2 — тест не смог выполниться.
set -eu

deb=$1
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq tcpdump xvfb xauth dnsutils "$deb" >/dev/null 2>&1 || { echo "не удалось установить пакеты" >&2; exit 2; }
id tester >/dev/null 2>&1 || useradd -m tester

# Адреса сайтов узнаём ДО начала записи (сам этот запрос в запись не попадёт).
site_ips=$(dig +short check.torproject.org 2>/dev/null | grep -E '^[0-9.]+$' | sort -u)
me=$(hostname -I | tr ' ' '\n' | grep -E '^[0-9.]+$' | head -n 1)

cap=/tmp/capture.pcap
tcpdump -i any -nn -U -w "$cap" "not host 127.0.0.1 and not ip6 host ::1" >/dev/null 2>&1 &
dump=$!
sleep 2

su tester -c 'cd ~ && timeout 420 xvfb-run -a brauser --no-sandbox --selftest > out.txt 2>/dev/null' || true
sleep 2
kill "$dump" 2>/dev/null || true
wait "$dump" 2>/dev/null || true

out=/home/tester/out.txt
grep -q '"usedOurTor": true' "$out" || { echo "Самопроверка не дошла до открытия сайта через Tor — тест утечек не состоялся." >&2; grep -E 'fatal|status|message' "$out" >&2 || true; exit 2; }

# Узлы сети Tor из согласованного списка, который загрузил Tor.
consensus=/home/tester/.config/Brauser/tor-data/cached-microdesc-consensus
[ -s "$consensus" ] || { echo "Нет списка узлов Tor." >&2; exit 2; }
awk '$1 == "r" { for (i = 2; i <= NF; i++) if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { print $i; break } }' "$consensus" | sort -u > /tmp/relays.txt

# Исходящие пакеты: "IP <мы>.порт > <адрес>.порт: ..."
tcpdump -nn -r "$cap" 2>/dev/null > /tmp/packets.txt || true
grep -E "^[0-9:.]+ +(\S+ +)?(In|Out)? *IP $me\.[0-9]+ > " /tmp/packets.txt > /tmp/outbound.txt || true
[ -s /tmp/outbound.txt ] || grep -E "IP $me\.[0-9]+ > " /tmp/packets.txt > /tmp/outbound.txt || true

total=$(wc -l < /tmp/outbound.txt)
udp=$(grep -cE ": (UDP|[0-9]+[+*-]* )|\.53: " /tmp/outbound.txt || true)
dns=$(grep -cE "\.53: " /tmp/outbound.txt || true)
sed -E "s/.*IP $me\.[0-9]+ > ([0-9.]+)\.[0-9]+: .*/\1/" /tmp/outbound.txt | grep -E '^[0-9.]+$' | sort -u > /tmp/dests.txt
dests=$(wc -l < /tmp/dests.txt)
grep -vxFf /tmp/relays.txt /tmp/dests.txt > /tmp/unknown.txt || true
unknown=$(wc -l < /tmp/unknown.txt)
direct=0
for ip in $site_ips; do if grep -qxF "$ip" /tmp/dests.txt; then direct=$((direct + 1)); echo "ПРЯМОЕ соединение с адресом сайта: $ip"; fi; done

echo "исходящих пакетов: $total"
echo "узлов Tor в списке: $(wc -l < /tmp/relays.txt)"
echo "разных адресов назначения: $dests ($(tr '\n' ' ' < /tmp/dests.txt))"
echo "DNS-запросов наружу: $dns"
echo "UDP-пакетов наружу: $udp"
echo "адресов назначения вне сети Tor: $unknown"
[ "$unknown" -eq 0 ] || { echo "  вне сети Tor:"; sed 's/^/    /' /tmp/unknown.txt; grep -F -f /tmp/unknown.txt /tmp/outbound.txt | head -n 5 | cut -c1-160 | sed 's/^/    /'; }
[ "$dns" -eq 0 ] || { echo "  DNS:"; grep -E "\.53: " /tmp/outbound.txt | head -n 5 | cut -c1-160 | sed 's/^/    /'; }

if [ "$total" -gt 0 ] && [ "$dns" -eq 0 ] && [ "$udp" -eq 0 ] && [ "$unknown" -eq 0 ] && [ "$direct" -eq 0 ]; then
  echo "ИТОГ: утечек не обнаружено — весь трафик ушёл только на узлы Tor."
  exit 0
fi
[ "$total" -gt 0 ] || { echo "ИТОГ: трафик не записан — тест не состоялся."; exit 2; }
echo "ИТОГ: ОБНАРУЖЕНЫ соединения мимо Tor."
exit 1
