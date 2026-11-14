'use strict';

const SCHEMES = new Set(['http', 'https', 'socks4', 'socks5']);

// Логин и пароль прокси попадают в конфигурацию Tor, поэтому в них недопустимы
// управляющие символы: перенос строки внутри значения стал бы новой директивой.
// 255 — предел, который Tor сам накладывает на учётные данные SOCKS5.
const safeCredential = (s) => s.length <= 255 && !/[\p{Cc}\p{Zl}\p{Zp}]/u.test(s);
// Имя хоста или IP-адрес (IPv6 — в квадратных скобках), без пробелов и спецсимволов.
const safeHost = (s) => /^(?:[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?|\[[0-9a-f:.]{2,45}\])$/i.test(s);

// Разбирает строку вида  socks5://host:port  |  http://user:pass@host:port  |  host:port
// Возвращает null, если строка не распознана или содержит недопустимые символы.
function parseProxy(line) {
  let s = String(line || '').trim();
  if (!s || s.startsWith('#')) return null;
  if (!/^[a-z0-9]+:\/\//i.test(s)) s = 'http://' + s;
  let u;
  try { u = new URL(s); } catch { return null; }
  let scheme = u.protocol.replace(':', '').toLowerCase();
  if (scheme === 'socks') scheme = 'socks5';
  if (!SCHEMES.has(scheme) || !u.hostname || !u.port) return null;
  if (!safeHost(u.hostname)) return null;

  let username;
  let password;
  try {
    username = decodeURIComponent(u.username || '');
    password = decodeURIComponent(u.password || '');
  } catch { return null; } // оборванная %-последовательность
  if (!safeCredential(username) || !safeCredential(password)) return null;

  return {
    scheme,
    host: u.hostname,
    port: Number(u.port),
    username,
    password,
    rules: `${scheme}://${u.hostname}:${u.port}`,
    label: `${scheme}://${u.hostname}:${u.port}`,
  };
}

function parseProxyList(lines) {
  return (lines || []).map(parseProxy).filter(Boolean);
}

module.exports = { parseProxy, parseProxyList };
