'use strict';

const SCHEMES = new Set(['http', 'https', 'socks4', 'socks5']);

// Разбирает строку вида  socks5://host:port  |  http://user:pass@host:port  |  host:port
function parseProxy(line) {
  let s = String(line || '').trim();
  if (!s || s.startsWith('#')) return null;
  if (!/^[a-z0-9]+:\/\//i.test(s)) s = 'http://' + s;
  let u;
  try { u = new URL(s); } catch { return null; }
  let scheme = u.protocol.replace(':', '').toLowerCase();
  if (scheme === 'socks') scheme = 'socks5';
  if (!SCHEMES.has(scheme) || !u.hostname || !u.port) return null;
  return {
    scheme,
    host: u.hostname,
    port: Number(u.port),
    username: decodeURIComponent(u.username || ''),
    password: decodeURIComponent(u.password || ''),
    rules: `${scheme}://${u.hostname}:${u.port}`,
    label: `${scheme}://${u.hostname}:${u.port}`,
  };
}

function parseProxyList(lines) {
  return (lines || []).map(parseProxy).filter(Boolean);
}

module.exports = { parseProxy, parseProxyList };
