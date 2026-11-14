'use strict';
/* global api */

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
};

let state = null;
let formFilled = false;

// ------------------------------------------------------------ схема маршрута

const SVG_NS = 'http://www.w3.org/2000/svg';
const ICONS = {
  you: 'M3 5h18v11H3z M8 20h8 M12 16v4',
  tor: 'M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18z M12 7a5 5 0 1 0 0 10a5 5 0 0 0 0-10z M12 10.5a1.5 1.5 0 1 0 0 3a1.5 1.5 0 0 0 0-3z',
  proxy: 'M4 5h16v6H4z M4 13h16v6H4z M7 8h.01 M7 16h.01',
  site: 'M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18z M3 12h18 M12 3c3 3 3 15 0 18 M12 3c-3 3-3 15 0 18',
};

function icon(name) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('class', 'icon');
  const path = document.createElementNS(SVG_NS, 'path');
  path.setAttribute('d', ICONS[name]);
  svg.append(path);
  return svg;
}

const regionNames = new Intl.DisplayNames(['ru'], { type: 'region' });
function countryName(code) {
  if (!code) return '';
  try { return regionNames.of(code.toUpperCase()); } catch { return code; }
}

function routeNode({ kind, iconName, role, main, sub, extra, progress }) {
  const node = el('div', 'node ' + kind);
  const head = el('div', 'head');
  head.append(icon(iconName), el('span', 'role', role));
  node.append(head, el('div', 'main', main));
  if (sub) node.append(el('div', 'sub', sub));
  if (extra) node.append(el('div', 'extra', extra));
  if (progress !== undefined) {
    const bar = el('div', 'bar');
    const fill = el('span');
    fill.style.width = progress + '%';
    bar.append(fill);
    node.append(bar);
  }
  return node;
}

function drawFlow(box, nodes, linkClass) {
  box.replaceChildren();
  nodes.forEach((n, i) => {
    if (i) box.append(el('div', 'link ' + linkClass));
    box.append(routeNode(n));
  });
}

function youNode() {
  const real = state.route.real;
  return {
    kind: 'you', iconName: 'you', role: 'Вы',
    main: real ? real.ip : 'ваш IP',
    sub: real ? countryName(real.country) : (state.settings.showRealIp ? '' : 'показ IP выключен'),
  };
}

function renderSecuredRoute() {
  const { tor, route, installing } = state;
  const nodes = [youNode()];
  let linkClass = 'secure';
  let note = '';

  if (route.upstream) {
    nodes.push({
      kind: 'proxy', iconName: 'proxy', role: 'Прокси',
      main: route.upstream.host + ':' + route.upstream.port,
      sub: route.upstream.scheme.toUpperCase(),
      extra: 'скрывает Tor от провайдера',
    });
  }

  if (tor.status !== 'ready') {
    const failed = tor.status === 'error';
    nodes.push({
      kind: 'tor' + (failed ? ' failed' : ''), iconName: 'tor', role: 'Сеть Tor',
      main: installing ? 'подготовка…' : failed ? 'нет соединения' : `подключение ${tor.progress}%`,
      sub: installing ? 'распаковка движка Tor Browser' : tor.message,
      progress: failed || installing ? undefined : tor.progress,
    });
    nodes.push({ kind: 'site off', iconName: 'site', role: 'Сайт видит', main: '—', sub: 'трафик заблокирован' });
    linkClass = 'idle';
    note = 'Пока Tor не подключён, защищённый браузер не выпускает трафик наружу — напрямую он не пойдёт.';
  } else if (route.circuit) {
    const roles = ['Входной узел', 'Промежуточный узел', 'Выходной узел'];
    const hops = route.circuit.hops.slice(-3);
    hops.forEach((hop, i) => nodes.push({
      kind: 'tor', iconName: 'tor', role: roles[i + (3 - hops.length)],
      main: hop.ip || 'мост',
      sub: countryName(hop.country),
      extra: hop.nickname,
    }));
    const exit = hops[hops.length - 1];
    nodes.push({
      kind: 'site', iconName: 'site', role: 'Сайт',
      main: route.circuit.target,
      sub: 'видит ' + (exit.ip || 'выходной узел'),
      extra: countryName(exit.country),
    });
    note = 'Цепочка последнего соединения. Входной узел знает ваш IP, но не знает, куда вы идёте. Выходной видит сайт, но не знает, кто вы.';
  } else {
    nodes.push({ kind: 'tor', iconName: 'tor', role: 'Сеть Tor', main: '3 узла', sub: 'подключено', extra: 'цепочка появится после первого сайта' });
    nodes.push({ kind: 'site', iconName: 'site', role: 'Сайт видит', main: 'выходной узел', sub: 'не ваш IP' });
    note = 'Tor подключён. Откройте любой сайт в защищённом браузере — здесь появятся реальные узлы его цепочки.';
  }

  drawFlow($('routeflow'), nodes, linkClass);
  $('routenote').textContent = note;
  $('transport').textContent = tor.transport === 'unix'
    ? 'Локальный доступ к Tor: Unix-сокеты, открытые только вашему пользователю.'
    : 'Локальный доступ к Tor: TCP 127.0.0.1 (порты 9250 и 9251) — другие программы и пользователи этого компьютера тоже могут к нему подключиться.';
}

function renderBasicRoute() {
  const real = state.route.real;
  drawFlow($('basicflow'), [
    youNode(),
    { kind: 'site exposed', iconName: 'site', role: 'Сайт видит', main: real ? real.ip : 'ваш IP', sub: real ? countryName(real.country) : '', extra: 'ваш настоящий IP' },
  ], 'warn');
}

function renderRecent() {
  const box = $('recent');
  box.replaceChildren();
  $('recentcard').hidden = !state.recent.length;
  for (const r of state.recent) {
    box.append(el('span', 'site', r.target), el('span', 'ip', r.ip || '—'), el('span', 'where', countryName(r.country)));
  }
}

// ------------------------------------------------------------ шапка и настройки

function renderTop() {
  const { settings, tor, installing, browser, fatal } = state;
  const secured = settings.mode === 'secured';
  $('mode-secured').classList.toggle('on', secured);
  $('mode-basic').classList.toggle('on', !secured);
  $('view-secured').hidden = !secured;
  $('view-basic').hidden = secured;
  $('fatal').hidden = !fatal;
  $('fatal').textContent = fatal;
  $('blockcard').hidden = !state.blocked;
  $('apply').disabled = state.blocked; // обычные настройки не применяются, пока не решён вопрос с прокси
  $('restart').disabled = state.blocked;

  const pill = $('pill');
  let text = 'Basic · прямое соединение';
  let cls = 'warn';
  if (secured) {
    if (installing) { text = 'Подготовка движка…'; cls = 'warn'; }
    else if (tor.status === 'ready') { text = browser.running ? 'Tor подключён · браузер открыт' : 'Tor подключён'; cls = 'ok'; }
    else if (tor.status === 'starting') { text = `Tor: подключение ${tor.progress}%`; cls = 'warn'; }
    else if (tor.status === 'error') { text = 'Tor не работает'; cls = 'bad'; }
    else { text = 'Tor остановлен'; cls = ''; }
  }
  pill.textContent = text;
  pill.className = 'pill ' + cls;
  pill.title = tor.message || '';

  $('open-secured').disabled = tor.status !== 'ready' || browser.running;
  $('open-secured').textContent = browser.running ? 'Защищённый браузер открыт' : 'Открыть защищённый браузер';
  $('newnym').disabled = tor.status !== 'ready';
}

const EXIT_COUNTRIES = ['de', 'nl', 'fr', 'ch', 'se', 'no', 'fi', 'at', 'pl', 'cz', 'ro', 'gb', 'us', 'ca', 'jp', 'sg'];

function fillForm() {
  const s = state.settings;
  const select = $('exit');
  select.replaceChildren(new Option('Любая (рекомендуется)', ''));
  for (const code of EXIT_COUNTRIES) select.append(new Option(countryName(code), code));
  select.value = s.exitCountry;
  $('upstream').value = s.upstreamProxy;
  $('bridges').value = s.bridges;
  $('checkip').checked = s.showRealIp;
  $('autolaunch').checked = s.autoLaunch;
  formFilled = true;
}

async function applySettings() {
  await api.call('settings:set', {
    exitCountry: $('exit').value,
    upstreamProxy: $('upstream').value,
    bridges: $('bridges').value,
    showRealIp: $('checkip').checked,
    autoLaunch: $('autolaunch').checked,
  });
  formFilled = false;
}

// ------------------------------------------------------------ уведомления и события

let toastTimer = null;
function toast(text) {
  const node = $('toast');
  node.textContent = text;
  node.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { node.hidden = true; }, 5000);
}

$('mode-secured').addEventListener('click', () => api.call('mode:set', 'secured'));
$('mode-basic').addEventListener('click', () => api.call('mode:set', 'basic'));
$('open-secured').addEventListener('click', () => api.call('browser:launch'));
$('open-basic').addEventListener('click', () => api.call('basic:open'));
$('newnym').addEventListener('click', () => api.call('tor:newnym'));
$('restart').addEventListener('click', () => api.call('tor:restart'));
$('apply').addEventListener('click', applySettings);
$('block-set').addEventListener('click', async () => {
  await api.call('proxy:resolve', { action: 'set', value: $('blockproxy').value });
  formFilled = false;
});
$('block-none').addEventListener('click', async () => {
  // Отдельное подтверждение: это решение открывает провайдеру сам факт использования Tor.
  if (!window.confirm('Продолжить без прокси?\n\nTor будет подключаться напрямую, и провайдер увидит, что вы используете Tor.')) return;
  await api.call('proxy:resolve', { action: 'none' });
  formFilled = false;
});

api.onState((next) => {
  state = next;
  renderTop();
  renderSecuredRoute();
  renderBasicRoute();
  renderRecent();
  if (!formFilled) fillForm();
});
api.onNotice(toast);
api.call('state:get');
