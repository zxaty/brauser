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
let panelOpen = false;

// ------------------------------------------------------------ вкладки и панель навигации

function renderTabs() {
  const box = $('tabs');
  box.replaceChildren();
  for (const tab of state.tabs) {
    const node = el('div', 'tab' + (tab.id === state.activeId ? ' active' : ''));
    node.title = tab.title;
    if (tab.loading) node.append(el('span', 'spinner'));
    node.append(el('span', 'title', tab.title));
    const close = el('button', 'close', '×');
    close.title = 'Закрыть вкладку (Ctrl+W)';
    close.addEventListener('click', (e) => { e.stopPropagation(); api.call('tab:close', tab.id); });
    node.append(close);
    node.addEventListener('click', () => { setPanel(false); api.call('tab:activate', tab.id); });
    node.addEventListener('auxclick', (e) => { if (e.button === 1) api.call('tab:close', tab.id); });
    box.append(node);
  }
}

function renderNav() {
  const active = state.tabs.find((t) => t.id === state.activeId);
  $('back').disabled = !active || !active.canGoBack;
  $('forward').disabled = !active || !active.canGoForward;
  $('reload').textContent = active && active.loading ? '✕' : '⟳';
  const addr = $('addr');
  if (document.activeElement !== addr) addr.value = active ? active.url : '';
  $('rotate').disabled = state.busy;
  $('ident').disabled = state.busy;
  $('newtab').disabled = state.busy;
}

function renderChip() {
  const chip = $('chip');
  const { settings, identity, tor } = state;
  let text = '';
  let cls = '';
  if (state.busy) {
    text = 'Смена маршрута…';
    cls = 'warn';
  } else if (settings.mode === 'tor' && tor.status !== 'ready') {
    if (tor.status === 'starting') { text = `Tor: запуск ${tor.progress}%`; cls = 'warn'; }
    else { text = tor.status === 'missing' ? 'Tor не найден' : 'Tor не работает'; cls = 'bad'; }
  } else {
    const name = { direct: 'Напрямую', tor: 'Tor', proxy: 'Прокси' }[settings.mode];
    const parts = [name];
    if (identity && identity.ip) parts.push(identity.ip + (identity.country ? ' ' + identity.country : ''));
    if (identity && identity.blocked) parts.push(`заблокировано: ${identity.blocked}`);
    text = parts.join(' · ');
    cls = settings.mode === 'direct' ? '' : 'ok';
  }
  chip.textContent = text;
  chip.className = cls;
  chip.title = settings.mode === 'tor' && tor.message ? tor.message : 'Показать маршрут';
}

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
  try { return regionNames.of(code); } catch { return code; }
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

function renderRoute() {
  const { settings, tor, route, identity } = state;
  const flow = $('routeflow');
  flow.replaceChildren();
  if (!route) return;

  const nodes = [];
  let linkClass = 'secure';
  let note = '';
  const real = route.real;

  nodes.push({
    kind: 'you', iconName: 'you', role: 'Вы',
    main: real ? real.ip : 'ваш IP',
    sub: real ? countryName(real.country) : (settings.checkIp ? 'определяется…' : 'показ IP выключен'),
  });

  const exitNode = (label) => ({
    kind: 'site', iconName: 'site', role: label,
    main: route.exit ? route.exit.ip : '—',
    sub: route.exit ? countryName(route.exit.country) : 'IP пока неизвестен',
    extra: identity ? 'пояс: ' + identity.timezone : '',
  });

  if (settings.mode === 'tor') {
    if (tor.status !== 'ready') {
      const failed = tor.status === 'missing' || tor.status === 'error' || tor.status === 'stopped';
      nodes.push({
        kind: 'tor' + (failed ? ' failed' : ''), iconName: 'tor', role: 'Сеть Tor',
        main: failed ? 'нет соединения' : `подключение ${tor.progress}%`,
        sub: tor.message,
        progress: failed ? undefined : tor.progress,
      });
      nodes.push({ kind: 'site off', iconName: 'site', role: 'Сайт видит', main: '—', sub: 'трафик заблокирован' });
      linkClass = 'idle';
      note = 'Пока Tor не подключён, браузер не выпускает трафик наружу — напрямую он не пойдёт.';
    } else {
      const hops = route.circuit ? route.circuit.hops : null;
      if (hops) {
        const roles = ['Входной узел', 'Промежуточный узел', 'Выходной узел'];
        hops.slice(-3).forEach((hop, i) => nodes.push({
          kind: 'tor', iconName: 'tor', role: roles[i],
          main: hop.ip || 'скрыт',
          sub: countryName(hop.country),
          extra: hop.nickname,
        }));
      } else {
        nodes.push({ kind: 'tor', iconName: 'tor', role: 'Сеть Tor', main: '3 узла', sub: 'цепочка строится…' });
      }
      nodes.push(exitNode('Сайт видит'));
      note = 'Входной узел знает ваш IP, но не знает, куда вы идёте. Выходной видит сайт, но не знает, кто вы. Сайт видит только выходной узел.';
    }
  } else if (settings.mode === 'proxy' && route.proxy) {
    nodes.push({
      kind: 'proxy', iconName: 'proxy', role: 'Прокси',
      main: route.proxy.host + ':' + route.proxy.port,
      sub: route.proxy.scheme.toUpperCase(),
    });
    nodes.push(exitNode('Сайт видит'));
    note = 'Сайт видит адрес прокси. Сам прокси видит и ваш IP, и адреса сайтов — используйте только те, которым доверяете.';
  } else {
    nodes.push({ ...exitNode('Сайт видит'), kind: 'site exposed', extra: 'ваш настоящий IP' });
    linkClass = 'warn';
    note = 'Прямое соединение: сайты видят ваш настоящий IP. Скрыт только отпечаток браузера. Включите Tor или прокси ниже.';
  }

  nodes.forEach((n, i) => {
    if (i) flow.append(el('div', 'link ' + linkClass));
    flow.append(routeNode(n));
  });
  $('routenote').textContent = note;
}

// ------------------------------------------------------------ настройки

function renderPanelLive() {
  renderRoute();
  const { tor, identity, settings, proxyCount } = state;
  const status = $('torstatus');
  const labels = {
    stopped: settings.mode === 'tor' ? 'Остановлен' : 'Выключен (выберите режим Tor)',
    missing: tor.message,
    starting: `Запуск: ${tor.progress}% — ${tor.message}`,
    ready: 'Подключён',
    error: tor.message || 'Ошибка',
  };
  status.textContent = labels[tor.status];
  status.className = 'status ' + ({ ready: 'ok', starting: 'warn', missing: 'bad', error: 'bad' }[tor.status] || '');

  const dl = $('persona');
  dl.replaceChildren();
  if (!identity) return;
  const rows = [
    ['Личность №', String(identity.n)],
    ['Маршрут', identity.proxy || { direct: 'напрямую', tor: 'Tor', proxy: `прокси (в списке: ${proxyCount})` }[settings.mode]],
    ['Внешний IP', identity.ip ? identity.ip + (identity.country ? ` (${identity.country})` : '') : 'неизвестен'],
    ['Часовой пояс', identity.timezone],
  ];
  if (settings.spoof) {
    rows.push(
      ['User-Agent', identity.persona.userAgent],
      ['Версия Windows', identity.persona.platformVersion],
      ['Ядра / память', `${identity.persona.cores} / ${identity.persona.memory} ГБ`],
      ['Экран', identity.persona.screen],
      ['Видеокарта', identity.persona.gpu],
    );
  } else {
    rows.push(['Отпечаток', 'подмена выключена']);
  }
  for (const [k, v] of rows) dl.append(el('dt', '', k), el('dd', '', v));
}

function fillForm() {
  const s = state.settings;
  for (const radio of document.querySelectorAll('input[name=mode]')) radio.checked = radio.value === s.mode;
  $('torpath').value = s.torPath;
  $('bridges').value = s.bridges;
  $('proxies').value = s.proxies.join('\n');
  $('rotatemin').value = s.rotateMinutes;
  $('spoof').checked = s.spoof;
  $('block').checked = s.blockTrackers;
  $('checkip').checked = s.checkIp;
  $('tz').value = s.timezone;
}

function setPanel(open) {
  if (open === panelOpen) return;
  panelOpen = open;
  $('panel').hidden = !open;
  if (open && state) { fillForm(); renderPanelLive(); }
  api.call('panel:set', open);
}

async function applySettings() {
  const mode = document.querySelector('input[name=mode]:checked');
  await api.call('settings:set', {
    mode: mode ? mode.value : 'direct',
    torPath: $('torpath').value,
    bridges: $('bridges').value,
    proxies: $('proxies').value.split(/\r?\n/),
    rotateMinutes: Number($('rotatemin').value) || 0,
    spoof: $('spoof').checked,
    blockTrackers: $('block').checked,
    checkIp: $('checkip').checked,
    timezone: $('tz').value,
  });
  fillForm();
}

// ------------------------------------------------------------ уведомления

let toastTimer = null;
function toast(text) {
  const node = $('toast');
  node.textContent = text;
  node.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { node.hidden = true; }, 5000);
}

// ------------------------------------------------------------ события

$('newtab').addEventListener('click', () => { setPanel(false); api.call('tab:new'); });
$('back').addEventListener('click', () => api.call('nav:back'));
$('forward').addEventListener('click', () => api.call('nav:forward'));
$('reload').addEventListener('click', () => api.call('nav:reload'));
$('rotate').addEventListener('click', () => api.call('ip:rotate'));
$('ident').addEventListener('click', () => { setPanel(false); api.call('identity:new'); });
$('gear').addEventListener('click', () => setPanel(!panelOpen));
$('chip').addEventListener('click', () => setPanel(!panelOpen));
$('closepanel').addEventListener('click', () => setPanel(false));
$('apply').addEventListener('click', applySettings);
$('addrform').addEventListener('submit', (e) => {
  e.preventDefault();
  setPanel(false);
  api.call('nav:go', $('addr').value);
  $('addr').blur();
});
$('addr').addEventListener('focus', () => $('addr').select());

api.onState((next) => {
  state = next;
  renderTabs();
  renderNav();
  renderChip();
  if (panelOpen) renderPanelLive();
});
api.onNotice(toast);
api.onFocusAddress(() => { $('addr').focus(); });
api.call('state:get');
