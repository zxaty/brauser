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
  chip.title = settings.mode === 'tor' && tor.message ? tor.message : 'Текущий маршрут';
}

// ------------------------------------------------------------ настройки

function renderPanelLive() {
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
