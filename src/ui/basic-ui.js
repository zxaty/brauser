'use strict';
/* global api */

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
};

function render(state) {
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
    node.addEventListener('click', () => api.call('tab:activate', tab.id));
    node.addEventListener('auxclick', (e) => { if (e.button === 1) api.call('tab:close', tab.id); });
    box.append(node);
  }

  const active = state.tabs.find((t) => t.id === state.activeId);
  $('back').disabled = !active || !active.canGoBack;
  $('forward').disabled = !active || !active.canGoForward;
  $('reload').textContent = active && active.loading ? '✕' : '⟳';
  const addr = $('addr');
  if (document.activeElement !== addr) addr.value = active ? active.url : '';
  $('chip').textContent = 'Basic · напрямую' + (state.blocked ? ` · заблокировано: ${state.blocked}` : '');
}

$('newtab').addEventListener('click', () => api.call('tab:new'));
$('back').addEventListener('click', () => api.call('nav:back'));
$('forward').addEventListener('click', () => api.call('nav:forward'));
$('reload').addEventListener('click', () => api.call('nav:reload'));
$('addrform').addEventListener('submit', (e) => {
  e.preventDefault();
  api.call('nav:go', $('addr').value);
  $('addr').blur();
});
$('addr').addEventListener('focus', () => $('addr').select());

api.onBasicState(render);
api.onFocusAddress(() => { $('addr').focus(); });
api.call('basic:state');
