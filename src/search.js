'use strict';
// Оформление страницы поиска DuckDuckGo — только штатными параметрами самого
// DuckDuckGo (https://duckduckgo.com/duckduckgo-help-pages/settings/params).
// Страница при этом не изменяется со стороны браузера: поисковик сам рисует
// её в заданных цветах, как для любого пользователя с такими настройками.
//
// Те же параметры продублированы скрытыми полями в формах поиска на
// стартовых страницах: src/ui/start.html и src/ui/secured-start.html.

const DDG_PARAMS = {
  kae: 'd',       // тёмная тема
  k7: '14161a',   // фон
  kj: '14161a',   // шапка
  k9: '8ab4ff',   // заголовки результатов
  kaa: 'c08be0',  // посещённые ссылки
  kx: '3ecf8e',   // адреса сайтов
  k8: 'c9ccd3',   // текст
  km: 'm',        // результаты по центру
  k1: '-1',       // без рекламы
  kak: '-1',      // без напоминаний и промо-блоков DuckDuckGo
  kax: '-1',
  kaq: '-1',
  kap: '-1',
  kao: '-1',
};

const query = Object.entries(DDG_PARAMS).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');

// Адрес поиска для готового запроса.
const searchUrl = (text) => `https://duckduckgo.com/?q=${encodeURIComponent(text)}&${query}`;
// Шаблон для поисковой системы движка ({searchTerms} подставляет сам движок).
const searchTemplate = `https://duckduckgo.com/?q={searchTerms}&${query}`;

module.exports = { DDG_PARAMS, searchUrl, searchTemplate };
