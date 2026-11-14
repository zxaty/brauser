'use strict';
// Небольшой встроенный список доменов трекеров и рекламных сетей.
// Блокируются сам домен и все его поддомены.

const DOMAINS = new Set([
  'google-analytics.com', 'googletagmanager.com', 'googletagservices.com',
  'doubleclick.net', 'googlesyndication.com', 'googleadservices.com', 'adservice.google.com',
  'connect.facebook.net', 'facebook.net', 'pixel.facebook.com',
  'mc.yandex.ru', 'mc.yandex.com', 'an.yandex.ru', 'yandexadexchange.net', 'adfox.ru',
  'top-fwz1.mail.ru', 'ad.mail.ru', 'counter.yadro.ru', 'tns-counter.ru',
  'scorecardresearch.com', 'quantserve.com', 'quantcount.com',
  'hotjar.com', 'hotjar.io', 'mouseflow.com', 'fullstory.com', 'clarity.ms', 'crazyegg.com',
  'criteo.com', 'criteo.net', 'taboola.com', 'outbrain.com', 'adnxs.com', 'rubiconproject.com',
  'pubmatic.com', 'openx.net', 'casalemedia.com', 'adsrvr.org', 'amazon-adsystem.com',
  'moatads.com', 'bluekai.com', 'demdex.net', 'omtrdc.net', 'everesttech.net',
  'segment.io', 'segment.com', 'mixpanel.com', 'amplitude.com', 'branch.io', 'appsflyer.com',
  'newrelic.com', 'nr-data.net', 'bugsnag.com', 'optimizely.com',
  'analytics.tiktok.com', 'ads.linkedin.com', 'px.ads.linkedin.com', 'snap.licdn.com',
  'bat.bing.com', 'analytics.twitter.com', 'ads-twitter.com', 'static.ads-twitter.com',
  'fingerprint.com', 'fpjs.io', 'fpcdn.io', 'fpnpmcdn.net',
]);

function isBlocked(hostname) {
  let host = String(hostname || '').toLowerCase();
  while (host) {
    if (DOMAINS.has(host)) return true;
    const dot = host.indexOf('.');
    if (dot === -1) return false;
    host = host.slice(dot + 1);
  }
  return false;
}

module.exports = { isBlocked };
