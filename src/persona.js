'use strict';
// «Личность» — набор параметров отпечатка, который генерируется заново
// при каждой смене личности. Личность всегда изображает обычный Chrome под
// ту ОС, на которой браузер реально запущен (Windows или Linux): выдавать
// себя за другую систему было бы несогласованно (шрифты, отрисовка) и
// только выделяло бы браузер.

const crypto = require('node:crypto');

const GPUS = [
  { vendor: 'Google Inc. (Intel)', renderer: 'ANGLE (Intel, Intel(R) UHD Graphics 630 (0x00003E9B) Direct3D11 vs_5_0 ps_5_0, D3D11)' },
  { vendor: 'Google Inc. (Intel)', renderer: 'ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x00009A49) Direct3D11 vs_5_0 ps_5_0, D3D11)' },
  { vendor: 'Google Inc. (NVIDIA)', renderer: 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 (0x00001F82) Direct3D11 vs_5_0 ps_5_0, D3D11)' },
  { vendor: 'Google Inc. (NVIDIA)', renderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002503) Direct3D11 vs_5_0 ps_5_0, D3D11)' },
  { vendor: 'Google Inc. (AMD)', renderer: 'ANGLE (AMD, AMD Radeon(TM) Graphics (0x00001636) Direct3D11 vs_5_0 ps_5_0, D3D11)' },
];

const LINUX_GPUS = [
  { vendor: 'Google Inc. (Intel)', renderer: 'ANGLE (Intel, Mesa Intel(R) UHD Graphics 630 (CFL GT2), OpenGL 4.6)' },
  { vendor: 'Google Inc. (Intel)', renderer: 'ANGLE (Intel, Mesa Intel(R) Xe Graphics (TGL GT2), OpenGL 4.6)' },
  { vendor: 'Google Inc. (AMD)', renderer: 'ANGLE (AMD, AMD Radeon Graphics (radeonsi, renoir, LLVM 17.0.6, DRM 3.57, 6.8.0-45-generic), OpenGL 4.6)' },
  { vendor: 'Google Inc. (NVIDIA Corporation)', renderer: 'ANGLE (NVIDIA Corporation, NVIDIA GeForce GTX 1650/PCIe/SSE2, OpenGL 4.5.0)' },
];

const LINUX = process.platform === 'linux';

const SCREENS = [
  [1366, 768], [1536, 864], [1600, 900], [1920, 1080], [2560, 1440],
];

const pick = (arr) => arr[crypto.randomInt(arr.length)];

function createPersona({ minWidth = 0, minHeight = 0 } = {}) {
  const fullVersion = process.versions.chrome;
  const major = fullVersion.split('.')[0];

  // Экран не может быть меньше реального окна, иначе это легко заметить.
  const fitting = SCREENS.filter(([w, h]) => w >= minWidth && h >= minHeight);
  const [width, height] = fitting.length ? pick(fitting) : [Math.max(minWidth, 1920), Math.max(minHeight, 1080)];

  const brands = [
    { brand: 'Chromium', version: major },
    { brand: 'Google Chrome', version: major },
    { brand: 'Not_A Brand', version: '24' },
  ];
  const fullVersionList = [
    { brand: 'Chromium', version: fullVersion },
    { brand: 'Google Chrome', version: fullVersion },
    { brand: 'Not_A Brand', version: '24.0.0.0' },
  ];

  return {
    seed: crypto.randomInt(1, 0x7fffffff),
    // Современный Chrome отдаёт «урезанный» User-Agent, одинаковый у всех.
    userAgent: `Mozilla/5.0 (${LINUX ? 'X11; Linux x86_64' : 'Windows NT 10.0; Win64; x64'}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${major}.0.0.0 Safari/537.36`,
    languages: 'en-US,en', // q-веса Chromium добавляет сам
    locale: 'en-US',
    platform: LINUX ? 'Linux x86_64' : 'Win32',
    uaMetadata: {
      brands,
      fullVersionList,
      platform: LINUX ? 'Linux' : 'Windows',
      platformVersion: LINUX ? pick(['6.8.0', '6.11.0', '6.14.0']) : pick(['10.0.0', '15.0.0', '19.0.0']),
      architecture: 'x86',
      model: '',
      mobile: false,
      bitness: '64',
      wow64: false,
    },
    hardwareConcurrency: pick([4, 8, 8, 12, 16]),
    deviceMemory: pick([4, 8, 8]),
    screen: { width, height, availWidth: width, availHeight: height - (LINUX ? 40 : 48), colorDepth: 24 },
    gpu: pick(LINUX ? LINUX_GPUS : GPUS),
  };
}

module.exports = { createPersona };
