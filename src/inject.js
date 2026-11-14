'use strict';
// Скрипт, который выполняется в каждой странице и каждом фрейме ДО скриптов
// сайта (через Page.addScriptToEvaluateOnNewDocument). Подменяет то, что
// нельзя переопределить средствами движка: экран, память, WebGL, canvas, аудио.
// Функция ниже сериализуется в строку, поэтому не должна ссылаться ни на что
// снаружи себя.

function pageScript(cfg) {
  const g = globalThis;

  // --- Маскировка: подменённые функции должны выглядеть как нативные ---
  const nativeSource = new WeakMap();
  const origToString = Function.prototype.toString;
  const mask = (fn, original) => {
    nativeSource.set(fn, origToString.call(original));
    return fn;
  };
  const toString = function toString() {
    return nativeSource.has(this) ? nativeSource.get(this) : origToString.call(this);
  };
  nativeSource.set(toString, origToString.call(origToString));
  Function.prototype.toString = toString;

  const patchGetter = (proto, prop, value) => {
    if (!proto) return;
    const desc = Object.getOwnPropertyDescriptor(proto, prop);
    if (!desc || !desc.get) return;
    const getter = mask(function () { return value; }, desc.get);
    Object.defineProperty(getter, 'name', { value: 'get ' + prop });
    Object.defineProperty(proto, prop, { ...desc, get: getter });
  };
  const patchMethod = (proto, name, make) => {
    if (!proto) return;
    const desc = Object.getOwnPropertyDescriptor(proto, name);
    if (!desc || typeof desc.value !== 'function') return;
    const original = desc.value;
    const replacement = mask(make(original), original);
    Object.defineProperty(replacement, 'name', { value: name });
    Object.defineProperty(replacement, 'length', { value: original.length });
    Object.defineProperty(proto, name, { ...desc, value: replacement });
  };

  // Детерминированный генератор: в пределах одной личности шум одинаковый,
  // поэтому повторный замер даёт тот же результат (иначе шум легко вычислить).
  const rng = (salt) => {
    let a = (cfg.seed ^ salt) >>> 0;
    return () => {
      a = (a + 0x6d2b79f5) >>> 0;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  };

  // --- Железо ---
  const navProto = g.Navigator ? g.Navigator.prototype : g.WorkerNavigator && g.WorkerNavigator.prototype;
  patchGetter(navProto, 'hardwareConcurrency', cfg.hardwareConcurrency);
  patchGetter(navProto, 'deviceMemory', cfg.deviceMemory);

  // --- Экран ---
  if (g.Screen) {
    const s = cfg.screen;
    patchGetter(g.Screen.prototype, 'width', s.width);
    patchGetter(g.Screen.prototype, 'height', s.height);
    patchGetter(g.Screen.prototype, 'availWidth', s.availWidth);
    patchGetter(g.Screen.prototype, 'availHeight', s.availHeight);
    patchGetter(g.Screen.prototype, 'availLeft', 0);
    patchGetter(g.Screen.prototype, 'availTop', 0);
    patchGetter(g.Screen.prototype, 'colorDepth', s.colorDepth);
    patchGetter(g.Screen.prototype, 'pixelDepth', s.colorDepth);
  }

  // --- WebGL: модель видеокарты ---
  for (const name of ['WebGLRenderingContext', 'WebGL2RenderingContext']) {
    const ctor = g[name];
    if (!ctor) continue;
    patchMethod(ctor.prototype, 'getParameter', (original) => function (param) {
      if (param === 37445) return cfg.gpu.vendor;   // UNMASKED_VENDOR_WEBGL
      if (param === 37446) return cfg.gpu.renderer; // UNMASKED_RENDERER_WEBGL
      return original.apply(this, arguments);
    });
  }

  // --- Canvas: едва заметный шум в считываемых пикселях ---
  const noisify = (data) => {
    const pixels = data.length >>> 2;
    if (!pixels) return;
    const next = rng(pixels);
    const count = Math.min(96, Math.max(8, pixels >>> 6));
    for (let i = 0; i < count; i++) {
      const p = Math.floor(next() * pixels) * 4;
      data[p + Math.floor(next() * 3)] ^= 1;
    }
  };

  if (g.CanvasRenderingContext2D && g.HTMLCanvasElement) {
    const ctxProto = g.CanvasRenderingContext2D.prototype;
    const canvasProto = g.HTMLCanvasElement.prototype;
    const origGetImageData = ctxProto.getImageData;
    const origPutImageData = ctxProto.putImageData;
    const origDrawImage = ctxProto.drawImage;
    const origGetContext = canvasProto.getContext;
    const createElement = g.Document.prototype.createElement;

    patchMethod(ctxProto, 'getImageData', (original) => function () {
      const image = original.apply(this, arguments);
      noisify(image.data);
      return image;
    });

    // Экспорт делаем с копии, чтобы не портить сам холст на странице.
    const noisyCopy = (canvas) => {
      try {
        const w = canvas.width, h = canvas.height;
        if (!w || !h) return canvas;
        const copy = createElement.call(g.document, 'canvas');
        copy.width = w;
        copy.height = h;
        const ctx = origGetContext.call(copy, '2d');
        origDrawImage.call(ctx, canvas, 0, 0);
        const image = origGetImageData.call(ctx, 0, 0, w, h);
        noisify(image.data);
        origPutImageData.call(ctx, image, 0, 0);
        return copy;
      } catch (e) {
        return canvas;
      }
    };

    patchMethod(canvasProto, 'toDataURL', (original) => function () {
      return original.apply(noisyCopy(this), arguments);
    });
    patchMethod(canvasProto, 'toBlob', (original) => function () {
      return original.apply(noisyCopy(this), arguments);
    });
  }

  // --- Аудио: неслышимый шум в буфере, по которому снимают отпечаток ---
  if (g.AudioBuffer) {
    const touched = new WeakMap();
    const abProto = g.AudioBuffer.prototype;
    const origGetChannelData = abProto.getChannelData;
    const noisyChannel = (buffer, channel) => {
      const data = origGetChannelData.call(buffer, channel);
      let done = touched.get(buffer);
      if (!done) touched.set(buffer, (done = new Set()));
      if (!done.has(channel)) {
        done.add(channel);
        const next = rng(data.length + channel);
        for (let i = 0; i < data.length; i += 97) data[i] += (next() - 0.5) * 1e-7;
      }
      return data;
    };
    patchMethod(abProto, 'getChannelData', () => function (channel) {
      return noisyChannel(this, channel);
    });
    patchMethod(abProto, 'copyFromChannel', (original) => function (destination, channel) {
      try { noisyChannel(this, channel); } catch (e) { /* пусть оригинал выбросит ошибку */ }
      return original.apply(this, arguments);
    });
  }
}

function buildInjection(persona) {
  const cfg = {
    seed: persona.seed,
    hardwareConcurrency: persona.hardwareConcurrency,
    deviceMemory: persona.deviceMemory,
    screen: persona.screen,
    gpu: persona.gpu,
  };
  return `(${pageScript.toString()})(${JSON.stringify(cfg)});`;
}

module.exports = { buildInjection };
