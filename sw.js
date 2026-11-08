/* Fics · service worker (modo sin conexión)
   - App (html, js, llave): red primero, caché si no hay conexión. Así las
     actualizaciones llegan solas y offline sigue abriendo.
   - Biblioteca (library.enc): red primero, caché de respaldo.
   - Capítulos e imágenes (data/…/*.enc?r=<rev>): caché primero. La versión va en
     la URL, así que un capítulo editado es una URL nueva y nunca se lee viejo.
   Todo lo guardado sigue cifrado: la caché no contiene texto legible. */
var SHELL = 'fics-shell-v8';
var DATA = 'fics-data';
var SHELL_FILES = ['./', 'index.html', 'app.js?v=8', 'keys.json', 'icon-180.png?v=2'];

self.addEventListener('install', function (e) {
  e.waitUntil(caches.open(SHELL).then(function (c) { return c.addAll(SHELL_FILES); }).then(function () {
    return self.skipWaiting();
  }));
});

self.addEventListener('activate', function (e) {
  e.waitUntil(caches.keys().then(function (names) {
    return Promise.all(names.filter(function (n) { return n.indexOf('fics-shell-') === 0 && n !== SHELL; })
      .map(function (n) { return caches.delete(n); }));
  }).then(function () { return self.clients.claim(); }));
});

// Siempre pide al servidor la versión actual (sin caché HTTP), para que las
// actualizaciones de la app lleguen al iPod en cuanto se publican.
// Safari 12 no respeta del todo las opciones de caché de fetch: se agrega un parámetro
// único a la URL para obligar a traer la versión del servidor.
function fresh(req) {
  var u = req.url + (req.url.indexOf('?') < 0 ? '?' : '&') + '_=' + Date.now();
  return fetch(u, { credentials: 'same-origin' });
}
function networkFirst(req, cacheName) {
  return fresh(req).then(function (res) {
    if (res && res.ok) {
      var copy = res.clone();
      caches.open(cacheName).then(function (c) { c.put(req, copy); });
    }
    return res;
  }).catch(function () {
    return caches.match(req, { ignoreSearch: false }).then(function (hit) {
      if (hit) return hit;
      // Navegación sin conexión a cualquier ruta: devolver la app.
      if (req.mode === 'navigate') return caches.match('index.html');
      throw new Error('offline');
    });
  });
}

function cacheFirst(req) {
  return caches.open(DATA).then(function (c) {
    return c.match(req).then(function (hit) {
      if (hit) return hit;
      return fetch(req).then(function (res) {
        if (res && res.ok) c.put(req, res.clone());
        return res;
      });
    });
  });
}

self.addEventListener('fetch', function (e) {
  var req = e.request;
  if (req.method !== 'GET') return;
  var url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  var path = url.pathname;
  if (/\/data\/library\.enc$/.test(path)) { e.respondWith(networkFirst(req, DATA)); return; }
  if (/\/data\/.+\.enc$/.test(path)) { e.respondWith(cacheFirst(req)); return; }
  e.respondWith(networkFirst(req, SHELL));
});
