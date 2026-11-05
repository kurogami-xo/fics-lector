/* Fase 0: solo comprueba que el service worker se registra.
   La cache offline llega en la Fase 2. */
self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('activate', function (e) { e.waitUntil(self.clients.claim()); });
