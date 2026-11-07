/* Fics · lector personal cifrado
   Escrito para Safari 12 (iOS 12): ES2017, sin optional chaining ni ??, sin frameworks.

   Cifrado
   - keys.json: llave pública RSA-OAEP + llave privada cifrada con AES-GCM, usando una
     llave derivada de la contraseña (PBKDF2-SHA256). La contraseña no sale del dispositivo.
   - data/*.enc: llave AES aleatoria envuelta con RSA-OAEP + contenido cifrado con AES-GCM.
   - "Recordar en este dispositivo" guarda la llave privada como CryptoKey NO exportable
     en IndexedDB: el navegador puede usarla, pero nadie puede leerla ni copiarla. */
(function () {
  'use strict';

  var ITERATIONS = 250000;
  var subtle = window.crypto && window.crypto.subtle;
  var enc = new TextEncoder();
  var dec = new TextDecoder();
  var app = document.getElementById('app');

  var state = { keys: null, pk: null, lib: null, cache: {} };

  /* ---------- Utilidades ---------- */
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function toB64(buf) {
    var bytes = new Uint8Array(buf), s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  function fromB64(b64) {
    var s = atob(b64), bytes = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
    return bytes;
  }
  function store(k, v) {
    try {
      if (v === undefined) return JSON.parse(localStorage.getItem('fics:' + k));
      localStorage.setItem('fics:' + k, JSON.stringify(v));
    } catch (e) { return null; }
  }
  function getJSON(url) {
    return fetch(url, { cache: 'no-cache' }).then(function (r) {
      if (!r.ok) { var e = new Error('HTTP ' + r.status); e.status = r.status; throw e; }
      return r.json();
    });
  }
  function fmtWords(n) {
    if (n >= 1000) return (Math.round(n / 100) / 10).toString().replace('.', ',') + 'k palabras';
    return n + ' palabras';
  }
  function minutes(n) { return Math.max(1, Math.round(n / 220)) + ' min'; }
  // "Capítulo 3 — La princesa y el filo" → { kicker: "Capítulo 3", name: "La princesa y el filo" }
  function splitTitle(t) {
    var m = /^(.+?)\s+[—–-]\s+(.+)$/.exec(t);
    return m ? { kicker: m[1], name: m[2] } : { kicker: '', name: t };
  }

  /* ---------- Ajustes de lectura ---------- */
  var SIZES = [15, 17, 19, 21, 24];
  var settings = store('settings') || {};
  if (settings.size == null) settings.size = 1;
  if (!settings.theme) settings.theme = (window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches) ? 'oscuro' : 'claro';
  function applyTheme() { document.documentElement.setAttribute('data-theme', settings.theme); }
  function saveSettings() { store('settings', settings); applyTheme(); }
  applyTheme();

  /* ---------- Llave guardada (IndexedDB) ---------- */
  function idb() {
    return new Promise(function (resolve, reject) {
      if (!window.indexedDB) { reject(new Error('sin IndexedDB')); return; }
      var req = indexedDB.open('fics', 1);
      req.onupgradeneeded = function () { req.result.createObjectStore('k'); };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error); };
    });
  }
  function idbOp(mode, fn) {
    return idb().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction('k', mode), req = fn(tx.objectStore('k'));
        tx.oncomplete = function () { resolve(req && req.result); };
        tx.onerror = tx.onabort = function () { reject(tx.error || new Error('idb')); };
      });
    });
  }
  function rememberKey(pk) { return idbOp('readwrite', function (s) { return s.put(pk, 'pk'); }); }
  function recallKey() { return idbOp('readonly', function (s) { return s.get('pk'); }); }
  function forgetKey() { return idbOp('readwrite', function (s) { return s.delete('pk'); }).catch(function () {}); }

  /* ---------- Cifrado ---------- */
  function deriveKey(password, salt, usages) {
    return subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey'])
      .then(function (base) {
        return subtle.deriveKey({ name: 'PBKDF2', salt: salt, iterations: ITERATIONS, hash: 'SHA-256' },
          base, { name: 'AES-GCM', length: 256 }, false, usages);
      });
  }
  function unlockPrivateKey(keys, password) {
    return deriveKey(password, fromB64(keys.kdf.salt), ['decrypt'])
      .then(function (aes) {
        return subtle.decrypt({ name: 'AES-GCM', iv: fromB64(keys.privateKey.iv) }, aes, fromB64(keys.privateKey.data));
      })
      .then(function (pkcs8) {
        return subtle.importKey('pkcs8', pkcs8, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
      });
  }
  function decryptDoc(file) {
    return subtle.decrypt({ name: 'RSA-OAEP' }, state.pk, fromB64(file.k))
      .then(function (raw) { return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']); })
      .then(function (aes) { return subtle.decrypt({ name: 'AES-GCM', iv: fromB64(file.iv) }, aes, fromB64(file.d)); })
      .then(function (plain) { return JSON.parse(dec.decode(plain)); });
  }
  // rev = huella del contenido; va en la URL para que la caché offline nunca sirva una versión vieja.
  function dataURL(path, rev) { return 'data/' + path + '.enc' + (rev ? '?r=' + rev : ''); }
  function load(path, rev) {
    var url = dataURL(path, rev);
    if (state.cache[url]) return Promise.resolve(state.cache[url]);
    return getJSON(url).then(function (file) {
      return decryptDoc(file).catch(function (e) { e.decrypt = true; throw e; });
    }).then(function (doc) {
      state.cache[url] = doc;
      return doc;
    });
  }

  /* ---------- Sin conexión ---------- */
  var DATA_CACHE = 'fics-data';
  var sync = { state: 'idle', done: 0, total: 0 };
  function allDataURLs() {
    var urls = [];
    state.lib.fics.forEach(function (f) {
      f.chapters.forEach(function (c) { urls.push(dataURL(f.id + '/' + c.id, c.rev)); });
      if (f.cover) urls.push(dataURL(f.id + '/' + f.cover, f.coverRev));
      if (f.moodboard) urls.push(dataURL(f.id + '/' + f.moodboard, f.moodboardRev));
    });
    return urls;
  }
  function absolute(u) { return new URL(u, location.href).href; }
  // Guarda en el iPod todo lo publicado (cifrado) y borra versiones viejas.
  function syncOffline() {
    if (!window.caches || !state.lib) { sync.state = 'unsupported'; showSync(); return; }
    if (sync.state === 'running') return;
    var urls = allDataURLs(), wanted = {};
    urls.forEach(function (u) { wanted[absolute(u)] = true; });
    wanted[absolute(dataURL('library'))] = true;
    sync = { state: 'running', done: 0, total: urls.length };
    showSync();
    caches.open(DATA_CACHE).then(function (cache) {
      var chain = Promise.resolve(), failed = 0;
      urls.forEach(function (u) {
        chain = chain.then(function () {
          return cache.match(u).then(function (hit) {
            if (!hit) return cache.add(u);
          }).catch(function () { failed++; }).then(function () { sync.done++; showSync(); });
        });
      });
      return chain.then(function () {
        return cache.keys().then(function (reqs) {
          return Promise.all(reqs.filter(function (r) { return !wanted[r.url]; })
            .map(function (r) { return cache.delete(r); }));
        });
      }).then(function () {
        sync.state = failed ? (navigator.onLine === false ? 'offline' : 'partial') : 'ready';
        sync.failed = failed;
        showSync();
      });
    }).catch(function () { sync.state = 'partial'; showSync(); });
  }
  function syncText() {
    if (sync.state === 'running') return 'Guardando para leer sin conexión… ' + sync.done + '/' + sync.total;
    if (sync.state === 'ready') return '✓ Todo disponible sin conexión';
    if (sync.state === 'offline') return 'Sin conexión · ' + (sync.total - sync.failed) + ' de ' + sync.total + ' guardados';
    if (sync.state === 'partial') return 'Faltan ' + sync.failed + ' archivos por guardar · toca para reintentar';
    if (sync.state === 'unsupported') return 'Este navegador no permite modo sin conexión';
    return '';
  }
  function showSync() {
    var el = document.getElementById('sync');
    if (!el) return;
    el.textContent = syncText();
    el.className = 'sync ' + sync.state;
  }

  /* ---------- Progreso de lectura ---------- */
  var progress = store('progress') || {};   // { idCap: { rev, pos, done } }
  function chapState(ch) {
    var p = progress[ch.id];
    if (!p) return 'new';
    if (p.rev !== ch.rev) return 'updated';
    return p.done ? 'read' : 'started';
  }
  function saveProgress(ch, pos, done) {
    var p = progress[ch.id] || {};
    p.rev = ch.rev; p.pos = pos; p.done = p.done || done;
    progress[ch.id] = p;
    store('progress', progress);
  }
  function unreadCount(fic) {
    return fic.chapters.filter(function (c) { var s = chapState(c); return s === 'new' || s === 'updated'; }).length;
  }

  /* ---------- Markdown mínimo ---------- */
  function inline(s) {
    return esc(s)
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/(^|[^*])\*(?!\s)(.+?)\*(?!\*)/g, '$1<em>$2</em>')
      .replace(/(^|\W)_(?!\s)(.+?)_(?=\W|$)/g, '$1<em>$2</em>');
  }
  function renderMarkdown(text) {
    return text.split(/\n\s*\n/).map(function (block) {
      var b = block.trim();
      if (!b) return '';
      if (/^(-{3,}|\*{3,}|_{3,})$/.test(b)) return '<hr>';
      var h = /^(#{1,6})\s+(.*)$/.exec(b);
      if (h) return '<h' + (h[1].length < 3 ? 3 : 4) + '>' + inline(h[2]) + '</h' + (h[1].length < 3 ? 3 : 4) + '>';
      return '<p>' + b.split('\n').map(inline).join('<br>') + '</p>';
    }).join('');
  }

  /* ---------- Componentes ---------- */
  function bar(left, title, right) {
    return '<div class="bar">' + (left || '<span class="back"></span>') +
      '<div class="title">' + title + '</div>' + (right || '<span class="back"></span>') + '</div>';
  }
  function coverHTML(fic) {
    return '<div class="cover" data-cover="' + esc(fic.id) + '">' +
      '<div class="ph"><b>' + esc(fic.title) + '</b><small>' + esc(fic.fandom) + '</small></div></div>';
  }
  // Las portadas también van cifradas: se descifran y se ponen encima del placeholder.
  function fillCovers(root) {
    var nodes = root.querySelectorAll('[data-cover]');
    Array.prototype.forEach.call(nodes, function (node) {
      var fic = findFic(node.getAttribute('data-cover'));
      if (!fic || !fic.cover) return;
      load(fic.id + '/' + fic.cover, fic.coverRev).then(function (doc) {
        var img = new Image();
        img.alt = '';
        img.src = doc.image;
        node.appendChild(img);
      }).catch(function () {});
    });
  }
  function findFic(id) {
    for (var i = 0; i < state.lib.fics.length; i++) if (state.lib.fics[i].id === id) return state.lib.fics[i];
    return null;
  }
  function render(html) {
    app.innerHTML = html;
    window.scrollTo(0, 0);
  }

  /* ---------- Pantalla: desbloqueo ---------- */
  function screenUnlock(note) {
    render(bar('', '<span class="brand">Fics</span>') +
      '<main><div class="card"><h2 style="margin:0 0 6px;font:700 19px Georgia,serif">Abrir la biblioteca</h2>' +
      '<p class="muted" style="margin:0">Tu contraseña no sale de este dispositivo.</p>' +
      '<label for="pw">Contraseña</label><input type="password" id="pw" autocomplete="current-password">' +
      '<label class="check"><input type="checkbox" id="remember" checked> Recordar en este dispositivo</label>' +
      '<button class="btn" id="go">Abrir</button><div class="msg" id="msg">' + (note || '') + '</div></div></main>');
    var pw = document.getElementById('pw'), go = document.getElementById('go'), msg = document.getElementById('msg');
    function submit() {
      if (!pw.value) return;
      go.disabled = true;
      msg.className = 'msg muted'; msg.textContent = 'Abriendo…';
      unlockPrivateKey(state.keys, pw.value).then(function (pk) {
        pw.value = '';
        state.pk = pk;
        var keep = document.getElementById('remember').checked;
        return (keep ? rememberKey(pk).catch(function () { store('noRemember', true); }) : forgetKey())
          .then(openLibrary);
      }, function () {
        go.disabled = false;
        msg.className = 'msg bad'; msg.textContent = 'Contraseña incorrecta.';
      });
    }
    go.onclick = submit;
    pw.onkeydown = function (e) { if (e.keyCode === 13) submit(); };
  }

  /* ---------- Pantalla: biblioteca ---------- */
  function screenLibrary() {
    var fics = state.lib.fics;
    var books = fics.map(function (f) {
      var unread = unreadCount(f);
      return '<a class="book" href="#/f/' + esc(f.id) + '">' + coverHTML(f) +
        '<div class="name">' + esc(f.title) + '</div>' +
        '<div class="sub">' + (unread ? '<span class="dot"></span>' + unread + ' sin leer' : f.chapters.length + ' partes') + '</div></a>';
    }).join('');
    render(bar('', '<span class="brand">Fics</span>', '<button class="tool" id="lock" title="Cerrar">⏏</button>') +
      '<main><div class="shelf-head"><h2>Mi biblioteca</h2><span class="muted" style="font-size:13px">' +
      fics.length + (fics.length === 1 ? ' historia' : ' historias') + '</span></div>' +
      (fics.length ? '<div class="grid">' + books + '</div>' : '<div class="card empty muted">Aún no hay historias.</div>') +
      '<div class="sync" id="sync"></div></main>');
    fillCovers(app);
    showSync();
    document.getElementById('sync').onclick = function () {
      if (sync.state === 'partial' || sync.state === 'offline') syncOffline();
    };
    document.getElementById('lock').onclick = function () {
      if (!confirmLock()) return;
      forgetKey().then(function () { state.pk = null; state.cache = {}; screenUnlock('Biblioteca cerrada.'); });
    };
  }
  function confirmLock() {
    // Sin diálogos del sistema: un segundo toque confirma.
    var b = document.getElementById('lock');
    if (b.getAttribute('data-armed')) return true;
    b.setAttribute('data-armed', '1');
    b.textContent = '¿Cerrar?';
    setTimeout(function () { if (b) { b.removeAttribute('data-armed'); b.textContent = '⏏'; } }, 2500);
    return false;
  }

  /* ---------- Pantalla: fic ---------- */
  function screenFic(fic) {
    var firstUnread = null, resume = null;
    var items = fic.chapters.map(function (c, i) {
      var st = chapState(c), t = splitTitle(c.title);
      if (firstUnread === null && (st === 'new' || st === 'updated')) firstUnread = i;
      if (st === 'started') resume = i;
      var flag = st === 'new' ? '<span class="flag">Nuevo</span>' : st === 'updated' ? '<span class="flag">Editado</span>' : '';
      return '<li class="' + (st === 'read' ? 'read' : '') + '"><a href="#/f/' + esc(fic.id) + '/' + i + '">' +
        '<span class="num">' + (i + 1) + '</span><span class="t">' + esc(t.name) +
        '<small>' + esc(t.kicker ? t.kicker + ' · ' : '') + minutes(c.words) + '</small></span>' + flag +
        '<span class="go">›</span></a></li>';
    }).join('');
    var start = resume != null ? resume : (firstUnread != null ? firstUnread : 0);
    var startLabel = resume != null ? 'Seguir leyendo' : (firstUnread === 0 || firstUnread == null ? 'Empezar a leer' : 'Leer lo nuevo');
    render(bar('<a class="back" href="#/">‹</a>', esc(fic.title)) +
      '<main><div class="hero"><div class="cover-wrap">' + coverHTML(fic) + '</div><div>' +
      '<div class="fandom">' + esc(fic.fandom) + '</div><h1>' + esc(fic.title) + '</h1>' +
      '<div class="stats">' + fic.chapters.length + ' partes · ' + fmtWords(fic.words) + (fic.status ? ' · ' + esc(fic.status) : '') + '</div>' +
      '<div class="chips">' + fic.tags.map(function (t) { return '<span class="chip">' + esc(t) + '</span>'; }).join('') + '</div>' +
      '</div></div>' +
      (fic.summary ? '<p class="summary">' + inline(fic.summary) + '</p>' : '') +
      '<a class="btn" href="#/f/' + esc(fic.id) + '/' + start + '">' + startLabel + '</a>' +
      (fic.moodboard ? '<div class="mood" id="mood"></div>' : '') +
      '<ul class="toc">' + items + '</ul></main>');
    fillCovers(app);
    if (fic.moodboard) {
      load(fic.id + '/' + fic.moodboard, fic.moodboardRev).then(function (doc) {
        var box = document.getElementById('mood');
        if (box) box.innerHTML = '<img alt="" src="' + doc.image + '">';
      }).catch(function () {});
    }
  }

  /* ---------- Pantalla: lector ---------- */
  var detachReader = null;
  function screenReader(fic, i) {
    var ch = fic.chapters[i];
    if (!ch) { location.hash = '#/f/' + fic.id; return; }
    var t = splitTitle(ch.title);
    render(bar('<a class="back" href="#/f/' + esc(fic.id) + '">‹</a>', esc(t.kicker || fic.title),
      '<button class="tool" id="aa">Aa</button>') +
      '<main><article class="reader" id="reader" style="font-size:' + SIZES[settings.size] + 'px">' +
      '<div class="muted" style="text-align:center;font-family:-apple-system,sans-serif">Abriendo…</div></article>' +
      '<div class="pager">' +
      (i > 0 ? '<a class="btn ghost" href="#/f/' + esc(fic.id) + '/' + (i - 1) + '">‹ Anterior</a>' : '') +
      (i < fic.chapters.length - 1 ? '<a class="btn" href="#/f/' + esc(fic.id) + '/' + (i + 1) + '">Siguiente ›</a>' : '') +
      '</div>' + (i === fic.chapters.length - 1 ? '<div class="end">Estás al día ✦</div>' : '') +
      '</main><div class="progress" id="prog"></div>');
    document.getElementById('aa').onclick = toggleSheet;

    load(fic.id + '/' + ch.id, ch.rev).then(function (doc) {
      var art = document.getElementById('reader');
      if (!art) return;
      art.innerHTML = (t.kicker ? '<div class="chap-kicker">' + esc(t.kicker) + '</div>' : '') +
        '<h2>' + esc(t.name) + '</h2>' + renderMarkdown(doc.body);
      var p = progress[ch.id];
      if (p && p.rev === ch.rev && p.pos > 0.02 && p.pos < 0.98) {
        setTimeout(function () { window.scrollTo(0, p.pos * maxScroll()); }, 0);
      } else {
        saveProgress(ch, 0, false);
      }
      attachScroll(ch);
    }, function () {
      var art = document.getElementById('reader');
      if (art) art.innerHTML = '<div class="card bad">No se pudo abrir este capítulo. Revisa la conexión.</div>';
    });
  }
  function maxScroll() {
    return Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
  }
  function attachScroll(ch) {
    var timer = null, prog = document.getElementById('prog');
    function onScroll() {
      var pos = Math.min(1, window.pageYOffset / maxScroll());
      if (prog) prog.style.width = (pos * 100) + '%';
      if (timer) return;
      timer = setTimeout(function () {
        timer = null;
        var now = Math.min(1, window.pageYOffset / maxScroll());
        saveProgress(ch, now, now > 0.9);
      }, 400);
    }
    window.addEventListener('scroll', onScroll);
    detachReader = function () { window.removeEventListener('scroll', onScroll); hideSheet(); };
    onScroll();
  }

  /* ---------- Panel Aa ---------- */
  function hideSheet() {
    var s = document.getElementById('sheet');
    if (s) s.parentNode.removeChild(s);
  }
  function toggleSheet() {
    if (document.getElementById('sheet')) { hideSheet(); return; }
    var themes = [['claro', 'Claro'], ['sepia', 'Sepia'], ['oscuro', 'Oscuro']];
    var div = document.createElement('div');
    div.className = 'sheet'; div.id = 'sheet';
    div.innerHTML =
      '<div class="row"><span class="lbl">Tamaño</span><div class="seg">' +
      '<button data-size="-1" style="font-size:14px">A−</button><button data-size="1" style="font-size:19px">A+</button></div></div>' +
      '<div class="row"><span class="lbl">Tema</span><div class="seg">' +
      themes.map(function (t) { return '<button data-set-theme="' + t[0] + '" class="' + (settings.theme === t[0] ? 'on' : '') + '">' + t[1] + '</button>'; }).join('') +
      '</div></div>';
    div.onclick = function (e) {
      var b = e.target.closest('button');
      if (!b) return;
      var art = document.getElementById('reader');
      if (b.hasAttribute('data-size')) {
        var ratio = window.pageYOffset / maxScroll();
        settings.size = Math.max(0, Math.min(SIZES.length - 1, settings.size + Number(b.getAttribute('data-size'))));
        if (art) art.style.fontSize = SIZES[settings.size] + 'px';
        window.scrollTo(0, ratio * maxScroll());
      } else {
        settings.theme = b.getAttribute('data-set-theme');
        Array.prototype.forEach.call(div.querySelectorAll('[data-set-theme]'), function (x) {
          x.className = x === b ? 'on' : '';
        });
      }
      saveSettings();
    };
    document.body.appendChild(div);
  }

  /* ---------- Rutas ---------- */
  function route() {
    if (detachReader) { detachReader(); detachReader = null; }
    if (!state.lib) return;
    var parts = location.hash.replace(/^#\/?/, '').split('/');
    if (parts[0] === 'f' && parts[1]) {
      var fic = findFic(parts[1]);
      if (!fic) { location.hash = '#/'; return; }
      if (parts[2] != null && parts[2] !== '') screenReader(fic, Number(parts[2]));
      else screenFic(fic);
      return;
    }
    screenLibrary();
  }
  window.addEventListener('hashchange', route);

  function openLibrary() {
    return load('library').then(function (lib) {
      state.lib = lib;
      route();
      syncOffline();
    }, function (err) {
      if (err && err.decrypt) {
        // La llave guardada no abre la biblioteca (p. ej. llave nueva): pedir contraseña.
        forgetKey();
        state.pk = null;
        screenUnlock('No se pudo abrir la biblioteca. Vuelve a poner tu contraseña.');
      } else if (err && err.status === 404) {
        render(bar('', '<span class="brand">Fics</span>') + '<main><div class="card empty muted">La biblioteca aún no se ha publicado.</div></main>');
      } else {
        // Sin conexión y sin copia guardada: nunca borrar la llave por esto.
        render(bar('', '<span class="brand">Fics</span>') + '<main><div class="card empty muted">' +
          'Sin conexión, y esta biblioteca aún no se guardó en este dispositivo.<br>Ábrela una vez con internet.' +
          '<button class="btn ghost" id="retry">Reintentar</button></div></main>');
        document.getElementById('retry').onclick = openLibrary;
      }
    });
  }

  /* ---------- Arranque ---------- */
  function fatal(text) {
    render('<main><div class="card bad">' + esc(text) + '</div></main>');
  }
  if (!subtle) { fatal('Este navegador no tiene cifrado disponible. Abre la app desde Safari.'); return; }
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(function () {});

  getJSON('keys.json').then(function (keys) {
    state.keys = keys;
    return recallKey().catch(function () { return null; }).then(function (pk) {
      if (pk) { state.pk = pk; return openLibrary(); }
      screenUnlock();
    });
  }, function () {
    fatal('No se encontró la llave de la biblioteca (keys.json).');
  });
})();
