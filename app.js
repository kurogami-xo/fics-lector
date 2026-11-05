/* Fics · Fase 0
   Escrito para Safari 12 (iOS 12): sin optional chaining, sin ??, sin frameworks.

   Esquema de cifrado
   - keys.json: llave publica RSA-OAEP (SPKI) + llave privada (PKCS8) cifrada con
     AES-GCM usando una llave derivada de la contrasena (PBKDF2-SHA256).
   - *.enc: llave AES aleatoria envuelta con RSA-OAEP + texto cifrado con AES-GCM.
   Quien publica capitulos solo necesita la llave publica; la contrasena nunca sale
   del dispositivo. */
(function () {
  'use strict';

  var ITERATIONS = 250000;
  var subtle = window.crypto && window.crypto.subtle;
  var enc = new TextEncoder();
  var dec = new TextDecoder();

  function $(id) { return document.getElementById(id); }
  function show(id) { $(id).classList.remove('hidden'); }
  function hide(id) { $(id).classList.add('hidden'); }
  function say(id, text, kind) {
    var el = $(id);
    el.textContent = text;
    el.className = 'msg' + (kind ? ' ' + kind : '');
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
  function now() { return (window.performance && performance.now) ? performance.now() : Date.now(); }

  /* ---------- Diagnostico ---------- */
  function check(label, ok, note) {
    var li = document.createElement('li');
    li.className = ok ? 'ok' : 'bad';
    li.textContent = (ok ? '✓ ' : '✗ ') + label + (note ? ' · ' + note : '');
    $('checks').appendChild(li);
  }

  function storageWorks() {
    try { localStorage.setItem('__t', '1'); localStorage.removeItem('__t'); return true; }
    catch (e) { return false; }
  }

  function runChecks() {
    $('checks').innerHTML = '';
    check('Cifrado del navegador', !!subtle);
    check('Guardado local', storageWorks());
    check('Base de datos local', !!window.indexedDB);
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('sw.js').then(function () {
        check('Modo offline disponible', true);
      }, function (err) {
        check('Modo offline disponible', false, String(err && err.message || err));
      });
    } else {
      check('Modo offline disponible', false, 'sin service worker');
    }
  }

  /* ---------- Llaves ---------- */
  function deriveKey(password, salt, usages) {
    return subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey'])
      .then(function (base) {
        return subtle.deriveKey(
          { name: 'PBKDF2', salt: salt, iterations: ITERATIONS, hash: 'SHA-256' },
          base, { name: 'AES-GCM', length: 256 }, false, usages);
      });
  }

  function createKeys(password) {
    var salt = window.crypto.getRandomValues(new Uint8Array(16));
    var iv = window.crypto.getRandomValues(new Uint8Array(12));
    var pair, spki;
    return subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true, ['encrypt', 'decrypt'])
      .then(function (p) { pair = p; return subtle.exportKey('spki', pair.publicKey); })
      .then(function (s) { spki = s; return subtle.exportKey('pkcs8', pair.privateKey); })
      .then(function (pkcs8) {
        return deriveKey(password, salt, ['encrypt']).then(function (aes) {
          return subtle.encrypt({ name: 'AES-GCM', iv: iv }, aes, pkcs8);
        });
      })
      .then(function (wrapped) {
        return {
          v: 1,
          kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: ITERATIONS, salt: toB64(salt) },
          publicKey: toB64(spki),
          privateKey: { iv: toB64(iv), data: toB64(wrapped) }
        };
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

  function decryptFile(privateKey, file) {
    return subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, fromB64(file.k))
      .then(function (raw) { return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']); })
      .then(function (aes) { return subtle.decrypt({ name: 'AES-GCM', iv: fromB64(file.iv) }, aes, fromB64(file.d)); })
      .then(function (plain) { return JSON.parse(dec.decode(plain)); });
  }

  function getJSON(url) {
    return fetch(url, { cache: 'no-store' }).then(function (r) {
      if (!r.ok) { var e = new Error('HTTP ' + r.status); e.status = r.status; throw e; }
      return r.json();
    });
  }

  /* ---------- Pantallas ---------- */
  function startSetup() {
    show('setup');
    $('btnCreate').onclick = function () {
      var a = $('p1').value, b = $('p2').value;
      if (a.length < 12) { say('setupMsg', 'Usa al menos 12 caracteres; una frase es ideal.', 'bad'); return; }
      if (a !== b) { say('setupMsg', 'Las contraseñas no coinciden.', 'bad'); return; }
      $('btnCreate').disabled = true;
      say('setupMsg', 'Creando llave… puede tardar unos segundos.');
      var t0 = now();
      createKeys(a).then(function (keys) {
        $('p1').value = ''; $('p2').value = '';
        $('keyText').value = JSON.stringify(keys);
        show('keyOut');
        say('setupMsg', 'Llave lista en ' + Math.round((now() - t0) / 100) / 10 + ' s.', 'ok');
      }, function (err) {
        $('btnCreate').disabled = false;
        say('setupMsg', 'No se pudo crear la llave: ' + (err && err.message || err), 'bad');
      });
    };
    $('btnCopy').onclick = function () {
      var t = $('keyText');
      t.removeAttribute('readonly'); t.select(); t.setSelectionRange(0, t.value.length);
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      t.setAttribute('readonly', '');
      $('btnCopy').textContent = ok ? 'Copiada ✓' : 'Selecciónala y cópiala a mano';
    };
  }

  function startUnlock(keys) {
    show('unlock');
    $('btnUnlock').onclick = function () {
      var pw = $('pw').value;
      if (!pw) return;
      $('btnUnlock').disabled = true;
      say('unlockMsg', 'Abriendo…');
      var t0 = now(), tKey;
      unlockPrivateKey(keys, pw).then(function (pk) {
        tKey = now();
        return getJSON('data/prueba.enc').then(function (file) { return decryptFile(pk, file); });
      }).then(function (doc) {
        $('pw').value = '';
        say('unlockMsg', 'Abierto ✓ · llave ' + Math.round((tKey - t0) / 100) / 10 + ' s · capítulo ' +
          Math.round((now() - tKey)) + ' ms', 'ok');
        var r = $('reader');
        r.innerHTML = '';
        var h = document.createElement('h3'); h.textContent = doc.title; r.appendChild(h);
        doc.body.split(/\n\s*\n/).forEach(function (para) {
          var p = document.createElement('p'); p.textContent = para; r.appendChild(p);
        });
        show('readerCard');
      }, function (err) {
        $('btnUnlock').disabled = false;
        if (err && err.status === 404) say('unlockMsg', 'La llave funciona, pero aún no hay capítulo de prueba publicado.', 'muted');
        else say('unlockMsg', 'Contraseña incorrecta o archivo dañado.', 'bad');
      });
    };
  }

  runChecks();
  if (!subtle) return;
  getJSON('keys.json').then(startUnlock, function () { startSetup(); });
})();
