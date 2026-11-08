# Fics · lector (público, contenido cifrado)
App web para el iPod touch de Jiji (iOS 12 / Safari 12): ES2017, sin `?.`/`??`, sin flex `gap`.
`data/` lo genera `fics/tools/publicar.mjs`; no editar a mano.
Cada vez que cambies index.html, app.js o sw.js: `node bump.mjs` antes del commit.
Así la app instalada en la pantalla de inicio detecta la versión nueva y se actualiza sola.
