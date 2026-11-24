// app.js — lo único que hace falta además de htmx (sin eval, sin código en línea).
// Cierra la ventana (modal) con ✕, Esc o clic afuera, y el menú de cuenta al hacer clic fuera.
(() => {
  const cerrar = () => { const m = document.getElementById('modal'); if (m) m.innerHTML = ''; };
  document.addEventListener('click', e => {
    const t = e.target;
    if (t.closest && t.closest('[data-cerrar]') && (t.matches('.mov') || t.closest('button[data-cerrar]'))) cerrar();
    // menú de cuenta: se cierra al hacer clic afuera o al elegir una opción
    const menu = document.querySelector('details.cuenta[open]');
    if (menu && (!menu.contains(t) || t.closest('.menu button'))) menu.removeAttribute('open');
  });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') cerrar(); });
  // al cargar una ventana, el cursor va al primer campo
  document.addEventListener('htmx:afterSwap', e => {
    if (e.target.id === 'modal') { const f = e.target.querySelector('[autofocus], input, select'); if (f) f.focus(); }
  });
})();

// Dispositivos: "Abrir/Cerrar todos" los segmentos (<details>). Al abrirlos, htmx pide el contenido de cada uno.
(() => {
  const marcar = () => {
    const b = document.getElementById('dv-plegar');
    if (!b) return;
    const hay = !!document.querySelector('details.segcard[open]');
    b.classList.toggle('abierto', hay);
    b.title = hay ? 'Cerrar todos' : 'Abrir todos';
  };
  document.addEventListener('click', e => {
    if (!(e.target.closest && e.target.closest('#dv-plegar'))) return;
    const abrir = !document.querySelector('details.segcard[open]');
    document.querySelectorAll('details.segcard').forEach(d => { d.open = abrir; });
    marcar();
  });
  document.addEventListener('toggle', marcar, true); // "toggle" no sube: se escucha en captura
  document.addEventListener('htmx:afterSettle', marcar);
})();
