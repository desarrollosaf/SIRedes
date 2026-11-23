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
