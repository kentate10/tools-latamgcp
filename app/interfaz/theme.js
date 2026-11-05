// Apply the saved theme before the stylesheet paints the page.
(() => {
  const key = 'latam-gcp-tema';
  let dark = false;
  try { dark = localStorage.getItem(key) === 'dark'; } catch {}
  function apply() {
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    const button = document.getElementById('themeToggle');
    if (button) {
      button.textContent = dark ? 'Modo claro · blanco/rojo' : 'Modo noche · negro/dorado';
      button.setAttribute('aria-pressed', String(dark));
      button.setAttribute('aria-label', dark ? 'Activar modo claro' : 'Activar modo oscuro');
    }
  }
  apply();
  document.addEventListener('DOMContentLoaded', () => {
    apply();
    document.getElementById('themeToggle')?.addEventListener('click', () => {
      dark = !dark;
      apply();
      try { localStorage.setItem(key, dark ? 'dark' : 'light'); } catch {}
    });
  });
  window.addEventListener('storage', event => {
    if (event.key === key) { dark = event.newValue === 'dark'; apply(); }
  });
})();
