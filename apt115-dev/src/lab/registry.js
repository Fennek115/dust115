// APT115 CODEX ARCANUM — LAB / TOOLS framework
// solve et coagula
//
// Namespace global `LAB`: registro de herramientas interactivas (widgets) y
// wiring de la barra lateral + secciones, con render PEREZOSO (cada tool se
// construye sólo la primera vez que se abre). No modifica app.js: sólo reusa
// el DOM compartido (#sidebar, #sections) y las clases existentes (.si/.sec/.on).
//
// Para agregar una herramienta nueva, en su propio archivo:
//   LAB.registerTool({ id, label, icon, group, render(container) });
// y sumá el <script> en index.html. Nada más.

export const LAB = (function () {
  'use strict';

  const tools = [];      // { id, label, icon, group, render(container) }
  const rendered = {};   // id -> bool  (guard de render perezoso)
  let inited = false;

  function registerTool(tool) {
    if (!tool || !tool.id || typeof tool.render !== 'function') {
      console.warn('[LAB] tool inválido (requiere id + render()):', tool);
      return;
    }
    if (tools.some(t => t.id === tool.id)) {
      console.warn('[LAB] tool duplicado ignorado:', tool.id);
      return;
    }
    tools.push(tool);
    // Si el LAB ya se inicializó (registro tardío), reconstruimos.
    if (inited) { reset(); build(); }
  }

  function errBox(e) {
    return '<div class="lab-err">⚠ Error al renderizar la herramienta: ' +
      String((e && e.message) || e) + '</div>';
  }

  // Activa una sección de tool: misma semántica que el resto de la app
  // (una sola .sec/.si con clase .on). Renderiza perezosamente al abrir.
  function activate(id) {
    document.querySelectorAll('.si').forEach(x => x.classList.remove('on'));
    document.querySelectorAll('.sec').forEach(x => x.classList.remove('on'));
    const si = document.querySelector('.si[data-id="' + id + '"]');
    const sec = document.getElementById('s-' + id);
    if (si) si.classList.add('on');
    if (sec) sec.classList.add('on');
    const sr = document.getElementById('searchResults');
    if (sr) sr.classList.remove('on');
    const input = document.getElementById('searchInput');
    if (input) input.value = '';

    const tool = tools.find(t => t.id === id);
    if (tool && sec && !rendered[id]) {
      try { tool.render(sec); }
      catch (e) { sec.innerHTML = errBox(e); console.error('[LAB] render', id, e); }
      rendered[id] = true;
    }
  }

  function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // Inserta el grupo LAB ARRIBA del todo (justo después de .sb-top), antes
  // de los grupos del cheatsheet, para que las herramientas sean lo primero
  // visible en el sidebar (descubribilidad).
  function buildSidebar() {
    const sb = document.getElementById('sidebar');
    if (!sb) return;
    const top = sb.querySelector('.sb-top');
    const groups = {};
    const order = [];
    tools.forEach(t => {
      const g = t.group || '🧪 LAB';
      if (!groups[g]) { groups[g] = []; order.push(g); }
      groups[g].push(t);
    });
    let h = '';
    order.forEach(g => {
      h += '<div class="sg lab-sg">' + esc(g) + '</div>';
      groups[g].forEach(t => {
        h += '<div class="si" data-id="' + esc(t.id) + '" title="' + esc(t.label) +
          '" onclick="LAB.activate(\'' + esc(t.id) + '\')">' +
          '<span class="si-icon">' + (t.icon || '') + '</span>' +
          '<span class="si-label">' + esc(t.label) + '</span></div>';
      });
    });
    if (top) top.insertAdjacentHTML('afterend', h);
    else sb.insertAdjacentHTML('afterbegin', h);
  }

  function buildSections() {
    const cont = document.getElementById('sections');
    if (!cont) return;
    tools.forEach(t => {
      const div = document.createElement('div');
      div.id = 's-' + t.id;
      div.className = 'sec lab-sec';
      cont.appendChild(div); // contenido perezoso (se llena al activar)
    });
  }

  function build() {
    buildSidebar();
    buildSections();
  }

  // Quita del DOM lo que agregamos (para reconstruir ante registro tardío)
  function reset() {
    document.querySelectorAll('#sidebar .lab-sg').forEach(el => el.remove());
    document.querySelectorAll('#sidebar .si').forEach(el => {
      if (tools.some(t => t.id === el.dataset.id)) el.remove();
    });
    document.querySelectorAll('#sections .lab-sec').forEach(el => el.remove());
    for (const k in rendered) delete rendered[k];
  }

  function initLab() {
    if (inited || !tools.length) return;
    inited = true;
    build();
  }

  // Copia compartida por los widgets (reusa el toast de app.js si existe).
  function copy(text) {
    try { navigator.clipboard.writeText(text); }
    catch (e) {
      const ta = document.createElement('textarea');
      ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); } catch (_) {}
      document.body.removeChild(ta);
    }
    if (typeof showToast === 'function') showToast('✓ Copiado');
  }

  return { registerTool, initLab, activate, copy, tools };
})();

// Se auto-cuelga LAB de window (back-compat con los tools aún no migrados) y
// auto-inicializa cuando el DOM esté listo (los tools se registran durante el
// parse, antes de DOMContentLoaded, así que para entonces ya están todos).
if (typeof window !== 'undefined') {
  window.LAB = LAB;
  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', function () { window.LAB.initLab(); });
    } else {
      window.LAB.initLab();
    }
  }
}
