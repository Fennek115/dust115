// APT115 CODEX ARCANUM — GTFOBins / LOLBAS offline reference
// quod est superius est sicut quod inferius
//
// Referencia buscable de GTFOBins (Unix) y LOLBAS (Windows). Los datasets
// (data/gtfobins.js, data/lolbas.js) se cargan PEREZOSAMENTE la primera vez
// que se abre el tool (inyección de <script>, funciona offline y en file://),
// así no pesan en la carga inicial de la página.
//
// Datos de GTFOBins y LOLBAS (GPL) — ver vendor/LICENSE-GTFOBins.txt y
// vendor/LICENSE-LOLBAS.txt.

export const lolref = (function () {
  'use strict';

  let source = 'gtfo';   // 'gtfo' | 'lol'
  let cat = '';          // filtro de categoría
  let dataPromise = null;
  const CAP = 60;

  function esc(s) {
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function loadScript(src) {
    return new Promise((res, rej) => {
      const s = document.createElement('script');
      s.src = src; s.onload = res;
      s.onerror = () => rej(new Error('no se pudo cargar ' + src));
      document.head.appendChild(s);
    });
  }
  function ensureData() {
    if (!dataPromise) {
      const need = [];
      if (!window.GTFOBINS) need.push(loadScript('data/gtfobins.js'));
      if (!window.LOLBAS) need.push(loadScript('data/lolbas.js'));
      dataPromise = Promise.all(need);
    }
    return dataPromise;
  }

  function categories() {
    const set = new Set();
    if (source === 'gtfo') (window.GTFOBINS || []).forEach(b => b.f.forEach(t => set.add(t.c)));
    else (window.LOLBAS || []).forEach(b => b.c.forEach(c => c.cat && set.add(c.cat)));
    return [...set].sort();
  }

  function render(container) {
    container.innerHTML =
      '<div class="sec-hdr"><div class="sec-title">📖 GTFOBins / LOLBAS</div>' +
      '<span class="sec-cmds-badge" id="lrCount">offline</span></div>' +
      '<div class="lab-intro">Referencia offline de binarios para vivir-de-la-tierra. ' +
      '<b>GTFOBins</b> (Unix: suid/sudo/cap/file-rw/shell) y <b>LOLBAS</b> (Windows: LOLBins). ' +
      'Datos GPL de los proyectos originales.</div>' +
      '<div class="lr-bar">' +
        '<div class="lr-src">' +
          '<button class="lr-srcb on" data-src="gtfo">GTFOBins · Unix</button>' +
          '<button class="lr-srcb" data-src="lol">LOLBAS · Windows</button>' +
        '</div>' +
        '<input class="lr-search" id="lrSearch" placeholder="buscar binario o comando… (ej: tar, suid, certutil)">' +
        '<select class="lr-cat" id="lrCat"></select>' +
      '</div>' +
      '<div id="lrOut"><div class="lab-loading">⬡ Cargando datasets…</div></div>';

    const search = container.querySelector('#lrSearch');
    const catSel = container.querySelector('#lrCat');

    container.querySelectorAll('.lr-srcb').forEach(b => {
      b.onclick = () => {
        source = b.dataset.src; cat = '';
        container.querySelectorAll('.lr-srcb').forEach(x => x.classList.toggle('on', x === b));
        fillCats(catSel); renderOut(container);
      };
    });
    let t;
    search.oninput = () => { clearTimeout(t); t = setTimeout(() => renderOut(container), 150); };
    catSel.onchange = () => { cat = catSel.value; renderOut(container); };

    ensureData().then(() => { fillCats(catSel); renderOut(container); })
      .catch(e => { container.querySelector('#lrOut').innerHTML = '<div class="lab-err">' + esc(e.message) + '</div>'; });
  }

  function fillCats(catSel) {
    const cats = categories();
    catSel.innerHTML = '<option value="">todas las categorías</option>' +
      cats.map(c => '<option value="' + esc(c) + '">' + esc(c) + '</option>').join('');
    catSel.value = cat;
  }

  function renderOut(container) {
    const out = container.querySelector('#lrOut');
    const q = (container.querySelector('#lrSearch').value || '').toLowerCase().trim();
    const html = source === 'gtfo' ? renderGtfo(q) : renderLol(q);
    out.innerHTML = html.body;
    const cnt = container.querySelector('#lrCount');
    if (cnt) cnt.textContent = html.shown + (html.total > html.shown ? '/' + html.total : '') + ' binarios';
    out.querySelectorAll('.rs-item').forEach(row => {
      const doCopy = () => { if (window.LAB) LAB.copy(row.dataset.pl); };
      const c = row.querySelector('.rs-item-c'); if (c) c.onclick = doCopy;
      const cp = row.querySelector('.rs-copy'); if (cp) cp.onclick = doCopy;
    });
  }

  function renderGtfo(q) {
    const data = window.GTFOBINS || [];
    let shown = 0, total = 0, body = '';
    for (const b of data) {
      const nameMatch = !q || b.n.toLowerCase().includes(q);
      const techs = b.f.filter(t => (!cat || t.c === cat) &&
        (!q || nameMatch || t.code.toLowerCase().includes(q)));
      if (!techs.length) continue;
      total++;
      if (shown >= CAP) continue;
      shown++;
      body += '<div class="lr-bin"><div class="lr-bin-h">' + esc(b.n) +
        ' <span class="lab-dim">(' + techs.length + ')</span></div>';
      for (const t of techs) {
        body += '<div class="rs-item" data-pl="' + esc(t.code) + '">' +
          '<div class="lr-cat-tag">' + esc(t.c) + '</div>' +
          '<code class="rs-item-c">' + esc(t.code) + '</code>' +
          '<button class="rs-copy">copy</button></div>';
        if (t.cm) body += '<div class="lr-cm">' + esc(t.cm) + '</div>';
      }
      body += '</div>';
    }
    return { body: body || empty(), shown, total };
  }

  function renderLol(q) {
    const data = window.LOLBAS || [];
    let shown = 0, total = 0, body = '';
    for (const b of data) {
      const nameMatch = !q || b.n.toLowerCase().includes(q) || (b.d || '').toLowerCase().includes(q);
      const cmds = b.c.filter(c => (!cat || c.cat === cat) &&
        (!q || nameMatch || c.cmd.toLowerCase().includes(q)));
      if (!cmds.length) continue;
      total++;
      if (shown >= CAP) continue;
      shown++;
      body += '<div class="lr-bin"><div class="lr-bin-h">' + esc(b.n) + '</div>' +
        (b.d ? '<div class="lr-desc">' + esc(b.d) + '</div>' : '');
      for (const c of cmds) {
        body += '<div class="rs-item" data-pl="' + esc(c.cmd) + '">' +
          (c.cat ? '<div class="lr-cat-tag">' + esc(c.cat) + '</div>' : '') +
          '<code class="rs-item-c">' + esc(c.cmd) + '</code>' +
          '<button class="rs-copy">copy</button></div>';
        if (c.d) body += '<div class="lr-cm">' + esc(c.d) + (c.mid ? ' · ' + esc(c.mid) : '') + '</div>';
      }
      body += '</div>';
    }
    return { body: body || empty(), shown, total };
  }

  function empty() { return '<div class="lab-note">Sin resultados. Probá otro término o categoría.</div>'; }

  if (window.LAB) {
    LAB.registerTool({ id: 'lolref', label: 'GTFOBins / LOLBAS', icon: '📖', group: '🧪 LAB / TOOLS', render });
  }
})();
