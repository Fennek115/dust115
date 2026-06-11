// APT115 CODEX ARCANUM — Reverse Shell & C2 Generator
// solve et coagula
//
// Widget que arma payloads a partir de RevshellData, templando {LHOST}/{LPORT}/…
// con la barra de variables global (reusa sub() de app.js). Encodings opcionales
// (URL/Base64/double-URL/PS-enc). Las plantillas se re-renderizan cuando cambian
// las variables de arriba.

(function () {
  'use strict';

  const ENCODINGS = [
    { id: 'raw', label: 'Raw' },
    { id: 'url', label: 'URL' },
    { id: 'durl', label: 'Double-URL' },
    { id: 'b64', label: 'Base64' },
    { id: 'psenc', label: 'PS -enc' },
  ];

  let active = 'reverse';
  let enc = 'raw';

  function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  // sustitución de variables: usa sub() global si existe; si no, deja crudo
  function tpl(s) { return (typeof sub === 'function') ? sub(s) : s; }

  function encode(s) {
    switch (enc) {
      case 'url': return encodeURIComponent(s);
      case 'durl': return encodeURIComponent(encodeURIComponent(s));
      case 'b64':
        try { return btoa(unescape(encodeURIComponent(s))); } catch (e) { return s; }
      case 'psenc': {
        // UTF-16LE → base64 (lo que espera powershell -EncodedCommand)
        let bytes = '';
        for (let i = 0; i < s.length; i++) {
          const c = s.charCodeAt(i);
          bytes += String.fromCharCode(c & 0xff, (c >> 8) & 0xff);
        }
        try { return 'powershell -nop -w hidden -e ' + btoa(bytes); } catch (e) { return s; }
      }
      default: return s;
    }
  }

  function cat() { return RevshellData.categories.find(c => c.id === active); }

  function render(container) {
    const vchips = ['LHOST', 'LPORT', 'RHOST', 'RPORT', 'DOMAIN']
      .map(k => '<span class="rs-var"><b>' + k + '</b> <span data-v="' + k + '">' + esc(tpl('{' + k + '}')) + '</span></span>').join('');

    const tabs = RevshellData.categories.map(c =>
      '<button class="rs-tab" data-cat="' + c.id + '">' + esc(c.label) + '</button>').join('');

    container.innerHTML =
      '<div class="sec-hdr"><div class="sec-title">🐚 Reverse Shell &amp; C2</div>' +
      '<span class="sec-cmds-badge">generator</span></div>' +
      '<div class="lab-intro">Payloads templados con tus variables (<b>LHOST/LPORT/RHOST</b> de la barra ' +
      'de arriba). Editá las variables arriba y todo se actualiza. Click en cualquier payload para copiarlo.</div>' +
      '<div class="rs-vars">' + vchips + '</div>' +
      '<div class="rs-tabs">' + tabs + '</div>' +
      '<div class="rs-enc" id="rsEnc"></div>' +
      '<div id="rsOut"></div>';

    container.querySelectorAll('.rs-tab').forEach(b => {
      b.onclick = () => { active = b.dataset.cat; renderOut(container); };
    });

    // re-render cuando cambian las variables globales (barra de arriba)
    ['lhost', 'lport', 'rhost', 'rport', 'domain'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.addEventListener('input', () => refreshVars(container));
    });

    renderOut(container);
  }

  function refreshVars(container) {
    container.querySelectorAll('[data-v]').forEach(el => {
      el.textContent = tpl('{' + el.dataset.v + '}');
    });
    renderOut(container);
  }

  function renderOut(container) {
    const c = cat();
    // marcar tab activa
    container.querySelectorAll('.rs-tab').forEach(b => b.classList.toggle('on', b.dataset.cat === active));

    // fila de encodings (sólo si la categoría lo permite)
    const encBar = container.querySelector('#rsEnc');
    if (c.enc) {
      encBar.style.display = '';
      encBar.innerHTML = '<span class="rs-enc-lbl">Encoding:</span>' + ENCODINGS.map(e =>
        '<button class="rs-encb' + (e.id === enc ? ' on' : '') + '" data-enc="' + e.id + '">' + e.label + '</button>').join('');
      encBar.querySelectorAll('.rs-encb').forEach(b => {
        b.onclick = () => { enc = b.dataset.enc; renderOut(container); };
      });
    } else {
      encBar.style.display = 'none';
    }

    let html = '';
    if (c.note) html += '<div class="lab-note">' + esc(c.note) + '</div>';
    c.groups.forEach(g => {
      html += '<div class="lab-sub">' + esc(g.name) + '</div>';
      g.items.forEach(it => {
        const payload = c.enc ? encode(tpl(it[1])) : tpl(it[1]);
        html += '<div class="rs-item" data-pl="' + esc(payload) + '">' +
          '<div class="rs-item-l">' + esc(it[0]) + '</div>' +
          '<code class="rs-item-c">' + esc(payload) + '</code>' +
          '<button class="rs-copy">copy</button></div>';
      });
    });
    const out = container.querySelector('#rsOut');
    out.innerHTML = html;
    out.querySelectorAll('.rs-item').forEach(row => {
      const doCopy = () => { if (window.LAB) LAB.copy(row.dataset.pl); };
      row.querySelector('.rs-copy').onclick = doCopy;
      row.querySelector('.rs-item-c').onclick = doCopy;
    });
  }

  if (window.LAB) {
    LAB.registerTool({ id: 'revshell', label: 'Reverse Shell & C2', icon: '🐚', group: '🧪 LAB / TOOLS', render });
  }
})();
