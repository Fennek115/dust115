// APT115 CODEX ARCANUM — IOC Extractor
// quod est superius est sicut quod inferius
//
// Pegás un reporte de threat intel / log / cualquier texto y extrae IOCs:
// IPs, dominios, URLs, emails, hashes (MD5/SHA1/SHA256), CVEs, IDs ATT&CK,
// claves de registro y rutas Windows. Refanguea la entrada primero
// (hxxp→http, [.]→.) y permite defanguear la salida para pegar en reportes.
// 100% local, JS puro, sin red.

(function () {
  'use strict';

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  function escAttr(s) { return esc(s).replace(/"/g, '&quot;'); }

  // ── Refang: normaliza indicadores ofuscados ANTES de extraer ──────────
  function refang(t) {
    return String(t)
      .replace(/h(?:tt|xx)ps/gi, 'https')
      .replace(/h(?:tt|xx)p/gi, 'http')
      .replace(/f(?:tp|xp)/gi, 'ftp')
      .replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}/g, '.')
      .replace(/\[\s*dot\s*\]|\(\s*dot\s*\)/gi, '.')
      .replace(/\s+dot\s+/gi, '.')
      .replace(/\[\s*:\s*\]/g, ':')
      .replace(/\[\s*\/\s*\]/g, '/')
      .replace(/\[\s*@\s*\]|\(\s*@\s*\)/g, '@')
      .replace(/\[\s*at\s*\]|\(\s*at\s*\)/gi, '@')
      .replace(/\[\s*:?\/\/\s*\]/g, '://');
  }

  // ── Defang: ofusca la salida para pegar segura en un reporte ──────────
  function defang(s) {
    return String(s)
      .replace(/\bhttps\b/gi, 'hxxps').replace(/\bhttp\b/gi, 'hxxp')
      .replace(/\bftp\b/gi, 'fxp')
      .replace(/@/g, '[at]')
      .replace(/\./g, '[.]');
  }

  // Extensiones de archivo: si el "TLD" de un dominio es una de estas, es un
  // nombre de archivo (foo.exe), no un dominio → se descarta.
  const FILE_EXT = new Set(('exe dll sys bat cmd ps1 vbs js jar jsp doc docx xls xlsx ' +
    'ppt pptx pdf zip rar 7z gz tar png jpg jpeg gif bmp svg ico txt log dat bin tmp ' +
    'ini cfg conf json xml yaml yml html htm css php asp aspx py sh rb go dmp lnk scr ' +
    'hta reg csv md rtf msi cab iso img vhd ovf db sqlite key pem crt cer').split(' '));

  // Categorías en orden de prioridad. Cada una: regex global + normalizador.
  // Los hashes van primero (64→40→32) — \b y la longitud los hacen exclusivos.
  const CATS = [
    { id: 'sha256', label: 'SHA-256', icon: '#', re: /\b[a-fA-F0-9]{64}\b/g, norm: s => s.toLowerCase() },
    { id: 'sha1', label: 'SHA-1', icon: '#', re: /\b[a-fA-F0-9]{40}\b/g, norm: s => s.toLowerCase() },
    { id: 'md5', label: 'MD5', icon: '#', re: /\b[a-fA-F0-9]{32}\b/g, norm: s => s.toLowerCase() },
    { id: 'url', label: 'URLs', icon: '🔗', re: /\b(?:https?|ftp):\/\/[^\s"'<>)\]}]+/gi, norm: s => s.replace(/[.,;)]+$/, '') },
    { id: 'email', label: 'Emails', icon: '✉', re: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g, norm: s => s.toLowerCase() },
    { id: 'ipv4', label: 'IPv4', icon: '🌐', re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g },
    { id: 'ipv6', label: 'IPv6', icon: '🌐', re: /\b(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{0,4}\b/g, norm: s => s.toLowerCase(), valid: s => (s.match(/:/g) || []).length >= 2 && /[a-f0-9]/i.test(s) },
    { id: 'domain', label: 'Dominios', icon: '🏷', re: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b/g, norm: s => s.toLowerCase(), valid: s => !FILE_EXT.has(s.split('.').pop().toLowerCase()) },
    { id: 'cve', label: 'CVEs', icon: '⚠', re: /\bCVE-\d{4}-\d{4,7}\b/gi, norm: s => s.toUpperCase() },
    { id: 'attack', label: 'ATT&CK IDs', icon: '🎯', re: /\bT\d{4}(?:\.\d{3})?\b/g },
    { id: 'registry', label: 'Registry', icon: '🗝', re: /\b(?:HK(?:LM|CU|CR|U|CC)|HKEY_[A-Z_]+)\\[^\s"'<>|]+/g },
    { id: 'winpath', label: 'Rutas Windows', icon: '📁', re: /\b[a-zA-Z]:\\[^\s"'<>|*?]+/g },
  ];

  let outFang = false; // estado del toggle "defang salida"

  function extract(text) {
    const src = refang(text);
    const out = {};
    for (const c of CATS) {
      const seen = new Set();
      const list = [];
      let m;
      c.re.lastIndex = 0;
      while ((m = c.re.exec(src)) !== null) {
        let v = m[0];
        if (c.norm) v = c.norm(v);
        if (c.valid && !c.valid(v)) continue;
        const key = v.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        list.push(v);
      }
      if (list.length) out[c.id] = list;
    }
    return out;
  }

  function render(container) {
    container.innerHTML =
      '<div class="sec-hdr"><div class="sec-title">🧬 IOC Extractor</div>' +
      '<span class="sec-cmds-badge" id="iocBadge">0 IOCs</span></div>' +
      '<div class="lab-intro">Pegá un reporte, log o cualquier texto y extrae indicadores. ' +
      'Refanguea la entrada (<code>hxxp→http</code>, <code>[.]→.</code>) y deduplica. ' +
      '100% local — nada sale del navegador.</div>' +
      '<textarea class="cv-io" id="iocIn" style="min-height:120px" ' +
        'placeholder="Pegá acá el texto con IOCs…&#10;Ej: el C2 hxxps://evil[.]com/p resolvía a 185[.]220[.]101[.]4"></textarea>' +
      '<div class="ioc-bar">' +
        '<label class="ioc-chk"><input type="checkbox" id="iocFang"> defang salida</label>' +
        '<button class="cv-btn" id="iocCopyAll">copiar todo</button>' +
        '<span class="lab-dim" id="iocHint">— escribí o pegá arriba</span>' +
      '</div>' +
      '<div id="iocOut"></div>';

    const inp = container.querySelector('#iocIn');
    const fang = container.querySelector('#iocFang');
    let t;
    inp.oninput = () => { clearTimeout(t); t = setTimeout(() => renderOut(container), 150); };
    fang.onchange = () => { outFang = fang.checked; renderOut(container); };
    container.querySelector('#iocCopyAll').onclick = () => copyAll(container);
  }

  let lastResult = {};

  function fmt(v) { return outFang ? defang(v) : v; }

  function renderOut(container) {
    const text = container.querySelector('#iocIn').value;
    const res = extract(text);
    lastResult = res;
    const out = container.querySelector('#iocOut');
    const total = Object.values(res).reduce((a, l) => a + l.length, 0);
    container.querySelector('#iocBadge').textContent = total + ' IOC' + (total === 1 ? '' : 's');
    const hint = container.querySelector('#iocHint');

    if (!text.trim()) { out.innerHTML = ''; if (hint) hint.textContent = '— escribí o pegá arriba'; return; }
    if (hint) hint.textContent = total ? '' : '— sin IOCs detectados';
    if (!total) { out.innerHTML = '<div class="lab-note">Sin indicadores en el texto.</div>'; return; }

    let html = '';
    for (const c of CATS) {
      const list = res[c.id];
      if (!list || !list.length) continue;
      html += '<div class="ioc-grp">' +
        '<div class="ioc-grp-h"><span>' + c.icon + ' ' + c.label +
        ' <span class="lab-dim">(' + list.length + ')</span></span>' +
        '<button class="ioc-copyg" data-cat="' + c.id + '">copiar</button></div>' +
        '<div class="ioc-list">' +
        list.map(v => '<div class="ioc-item" data-v="' + escAttr(fmt(v)) + '">' +
          '<code>' + esc(fmt(v)) + '</code></div>').join('') +
        '</div></div>';
    }
    out.innerHTML = html;

    out.querySelectorAll('.ioc-item').forEach(el => {
      el.onclick = () => { if (window.LAB) LAB.copy(el.dataset.v); };
    });
    out.querySelectorAll('.ioc-copyg').forEach(btn => {
      btn.onclick = (e) => {
        e.stopPropagation();
        const list = (lastResult[btn.dataset.cat] || []).map(fmt);
        if (list.length && window.LAB) LAB.copy(list.join('\n'));
      };
    });
  }

  function copyAll(container) {
    const res = lastResult;
    const parts = [];
    for (const c of CATS) {
      const list = res[c.id];
      if (!list || !list.length) continue;
      parts.push('# ' + c.label + ' (' + list.length + ')');
      list.forEach(v => parts.push(fmt(v)));
      parts.push('');
    }
    if (parts.length && window.LAB) LAB.copy(parts.join('\n').trim());
  }

  if (typeof window !== 'undefined' && window.LAB) {
    LAB.registerTool({ id: 'ioc', label: 'IOC Extractor', icon: '🧬', group: '🧪 LAB / TOOLS', render });
  }
  // Hook de test (no-op en browser): permite probar la lógica desde Node.
  if (typeof module !== 'undefined' && module.exports) module.exports = { refang, defang, extract };
})();
