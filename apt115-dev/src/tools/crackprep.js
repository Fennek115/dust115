// APT115 CODEX ARCANUM — Cracking-prep (perfilador + máscaras + reglas)
// quod est superius est sicut quod inferius
//
// Tres utilidades OFFLINE para preparar un ataque de diccionario en un pentest
// autorizado — no crackea nada ni trae wordlists:
//  1. Perfilador de objetivo (CUPP-lite, lógica portada): de datos del objetivo
//     genera candidatos (concatenaciones, capitalización, leet, sufijos
//     numéricos/de símbolo, formatos de fecha, keyboard walks). Fundado en la
//     investigación: los números van casi siempre AL FINAL (sobre todo el 1) y
//     las fechas son el 2º dato más usado.
//  2. Estimador de keyspace de máscaras hashcat (PACK-style): ?u?l?l?d?d →
//     producto de tamaños de charset, y tiempo a N intentos/seg.
//  3. Aplicador de reglas hashcat/JtR: preview de candidatos desde una palabra
//     base (subset común de funciones).
// Todo local, sin red. CUPP (GPLv3) y PACK (BSD-3): lógica portada, no código.

export const crackprep = (function () {
  'use strict';

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  function cap(w) { return w ? w[0].toUpperCase() + w.slice(1) : w; }

  // ── 1. Perfilador (CUPP-lite) ─────────────────────────────────────────
  const LEET = { a: '4', e: '3', i: '1', o: '0', s: '5', t: '7', l: '1', g: '9', b: '8' };
  const LEET2 = { a: '@', e: '3', i: '!', o: '0', s: '$', t: '7' };
  function leetVariants(w) {
    const v1 = w.replace(/[aeiostlgb]/g, c => LEET[c] || c);
    const v2 = w.replace(/[aeiost]/g, c => LEET2[c] || c);
    return [...new Set([v1, v2])].filter(x => x !== w);
  }

  /** Extrae fragmentos numéricos útiles de una fecha (varios formatos). */
  function extractDateNums(str) {
    const s = String(str == null ? '' : str).trim();
    const out = [];
    const m = /(\d{1,4})\D(\d{1,2})\D(\d{1,4})/.exec(s);
    if (!m) { const y = /^\d{4}$/.exec(s); if (y) { out.push(s, s.slice(2)); } return out; }
    let a = m[1], b = m[2], c = m[3], yyyy, mm, dd;
    if (a.length === 4) { yyyy = a; mm = b.padStart(2, '0'); dd = c.padStart(2, '0'); }
    else if (c.length === 4) { dd = a.padStart(2, '0'); mm = b.padStart(2, '0'); yyyy = c; }
    else { dd = a.padStart(2, '0'); mm = b.padStart(2, '0'); yyyy = (+c < 30 ? '20' : '19') + c.padStart(2, '0'); }
    const yy = yyyy.slice(2);
    out.push(yyyy, yy, dd + mm, mm + dd, dd + mm + yyyy, mm + yyyy, dd + mm + yy, mm, dd);
    return [...new Set(out)];
  }

  const WALKS = ['123456', 'password', 'qwerty', 'qwerty123', '111111', '12345678',
    'abc123', 'letmein', '1q2w3e', '1qaz2wsx', 'qazwsx', 'admin', 'iloveyou'];

  /**
   * Genera una wordlist de candidatos desde datos del objetivo.
   * @param {Record<string,string>} data @param {Record<string,any>} [opts]
   * @returns {string[]}
   */
  function profile(data, opts) {
    const o = Object.assign({ leet: true, numbers: true, specials: true, caps: true, combine: true, walks: true, minLen: 1, maxLen: 40, limit: 50000, years: [] }, opts || {});
    const out = new Set();
    let full = false;
    const add = (s) => {
      if (full) return;
      if (s && s.length >= o.minLen && s.length <= o.maxLen) out.add(s);
      if (out.size >= o.limit) full = true;
    };

    const words = [];
    const push = (v) => { if (v) { const w = String(v).trim().toLowerCase().replace(/\s+/g, ''); if (w) words.push(w); } };
    ['first', 'last', 'nick', 'partner', 'partnerNick', 'pet', 'company'].forEach(k => push(data[k]));
    (data.kids || '').split(/[,;]/).forEach(push);
    (data.extra || '').split(/[,;]/).forEach(push);
    const uniq = [...new Set(words)];

    const nums = new Set();
    if (o.numbers) {
      ['1', '12', '123', '1234', '12345', '123456', '007', '69', '321'].forEach(n => nums.add(n));
      for (let i = 0; i < 100; i++) nums.add(String(i).padStart(2, '0'));
      (o.years || []).forEach(y => nums.add(String(y)));
      ['birth', 'partnerBirth', 'anniversary', 'kidBirth'].forEach(k => { if (data[k]) extractDateNums(data[k]).forEach(n => nums.add(n)); });
    }
    const specials = o.specials ? ['!', '@', '#', '$', '.', '_', '*', '123!', '!@#'] : [];

    // candidatos base (palabra + capitalización + leet) y combinaciones de pares
    const cands = new Set();
    for (const w of uniq) {
      (o.caps ? [w, cap(w), w.toUpperCase()] : [w]).forEach(v => cands.add(v));
      if (o.leet) leetVariants(w).forEach(v => cands.add(v));
    }
    if (o.combine) {
      for (let i = 0; i < uniq.length; i++) for (let j = 0; j < uniq.length; j++) {
        if (i === j) continue;
        ['', '.', '_', '-'].forEach(sep => cands.add(uniq[i] + sep + uniq[j]));
        if (o.caps) cands.add(cap(uniq[i]) + cap(uniq[j]));
      }
    }

    for (const c of cands) {
      add(c);
      if (full) break;
      for (const n of nums) { add(c + n); if (full) break; }
      if (full) break;
      for (const s of specials) { add(c + s); if (full) break; }
      if (full) break;
      // patrón muy común: palabra + número + símbolo (p.ej. año + !)
      for (const n of nums) { add(c + n + '!'); if (full) break; }
      if (full) break;
    }
    if (o.walks) WALKS.forEach(add);
    return [...out];
  }

  // ── 2. Estimador de keyspace de máscaras (hashcat) ────────────────────
  const MASK_SETS = { l: 26, u: 26, d: 10, s: 33, a: 95, b: 256, h: 16, H: 16 };
  function humanTime(secs) {
    if (!isFinite(secs)) return '∞';
    if (secs < 1) return '< 1 s';
    const u = [['año', 31557600], ['día', 86400], ['hora', 3600], ['min', 60], ['s', 1]];
    const parts = [];
    for (const [name, len] of u) { if (secs >= len) { const v = Math.floor(secs / len); secs -= v * len; parts.push(v + ' ' + name + (v !== 1 && name !== 'min' && name !== 's' ? 's' : '')); if (parts.length === 2) break; } }
    return parts.join(' ');
  }
  /** Máscara hashcat → keyspace y tiempo a `pps` intentos/seg. @param {string} mask @param {number} pps */
  function maskKeyspace(mask, pps) {
    const rate = pps > 0 ? pps : 1e9;
    const m = String(mask == null ? '' : mask);
    const sizes = [];
    let i = 0;
    while (i < m.length) {
      if (m[i] === '?') {
        const t = m[i + 1];
        if (t === undefined) return { ok: false, error: '"?" al final sin tipo de charset.' };
        if (t === '?') sizes.push({ n: 1, label: '?' });
        else if (MASK_SETS[t] !== undefined) sizes.push({ n: MASK_SETS[t], label: '?' + t });
        else return { ok: false, error: 'Charset ?' + t + ' no soportado (usá l u d s a b h).' };
        i += 2;
      } else { sizes.push({ n: 1, label: m[i] }); i++; }
    }
    if (!sizes.length) return { ok: false, error: 'Máscara vacía.' };
    let combos = 1n;
    for (const s of sizes) combos *= BigInt(s.n);
    const combosNum = Number(combos);
    const seconds = combosNum / rate;
    return { ok: true, length: sizes.length, perPosition: sizes, combinations: combos.toString(), combosNum, seconds, human: humanTime(seconds) };
  }

  // ── 3. Aplicador de reglas hashcat/JtR (subset) ───────────────────────
  function pos(ch) { const c = String(ch).toUpperCase().charCodeAt(0); return c >= 48 && c <= 57 ? c - 48 : c - 55; } // 0-9, A=10…
  function toggle(ch) { return ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase(); }

  /** Aplica una línea de reglas hashcat a una palabra. @param {string} word @param {string} rule */
  function applyRule(word, rule) {
    let w = String(word);
    const r = String(rule);
    let i = 0;
    while (i < r.length) {
      const f = r[i];
      if (f === ' ' || f === '\t') { i++; continue; }
      switch (f) {
        case ':': break;
        case 'l': w = w.toLowerCase(); break;
        case 'u': w = w.toUpperCase(); break;
        case 'c': w = w ? w[0].toUpperCase() + w.slice(1).toLowerCase() : w; break;
        case 'C': w = w ? w[0].toLowerCase() + w.slice(1).toUpperCase() : w; break;
        case 't': w = [...w].map(toggle).join(''); break;
        case 'r': w = [...w].reverse().join(''); break;
        case 'd': w = w + w; break;
        case 'f': w = w + [...w].reverse().join(''); break;
        case '{': w = w.slice(1) + w.slice(0, 1); break;
        case '}': w = w.slice(-1) + w.slice(0, -1); break;
        case '[': w = w.slice(1); break;
        case ']': w = w.slice(0, -1); break;
        case '$': i++; w = w + (r[i] || ''); break;
        case '^': i++; w = (r[i] || '') + w; break;
        case 'T': { i++; const n = pos(r[i]); if (n >= 0 && n < w.length) w = w.slice(0, n) + toggle(w[n]) + w.slice(n + 1); break; }
        case 'D': { i++; const n = pos(r[i]); if (n >= 0) w = w.slice(0, n) + w.slice(n + 1); break; }
        case 'o': { i++; const n = pos(r[i]); i++; const ch = r[i] || ''; if (n >= 0 && n < w.length) w = w.slice(0, n) + ch + w.slice(n + 1); break; }
        case 'i': { i++; const n = pos(r[i]); i++; const ch = r[i] || ''; if (n >= 0) w = w.slice(0, n) + ch + w.slice(n); break; }
        case 's': { i++; const x = r[i]; i++; const y = r[i] || ''; if (x != null) w = w.split(x).join(y); break; }
        case '@': { i++; const x = r[i]; if (x != null) w = w.split(x).join(''); break; }
        default: break; // función no soportada: se ignora
      }
      i++;
    }
    return w;
  }
  /** Aplica varias líneas de reglas a una palabra. @returns {{rule:string, result:string}[]} */
  function applyRules(word, rulesText) {
    return String(rulesText == null ? '' : rulesText).split(/\r?\n/).map(l => l.trim()).filter(Boolean)
      .map(rule => ({ rule, result: applyRule(word, rule) }));
  }

  // ── Render ────────────────────────────────────────────────────────────
  let lastList = [];

  function downloadText(name, text) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  const FIELDS = [
    ['first', 'Nombre'], ['last', 'Apellido'], ['nick', 'Apodo'],
    ['partner', 'Pareja'], ['kids', 'Hijos (coma)'], ['pet', 'Mascota'],
    ['company', 'Empresa/equipo'], ['extra', 'Palabras clave (coma)'],
    ['birth', 'Nacimiento (fecha)'], ['anniversary', 'Aniversario (fecha)'],
  ];

  function render(container) {
    container.innerHTML =
      '<div class="lab-sec">' +
      '<div class="lab-intro"><b>Cracking-prep.</b> Para un pentest autorizado: perfila candidatos desde ' +
      'datos del objetivo, estima el keyspace de una máscara hashcat y previsualiza reglas. ' +
      'Todo local — no crackea nada ni descarga wordlists.</div>' +

      '<div class="lab-panel"><div class="lab-panel-h" onclick="this.parentElement.classList.toggle(\'collapsed\')">' +
      '<span>👤 Perfilador de objetivo</span><span class="lab-panel-x">▾</span></div><div class="lab-panel-b">' +
      '<div class="cp-form">' +
      FIELDS.map(f => '<label class="cp-fld"><span>' + esc(f[1]) + '</span><input id="cp_' + f[0] + '" spellcheck="false"></label>').join('') +
      '</div>' +
      '<div class="cp-opts">' +
      ['leet', 'numbers', 'specials', 'caps', 'combine', 'walks'].map(k => '<label><input type="checkbox" id="cp_o_' + k + '" checked> ' + k + '</label>').join('') +
      '</div>' +
      '<div class="x5-actions"><button id="cpGen" class="cv-btn">Generar wordlist</button>' +
      '<button id="cpCopy" class="cv-btn">copiar</button><button id="cpDl" class="cv-btn">descargar .txt</button>' +
      '<span id="cpCount" class="lab-dim"></span></div>' +
      '<textarea id="cpOut" class="cv-io out" readonly spellcheck="false" style="min-height:140px"></textarea>' +
      '</div></div>' +

      '<div class="lab-panel collapsed"><div class="lab-panel-h" onclick="this.parentElement.classList.toggle(\'collapsed\')">' +
      '<span>🎭 Keyspace de máscara (hashcat)</span><span class="lab-panel-x">▾</span></div><div class="lab-panel-b">' +
      '<div class="cp-row"><input id="cpMask" class="cv-key" placeholder="?u?l?l?l?d?d?d" spellcheck="false">' +
      '<select id="cpPps"><option value="1000000000">1 GH/s (GPU media)</option>' +
      '<option value="100000000000">100 GH/s (rig)</option>' +
      '<option value="100000">100 KH/s (bcrypt)</option></select>' +
      '<button id="cpMaskGo" class="cv-btn">Estimar</button></div>' +
      '<div id="cpMaskOut"></div></div></div>' +

      '<div class="lab-panel collapsed"><div class="lab-panel-h" onclick="this.parentElement.classList.toggle(\'collapsed\')">' +
      '<span>🧰 Reglas hashcat/JtR</span><span class="lab-panel-x">▾</span></div><div class="lab-panel-b">' +
      '<div class="cp-row"><input id="cpWord" class="cv-key" placeholder="palabra base (ej: password)" spellcheck="false"></div>' +
      '<textarea id="cpRules" class="cv-io" spellcheck="false" style="min-height:80px" placeholder="una regla por línea, ej:&#10;c $1 $2 $3&#10;sa@ so0&#10;r"></textarea>' +
      '<div class="x5-actions"><button id="cpRulesGo" class="cv-btn">Aplicar</button></div>' +
      '<div id="cpRulesOut"></div></div></div>' +
      '</div>';

    // perfilador
    const collectData = () => { const d = {}; FIELDS.forEach(f => { d[f[0]] = container.querySelector('#cp_' + f[0]).value; }); return d; };
    const collectOpts = () => { const o = {}; ['leet', 'numbers', 'specials', 'caps', 'combine', 'walks'].forEach(k => { o[k] = container.querySelector('#cp_o_' + k).checked; }); return o; };
    container.querySelector('#cpGen').onclick = () => {
      lastList = profile(collectData(), collectOpts());
      container.querySelector('#cpOut').value = lastList.join('\n');
      container.querySelector('#cpCount').textContent = lastList.length + ' candidatos';
    };
    container.querySelector('#cpCopy').onclick = () => { if (window.LAB) window.LAB.copy(lastList.join('\n')); };
    container.querySelector('#cpDl').onclick = () => { if (lastList.length) downloadText('apt115_wordlist.txt', lastList.join('\n')); };

    // máscara
    container.querySelector('#cpMaskGo').onclick = () => {
      const r = maskKeyspace(container.querySelector('#cpMask').value, +container.querySelector('#cpPps').value);
      const out = container.querySelector('#cpMaskOut');
      if (!r.ok) { out.innerHTML = '<div class="lab-note">' + esc(r.error) + '</div>'; return; }
      out.innerHTML = '<table class="lab-kv"><tbody>' +
        '<tr><th>Largo</th><td>' + r.length + ' posiciones</td></tr>' +
        '<tr><th>Combinaciones</th><td><code>' + esc(r.combinations) + '</code></td></tr>' +
        '<tr><th>Tiempo estimado</th><td>' + esc(r.human) + '</td></tr>' +
        '<tr><th>Por posición</th><td>' + r.perPosition.map(p => esc(p.label) + '=' + p.n).join(' · ') + '</td></tr>' +
        '</tbody></table>';
    };

    // reglas
    container.querySelector('#cpRulesGo').onclick = () => {
      const res = applyRules(container.querySelector('#cpWord').value, container.querySelector('#cpRules').value);
      const out = container.querySelector('#cpRulesOut');
      if (!res.length) { out.innerHTML = '<div class="lab-note">Poné una palabra base y al menos una regla.</div>'; return; }
      out.innerHTML = '<table class="lab-table"><thead><tr><th>Regla</th><th>Resultado</th></tr></thead><tbody>' +
        res.map(x => '<tr><td><code>' + esc(x.rule) + '</code></td><td><code>' + esc(x.result) + '</code></td></tr>').join('') +
        '</tbody></table>';
    };
  }

  if (typeof window !== 'undefined' && window.LAB) {
    window.LAB.registerTool({ id: 'crackprep', label: 'Cracking-prep', icon: '🔓', group: '🧪 LAB / TOOLS', render });
  }
  return { profile, extractDateNums, leetVariants, maskKeyspace, applyRule, applyRules, humanTime };
})();
