// APT115 CODEX ARCANUM — Mini-CyberChef
// Encode/decode, hashing, JWT y hash-ID. Todo client-side, sin deps salvo
// SparkMD5 (MD5) y crypto.subtle (SHA). Operaciones puras input→output.

export const convert = (function () {
  'use strict';

  function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // ── operaciones de codificación ──────────────────────────────
  const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  function b32enc(s) {
    let bits = '', out = '';
    for (let i = 0; i < s.length; i++) bits += s.charCodeAt(i).toString(2).padStart(8, '0');
    for (let i = 0; i + 5 <= bits.length; i += 5) out += B32[parseInt(bits.substr(i, 5), 2)];
    const rem = bits.length % 5;
    if (rem) out += B32[parseInt(bits.substr(bits.length - rem).padEnd(5, '0'), 2)];
    while (out.length % 8) out += '=';
    return out;
  }
  function b32dec(s) {
    s = s.replace(/=+$/, '').toUpperCase().replace(/[^A-Z2-7]/g, '');
    let bits = '', out = '';
    for (const c of s) bits += B32.indexOf(c).toString(2).padStart(5, '0');
    for (let i = 0; i + 8 <= bits.length; i += 8) out += String.fromCharCode(parseInt(bits.substr(i, 8), 2));
    return out;
  }
  function b64enc(s) { return btoa(unescape(encodeURIComponent(s))); }
  function b64dec(s) { return decodeURIComponent(escape(atob(s.trim().replace(/\s+/g, '')))); }
  function hexenc(s) { let o = ''; for (let i = 0; i < s.length; i++) o += s.charCodeAt(i).toString(16).padStart(2, '0'); return o; }
  function hexdec(s) { s = s.replace(/[^0-9a-fA-F]/g, ''); let o = ''; for (let i = 0; i + 2 <= s.length; i += 2) o += String.fromCharCode(parseInt(s.substr(i, 2), 16)); return o; }
  function htmlenc(s) { return s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
  function htmldec(s) { const t = document.createElement('textarea'); t.innerHTML = s; return t.value; }
  function rot(s, n) { n = ((parseInt(n) || 13) % 26 + 26) % 26; return s.replace(/[a-z]/g, c => String.fromCharCode((c.charCodeAt(0) - 97 + n) % 26 + 97)).replace(/[A-Z]/g, c => String.fromCharCode((c.charCodeAt(0) - 65 + n) % 26 + 65)); }
  function xor(s, key) {
    if (!key) return '(definí una key XOR)';
    let o = '';
    for (let i = 0; i < s.length; i++) o += (s.charCodeAt(i) ^ key.charCodeAt(i % key.length)).toString(16).padStart(2, '0');
    return o;
  }

  function jwt(s) {
    const p = s.trim().split('.');
    if (p.length < 2) return 'No parece un JWT (formato header.payload.signature).';
    const dec = (x) => { try { return JSON.stringify(JSON.parse(b64dec(x.replace(/-/g, '+').replace(/_/g, '/'))), null, 2); } catch (e) { return '(no decodificable)'; } };
    let out = '── HEADER ──\n' + dec(p[0]) + '\n\n── PAYLOAD ──\n' + dec(p[1]);
    try {
      const h = JSON.parse(b64dec(p[0].replace(/-/g, '+').replace(/_/g, '/')));
      if (h.alg && String(h.alg).toLowerCase() === 'none') out += '\n\n⚠ alg=none — JWT sin firma (posible bypass de auth)';
    } catch (e) {}
    try {
      const pl = JSON.parse(b64dec(p[1].replace(/-/g, '+').replace(/_/g, '/')));
      if (pl.exp) out += '\n\nexp: ' + new Date(pl.exp * 1000).toISOString() + (pl.exp * 1000 < Date.now() ? ' (EXPIRADO)' : '');
    } catch (e) {}
    out += '\n\n── SIGNATURE ──\n' + (p[2] || '(vacía)');
    return out;
  }

  // hash-ID por longitud/charset
  function hashid(s) {
    s = s.trim();
    const out = [];
    if (/^[a-f0-9]{32}$/i.test(s)) out.push('MD5 / NTLM / MD4 (32 hex)');
    if (/^[a-f0-9]{40}$/i.test(s)) out.push('SHA-1 (40 hex)');
    if (/^[a-f0-9]{56}$/i.test(s)) out.push('SHA-224');
    if (/^[a-f0-9]{64}$/i.test(s)) out.push('SHA-256 (64 hex)');
    if (/^[a-f0-9]{96}$/i.test(s)) out.push('SHA-384');
    if (/^[a-f0-9]{128}$/i.test(s)) out.push('SHA-512 (128 hex)');
    if (/^\$2[aby]\$\d{2}\$/.test(s)) out.push('bcrypt');
    if (/^\$1\$/.test(s)) out.push('md5crypt ($1$)');
    if (/^\$6\$/.test(s)) out.push('sha512crypt ($6$)');
    if (/^\$5\$/.test(s)) out.push('sha256crypt ($5$)');
    if (/^[a-f0-9]{32}:[a-f0-9]{32}$/i.test(s)) out.push('NTLMv1 / MD5(salt) (hash:hash)');
    if (/^[a-f0-9]{16}$/i.test(s)) out.push('MySQL<4.1 / LM half (16 hex)');
    if (/^\*[A-F0-9]{40}$/i.test(s)) out.push('MySQL 4.1+ (*SHA1)');
    return out.length ? out.join('\n') : 'No reconocido (longitud ' + s.length + ').';
  }

  async function sha(algo, s) {
    const data = new TextEncoder().encode(s);
    const d = await crypto.subtle.digest(algo, data);
    return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
  }
  async function hashes(s) {
    const md5 = (typeof SparkMD5 !== 'undefined') ? SparkMD5.hash(s) : '(SparkMD5 no cargado)';
    const [s1, s256, s512] = await Promise.all([sha('SHA-1', s), sha('SHA-256', s), sha('SHA-512', s)]);
    return 'MD5    ' + md5 + '\nSHA-1  ' + s1 + '\nSHA256 ' + s256 + '\nSHA512 ' + s512;
  }

  // ── timestamp ────────────────────────────────────────────────
  function relTime(date) {
    const diff = date.getTime() - Date.now();
    const abs = Math.abs(diff), fut = diff > 0;
    const units = [['año', 'años', 31536e6], ['mes', 'meses', 2592e6], ['día', 'días', 864e5],
      ['hora', 'horas', 36e5], ['minuto', 'minutos', 6e4], ['segundo', 'segundos', 1e3]];
    for (const [sing, plur, ms] of units) {
      if (abs >= ms) { const v = Math.floor(abs / ms); return (fut ? 'en ' : 'hace ') + v + ' ' + (v === 1 ? sing : plur); }
    }
    return 'ahora mismo';
  }
  /** Detecta epoch (s/ms/µs/ns por cantidad de dígitos) o fecha parseable. */
  function tsConvert(input) {
    const s = String(input == null ? '' : input).trim();
    if (!s) return { ok: false, error: 'Pegá un epoch o una fecha.' };
    let date = null, srcKind = '';
    if (/^-?\d+$/.test(s)) {
      const n = Number(s), len = s.replace('-', '').length;
      if (len <= 11) { date = new Date(n * 1000); srcKind = 'epoch en segundos'; }
      else if (len <= 14) { date = new Date(n); srcKind = 'epoch en milisegundos'; }
      else if (len <= 17) { date = new Date(n / 1000); srcKind = 'epoch en microsegundos'; }
      else { date = new Date(n / 1e6); srcKind = 'epoch en nanosegundos'; }
    } else {
      const t = Date.parse(s);
      if (!isNaN(t)) { date = new Date(t); srcKind = 'fecha'; }
    }
    if (!date || isNaN(date.getTime())) return { ok: false, error: 'No reconocí un epoch ni una fecha válida.' };
    return {
      ok: true, srcKind, iso: date.toISOString(), utc: date.toUTCString(), local: date.toString(),
      epochS: Math.floor(date.getTime() / 1000), epochMs: date.getTime(), rel: relTime(date),
    };
  }
  function tsToString(r) {
    if (!r.ok) return '⚠ ' + r.error;
    return [
      'Interpretado como ' + r.srcKind,
      'ISO 8601 (UTC) : ' + r.iso,
      'UTC            : ' + r.utc,
      'Local          : ' + r.local,
      'Epoch (s)      : ' + r.epochS,
      'Epoch (ms)     : ' + r.epochMs,
      'Relativo       : ' + r.rel,
    ].join('\n');
  }

  // ── regex tester (texto = input, patrón = campo Key; acepta /pat/flags) ──
  function regexTest(pattern, text) {
    const pat = String(pattern == null ? '' : pattern);
    if (!pat) return { ok: false, error: 'Poné el patrón en el campo Key (acepta /patrón/flags).' };
    let body = pat, flags = '';
    const m = /^\/(.*)\/([gimsuy]*)$/.exec(pat);
    if (m) { body = m[1]; flags = m[2]; }
    if (!/g/.test(flags)) flags += 'g';
    let re;
    try { re = new RegExp(body, flags); } catch (e) { return { ok: false, error: 'Regex inválida: ' + (e && e.message || e) }; }
    const matches = [];
    let mm, guard = 0;
    const str = String(text == null ? '' : text);
    while ((mm = re.exec(str)) && guard++ < 10000) {
      matches.push({ match: mm[0], index: mm.index, groups: mm.slice(1) });
      if (mm.index === re.lastIndex) re.lastIndex++; // evita loop en matches de ancho cero
    }
    return { ok: true, count: matches.length, matches, flags, source: body };
  }
  function regexToString(r) {
    if (!r.ok) return '⚠ ' + r.error;
    const head = '/' + r.source + '/' + r.flags;
    if (!r.count) return 'Sin coincidencias.  (' + head + ')';
    const lines = [head + ' — ' + r.count + ' coincidencia(s):', ''];
    r.matches.slice(0, 200).forEach((m, i) => {
      let line = '[' + i + '] @' + m.index + '  ' + JSON.stringify(m.match);
      if (m.groups.length) line += '   grupos: ' + m.groups.map(g => g === undefined ? '∅' : JSON.stringify(g)).join(', ');
      lines.push(line);
    });
    if (r.count > 200) lines.push('… (+' + (r.count - 200) + ' más)');
    return lines.join('\n');
  }

  // catálogo de operaciones (label → fn(input,key)). usaKey marca XOR/ROT.
  const OPS = [
    { g: 'Base64', ops: [['Encode', s => b64enc(s)], ['Decode', s => b64dec(s)]] },
    { g: 'Hex', ops: [['Encode', s => hexenc(s)], ['Decode', s => hexdec(s)]] },
    { g: 'URL', ops: [['Encode', s => encodeURIComponent(s)], ['Decode', s => decodeURIComponent(s)]] },
    { g: 'Base32', ops: [['Encode', s => b32enc(s)], ['Decode', s => b32dec(s)]] },
    { g: 'HTML', ops: [['Encode', s => htmlenc(s)], ['Decode', s => htmldec(s)]] },
    { g: 'Cifras', ops: [['ROT-N', (s, k) => rot(s, k), 'key'], ['XOR (hex)', (s, k) => xor(s, k), 'key']] },
    { g: 'JWT', ops: [['Decode', s => jwt(s)]] },
    { g: 'Hashes', ops: [['MD5/SHA-1/256/512', s => hashes(s)], ['Hash ID', s => hashid(s)]] },
    { g: 'Timestamp', ops: [['Epoch/Fecha →', s => tsToString(tsConvert(s))], ['Ahora', () => tsToString(tsConvert('' + Math.floor(Date.now() / 1000)))]] },
    { g: 'Regex', ops: [['Probar (Key=patrón)', (s, k) => regexToString(regexTest(k, s)), 'key']] },
  ];

  function render(container) {
    let btns = '';
    OPS.forEach(grp => {
      btns += '<div class="cv-grp"><span class="cv-glbl">' + grp.g + '</span>';
      grp.ops.forEach((o, i) => {
        btns += '<button class="cv-btn" data-g="' + grp.g + '" data-i="' + i + '">' + o[0] + '</button>';
      });
      btns += '</div>';
    });

    container.innerHTML =
      '<div class="sec-hdr"><div class="sec-title">🔁 Convert / Hash</div>' +
      '<span class="sec-cmds-badge">mini-cyberchef</span></div>' +
      '<div class="lab-intro">Encode/decode, hashing, JWT, hash-ID, timestamp y regex — todo local en el navegador.</div>' +
      '<textarea class="cv-io" id="cvIn" placeholder="Input… (texto, epoch/fecha, o el texto a testear con regex)" spellcheck="false"></textarea>' +
      '<div class="cv-keyrow"><label>Key / N / patrón (XOR · ROT · Regex):</label><input class="cv-key" id="cvKey" placeholder="ej: 13  ·  s3cr3t  ·  /\\d+/g"></div>' +
      '<div class="cv-ops">' + btns + '</div>' +
      '<div class="cv-outrow"><span class="lab-sub" style="margin:0">Output</span><button class="rs-copy" id="cvCopy">copy</button></div>' +
      '<textarea class="cv-io out" id="cvOut" readonly spellcheck="false" placeholder="Resultado…"></textarea>';

    const inEl = container.querySelector('#cvIn');
    const keyEl = container.querySelector('#cvKey');
    const outEl = container.querySelector('#cvOut');

    container.querySelectorAll('.cv-btn').forEach(b => {
      b.onclick = async () => {
        const grp = OPS.find(x => x.g === b.dataset.g);
        const op = grp.ops[+b.dataset.i];
        try {
          outEl.value = '…';
          const r = await Promise.resolve(op[1](inEl.value, keyEl.value));
          outEl.value = r;
        } catch (e) {
          outEl.value = '⚠ Error: ' + (e && e.message || e);
        }
      };
    });
    container.querySelector('#cvCopy').onclick = () => { if (window.LAB) LAB.copy(outEl.value); };
  }

  if (typeof window !== 'undefined' && window.LAB) {
    window.LAB.registerTool({ id: 'convert', label: 'Convert / Hash', icon: '🔁', group: '🧪 LAB / TOOLS', render });
  }
  // Hook de test: núcleo puro verificable desde Node.
  return { tsConvert, regexTest, hashid };
})();
