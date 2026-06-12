// APT115 CODEX ARCANUM — Crypto / Payload Lab
// Destrabar payloads ofuscados: XOR (brute single-byte con scoring + detección de
// largo de clave estilo Kasiski/Hamming + recuperación columna a columna), RC4 y
// AES (vía Web Crypto). Todo client-side. El núcleo es puro y se exporta para test.

export const cryptolab = (function () {
  'use strict';

  function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // ── parseo de entrada → Uint8Array ───────────────────────────
  // Acepta hex (cualquier formato: 0x, espacios, \x, comas), base64 o texto crudo.
  function parseBytes(text, fmt) {
    text = text || '';
    if (fmt === 'text') return new TextEncoder().encode(text);
    if (fmt === 'hex' || fmt === 'auto') {
      const h = text.replace(/0x/gi, '').replace(/\\x/gi, '').replace(/[^0-9a-fA-F]/g, '');
      if (fmt === 'hex' || (h.length >= 2 && h.length % 2 === 0 && looksHex(text))) {
        const out = new Uint8Array(h.length / 2);
        for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
        return out;
      }
    }
    if (fmt === 'b64' || fmt === 'auto') {
      try {
        const clean = text.trim().replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
        if (/^[A-Za-z0-9+/]+={0,2}$/.test(clean) && clean.length % 4 === 0) {
          const bin = atob(clean);
          const out = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
          return out;
        }
      } catch (e) { /* sigue */ }
    }
    if (fmt === 'b64') throw new Error('base64 inválido');
    if (fmt === 'hex') throw new Error('hex inválido');
    // auto fallback → texto crudo
    return new TextEncoder().encode(text);
  }
  function looksHex(text) {
    const s = text.trim();
    return /^[0-9a-fA-F\s,0x\\]+$/.test(s) && (s.match(/[0-9a-fA-F]/g) || []).length >= 4;
  }

  // ── entropía Shannon (0–8 bits/byte) ─────────────────────────
  function entropy(bytes) {
    if (!bytes.length) return 0;
    const f = new Array(256).fill(0);
    for (const b of bytes) f[b]++;
    let e = 0;
    for (const c of f) if (c) { const p = c / bytes.length; e -= p * Math.log2(p); }
    return e;
  }

  // ── detección de magic bytes (señal de plaintext recuperado) ─
  const MAGICS = [
    [[0x4D, 0x5A], 'MZ (PE/DOS exe)'],
    [[0x7F, 0x45, 0x4C, 0x46], 'ELF'],
    [[0x50, 0x4B, 0x03, 0x04], 'ZIP/Office/JAR'],
    [[0x25, 0x50, 0x44, 0x46], '%PDF'],
    [[0x89, 0x50, 0x4E, 0x47], 'PNG'],
    [[0xFF, 0xD8, 0xFF], 'JPEG'],
    [[0x47, 0x49, 0x46, 0x38], 'GIF'],
    [[0x1F, 0x8B], 'gzip'],
    [[0x42, 0x5A, 0x68], 'bzip2'],
    [[0x52, 0x61, 0x72, 0x21], 'RAR'],
    [[0xFE, 0xED, 0xFA], 'Mach-O'],
    [[0xCA, 0xFE, 0xBA, 0xBE], 'Mach-O fat / Java class'],
    [[0x23, 0x21], '#! (script shebang)'],
    [[0x3C, 0x3F, 0x78, 0x6D, 0x6C], '<?xml'],
    [[0x3C, 0x68, 0x74, 0x6D, 0x6C], '<html'],
    [[0xEF, 0xBB, 0xBF], 'UTF-8 BOM'],
  ];
  function detectMagic(bytes) {
    for (const [sig, name] of MAGICS) {
      let ok = true;
      for (let i = 0; i < sig.length; i++) if (bytes[i] !== sig[i]) { ok = false; break; }
      if (ok) return name;
    }
    return null;
  }

  // ── scoring de plausibilidad de texto/payload ────────────────
  // Frecuencia de letras en inglés (×1000) — base para chi² aprox.
  const ENG = { e: 127, t: 91, a: 82, o: 75, i: 70, n: 67, s: 63, h: 61, r: 60, d: 43, l: 40, c: 28, u: 28, m: 24, w: 24, f: 22, g: 20, y: 20, p: 19, b: 15, v: 10, k: 8, j: 1.5, x: 1.5, q: 1, z: 0.7 };
  const KEYWORDS = ['http', 'https', 'powershell', 'cmd.exe', 'function', 'kernel32', 'iex', 'invoke',
    'downloadstring', 'wscript', 'cscript', 'shellcode', 'createobject', '.exe', '.dll', 'rundll32',
    'mshta', 'base64', 'system32', 'temp', 'appdata', 'admin', 'password', 'user', 'select ',
    'the ', 'and ', 'var ', 'def ', 'import ', 'return ', '<html', '<?php', '#!/'];

  function scoreBytes(bytes) {
    const n = bytes.length || 1;
    let printable = 0, ctrl = 0, nul = 0, letters = 0, spaces = 0;
    const lf = {};
    for (const b of bytes) {
      if (b === 0) nul++;
      if (b === 32) spaces++;
      if ((b >= 0x20 && b <= 0x7e) || b === 9 || b === 10 || b === 13) printable++;
      else ctrl++;
      if ((b >= 65 && b <= 90) || (b >= 97 && b <= 122)) {
        letters++;
        const c = String.fromCharCode(b | 0x20);
        lf[c] = (lf[c] || 0) + 1;
      }
    }
    let score = (printable / n) * 100;            // base: cuán imprimible es
    score -= (ctrl / n) * 90;                       // castigo fuerte a control
    score -= (nul / n) * 60;                         // castigo extra a NUL
    // banda de espacios típica de texto natural (~8–20%)
    const sr = spaces / n;
    if (sr >= 0.06 && sr <= 0.22) score += 12; else if (sr > 0) score += 3;
    // similitud con frecuencia inglesa (premia distribución natural de letras)
    if (letters > n * 0.4) {
      let chi = 0;
      for (const c in ENG) {
        const obs = (lf[c] || 0) / letters * 1000;
        const exp = ENG[c];
        chi += Math.abs(obs - exp);
      }
      score += Math.max(0, 25 - chi / 40);
    }
    // keywords de alto valor
    let kwHits = 0;
    if (printable / n > 0.6) {
      const txt = bytesToLatin(bytes).toLowerCase();
      for (const k of KEYWORDS) if (txt.indexOf(k) !== -1) kwHits++;
      score += kwHits * 8;
    }
    // un magic byte reconocible es señal fuerte de plaintext recuperado: domina
    // sobre la penalización por NULs (los headers PE/ELF traen ceros estructurales).
    const magic = detectMagic(bytes);
    if (magic) score += 80;
    return { score, printable: printable / n, magic, kwHits };
  }

  function bytesToLatin(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return s;
  }

  // ── XOR ──────────────────────────────────────────────────────
  function xorKey(bytes, key) {        // key: Uint8Array
    const out = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ key[i % key.length];
    return out;
  }
  // brute single-byte: 256 claves, devuelve top candidatos ordenados por score.
  function xorBruteSingle(bytes, top) {
    const res = [];
    for (let k = 0; k < 256; k++) {
      const dec = xorKey(bytes, Uint8Array.of(k));
      const sc = scoreBytes(dec);
      res.push({ key: k, score: sc.score, printable: sc.printable, magic: sc.magic, kwHits: sc.kwHits, bytes: dec });
    }
    // un magic byte reconocido en offset 0 es señal casi definitiva en un brute →
    // va primero; entre candidatos sin magic (o varios con magic), desempata el score.
    res.sort((a, b) => (b.magic ? 1 : 0) - (a.magic ? 1 : 0) || b.score - a.score);
    return res.slice(0, top || 8);
  }

  // distancia de Hamming entre dos buffers de igual largo
  function hamming(a, b) {
    let d = 0;
    for (let i = 0; i < a.length; i++) {
      let x = a[i] ^ b[i];
      while (x) { d += x & 1; x >>= 1; }
    }
    return d;
  }
  // Índice de Coincidencia de una columna (prob. de que dos bytes al azar sean iguales).
  function columnIC(col) {
    const n = col.length;
    if (n < 2) return 0;
    const f = new Array(256).fill(0);
    for (const b of col) f[b]++;
    let s = 0;
    for (const c of f) s += c * (c - 1);
    return s / (n * (n - 1));
  }
  // detección de largo de clave repetida vía Índice de Coincidencia por columnas.
  // El IC es INVARIANTE bajo XOR de byte fijo → al largo correcto (y sus múltiplos)
  // cada columna conserva el IC del idioma/plaintext (alto); a largos incorrectos las
  // columnas mezclan posiciones de clave y el IC tiende a uniforme (bajo). Más robusto
  // que Hamming en texto ASCII (banda estrecha de bytes). IC alto = largo más probable.
  function guessKeyLengths(bytes, maxLen) {
    maxLen = Math.min(maxLen || 40, Math.floor(bytes.length / 4));
    const res = [];
    for (let kl = 1; kl <= maxLen; kl++) {
      if (Math.floor(bytes.length / kl) < 2) continue;
      let icSum = 0, cols = 0;
      for (let c = 0; c < kl; c++) {
        const col = [];
        for (let i = c; i < bytes.length; i += kl) col.push(bytes[i]);
        const ic = columnIC(col);
        if (ic) { icSum += ic; cols++; }
      }
      if (cols) res.push({ keyLen: kl, ic: icSum / cols });
    }
    res.sort((a, b) => b.ic - a.ic);
    return res;
  }
  // recupera la clave repetida de largo dado: brute single-byte por columna.
  function recoverRepeatingKey(bytes, keyLen) {
    const key = new Uint8Array(keyLen);
    for (let col = 0; col < keyLen; col++) {
      const colBytes = [];
      for (let i = col; i < bytes.length; i += keyLen) colBytes.push(bytes[i]);
      const cb = Uint8Array.from(colBytes);
      let best = -Infinity, bestK = 0;
      for (let k = 0; k < 256; k++) {
        const sc = scoreBytes(xorKey(cb, Uint8Array.of(k)));
        if (sc.score > best) { best = sc.score; bestK = k; }
      }
      key[col] = bestK;
    }
    return key;
  }

  // ── RC4 ──────────────────────────────────────────────────────
  function rc4(bytes, key) {           // key: Uint8Array
    const S = new Uint8Array(256);
    for (let i = 0; i < 256; i++) S[i] = i;
    let j = 0;
    for (let i = 0; i < 256; i++) {
      j = (j + S[i] + key[i % key.length]) & 255;
      const t = S[i]; S[i] = S[j]; S[j] = t;
    }
    const out = new Uint8Array(bytes.length);
    let a = 0, b = 0;
    for (let n = 0; n < bytes.length; n++) {
      a = (a + 1) & 255;
      b = (b + S[a]) & 255;
      const t = S[a]; S[a] = S[b]; S[b] = t;
      out[n] = bytes[n] ^ S[(S[a] + S[b]) & 255];
    }
    return out;
  }

  // ── AES (Web Crypto) ─────────────────────────────────────────
  async function aes(bytes, keyBytes, ivBytes, mode, decrypt) {
    const map = { cbc: 'AES-CBC', ctr: 'AES-CTR', gcm: 'AES-GCM' };
    const algName = map[mode];
    if (!algName) throw new Error('modo AES no soportado');
    if (![16, 24, 32].includes(keyBytes.length)) throw new Error('clave AES debe ser 128/192/256 bits (16/24/32 bytes)');
    const ck = await crypto.subtle.importKey('raw', keyBytes, { name: algName }, false, [decrypt ? 'decrypt' : 'encrypt']);
    let params;
    if (mode === 'cbc') { if (ivBytes.length !== 16) throw new Error('IV de CBC debe ser 16 bytes'); params = { name: 'AES-CBC', iv: ivBytes }; }
    else if (mode === 'ctr') { if (ivBytes.length !== 16) throw new Error('counter/IV de CTR debe ser 16 bytes'); params = { name: 'AES-CTR', counter: ivBytes, length: 64 }; }
    else { if (ivBytes.length < 1) throw new Error('GCM requiere nonce/IV (típico 12 bytes)'); params = { name: 'AES-GCM', iv: ivBytes }; }
    const r = decrypt ? await crypto.subtle.decrypt(params, ck, bytes) : await crypto.subtle.encrypt(params, ck, bytes);
    return new Uint8Array(r);
  }

  const CORE = {
    parseBytes, looksHex, entropy, detectMagic, scoreBytes, bytesToLatin,
    xorKey, xorBruteSingle, hamming, guessKeyLengths, recoverRepeatingKey, rc4, aes,
  };

  // ── salida en hex/texto/base64 ───────────────────────────────
  function toHex(bytes) { let o = ''; for (let i = 0; i < bytes.length; i++) o += bytes[i].toString(16).padStart(2, '0'); return o; }
  function toB64(bytes) { let s = ''; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s); }
  function toPreview(bytes, max) {
    max = max || 4096;
    let s = '';
    const n = Math.min(bytes.length, max);
    for (let i = 0; i < n; i++) {
      const b = bytes[i];
      s += (b === 9 || b === 10 || b === 13 || (b >= 0x20 && b <= 0x7e)) ? String.fromCharCode(b) : '·';
    }
    if (bytes.length > max) s += '\n…(' + (bytes.length - max) + ' bytes más)';
    return s;
  }

  // ── UI ───────────────────────────────────────────────────────
  function render(container) {
    container.innerHTML =
      '<div class="sec-hdr"><div class="sec-title">🔐 Crypto / Payload Lab</div>' +
      '<span class="sec-cmds-badge">xor · rc4 · aes</span></div>' +
      '<div class="lab-intro">Destrabá payloads ofuscados: fuerza bruta XOR de 1 byte con scoring, ' +
      'detección de largo de clave repetida (Kasiski/Hamming), RC4 y AES (Web Crypto). ' +
      'Todo local — nada sale del navegador.</div>' +
      '<textarea class="cv-io" id="clIn" placeholder="Pegá el blob cifrado/ofuscado (hex, base64 o texto)…" spellcheck="false"></textarea>' +
      '<div class="cv-keyrow"><label>Formato de entrada:</label>' +
      '<select class="cv-key" id="clFmt" style="max-width:160px">' +
      '<option value="auto">auto</option><option value="hex">hex</option>' +
      '<option value="b64">base64</option><option value="text">texto crudo</option></select>' +
      '<span class="lab-dim" id="clStat" style="margin-left:10px"></span></div>' +
      '<div class="cv-ops">' +
      '<div class="cv-grp"><span class="cv-glbl">Modo</span>' +
      '<button class="cv-btn on" data-m="brute">XOR brute (1 byte)</button>' +
      '<button class="cv-btn" data-m="keylen">XOR clave repetida</button>' +
      '<button class="cv-btn" data-m="key">XOR / RC4 con clave</button>' +
      '<button class="cv-btn" data-m="aes">AES (Web Crypto)</button>' +
      '</div></div>' +
      '<div id="clPanel"></div>' +
      '<div id="clOut"></div>';

    const inEl = container.querySelector('#clIn');
    const fmtEl = container.querySelector('#clFmt');
    const statEl = container.querySelector('#clStat');
    const panel = container.querySelector('#clPanel');
    const outEl = container.querySelector('#clOut');
    let mode = 'brute';

    function getBytes() {
      const b = parseBytes(inEl.value, fmtEl.value);
      statEl.textContent = b.length + ' bytes · entropía ' + entropy(b).toFixed(2) + ' bits/byte' +
        (entropy(b) > 7.5 ? ' (alta → ¿cifrado/comprimido?)' : entropy(b) > 6 ? ' (media)' : ' (baja → ¿XOR/texto?)');
      return b;
    }

    function resultBox(bytes, title) {
      const magic = detectMagic(bytes);
      return '<div class="lab-panel"><div class="lab-panel-h">' + esc(title || 'Resultado') +
        (magic ? ' <span class="lab-tag">magic: ' + esc(magic) + '</span>' : '') +
        ' <span class="lab-dim">' + bytes.length + ' bytes</span></div>' +
        '<div class="lab-panel-b">' +
        '<div class="cv-outrow"><span class="lab-sub" style="margin:0">Texto</span>' +
        '<span class="lab-actions" style="margin:0">' +
        '<button class="rs-copy cl-cp" data-f="text">copy txt</button>' +
        '<button class="rs-copy cl-cp" data-f="hex">copy hex</button>' +
        '<button class="rs-copy cl-cp" data-f="b64">copy b64</button></span></div>' +
        '<pre class="lab-pre cl-prev">' + esc(toPreview(bytes)) + '</pre></div></div>';
    }
    function wireCopies(scope, bytes) {
      scope.querySelectorAll('.cl-cp').forEach(b => b.onclick = () => {
        const f = b.dataset.f;
        LAB.copy(f === 'hex' ? toHex(bytes) : f === 'b64' ? toB64(bytes) : bytesToLatin(bytes));
      });
    }

    function renderPanel() {
      if (mode === 'brute') {
        panel.innerHTML = '<div class="lab-note">Prueba las 256 claves de 1 byte y ordena por plausibilidad ' +
          '(imprimible + frecuencia de letras + keywords + magic bytes).</div>' +
          '<div class="lab-actions"><button class="cv-btn" id="clRun">Forzar XOR ▸</button></div>';
        panel.querySelector('#clRun').onclick = () => {
          try {
            const b = getBytes();
            if (!b.length) { outEl.innerHTML = '<div class="lab-err">Entrada vacía.</div>'; return; }
            const top = xorBruteSingle(b, 8);
            outEl.innerHTML = '<div class="lab-sub">Top candidatos</div>' +
              top.map(c =>
                '<div class="lab-panel"><div class="lab-panel-h">clave <code>0x' +
                c.key.toString(16).padStart(2, '0') + '</code> (' + (c.key >= 32 && c.key <= 126 ? "'" + esc(String.fromCharCode(c.key)) + "'" : 'no-print') + ')' +
                ' <span class="lab-dim">score ' + c.score.toFixed(0) + ' · ' + (c.printable * 100).toFixed(0) + '% print' +
                (c.kwHits ? ' · ' + c.kwHits + ' kw' : '') + '</span>' +
                (c.magic ? ' <span class="lab-tag">' + esc(c.magic) + '</span>' : '') +
                '</div><div class="lab-panel-b"><pre class="lab-pre">' + esc(toPreview(c.bytes, 600)) + '</pre>' +
                '<div class="lab-actions"><button class="rs-copy cl-pick" data-k="' + c.key + '">usar esta clave ▸</button></div>' +
                '</div></div>').join('');
            outEl.querySelectorAll('.cl-pick').forEach(btn => btn.onclick = () => {
              const dec = xorKey(b, Uint8Array.of(+btn.dataset.k));
              const box = document.createElement('div');
              box.innerHTML = resultBox(dec, 'XOR 0x' + (+btn.dataset.k).toString(16).padStart(2, '0'));
              outEl.prepend(box);
              wireCopies(box, dec);
              box.scrollIntoView({ block: 'nearest' });
            });
          } catch (e) { outEl.innerHTML = '<div class="lab-err">⚠ ' + esc(e.message) + '</div>'; }
        };
      } else if (mode === 'keylen') {
        panel.innerHTML = '<div class="lab-note">Estima el largo de la clave XOR repetida por Índice de Coincidencia ' +
          'por columnas (más alto = más probable; los múltiplos del largo real también puntúan alto). ' +
          'Luego recupera la clave forzando cada columna.</div>' +
          '<div class="cv-keyrow"><label>Largo máx:</label><input class="cv-key" id="clMax" value="32" style="max-width:90px"></div>' +
          '<div class="lab-actions"><button class="cv-btn" id="clRun">Analizar ▸</button></div>';
        panel.querySelector('#clRun').onclick = () => {
          try {
            const b = getBytes();
            if (b.length < 8) { outEl.innerHTML = '<div class="lab-err">Muy poco dato para analizar el largo de clave.</div>'; return; }
            const guesses = guessKeyLengths(b, parseInt(panel.querySelector('#clMax').value) || 32);
            const topLens = guesses.slice(0, 6);
            outEl.innerHTML = '<div class="lab-sub">Largos de clave probables</div>' +
              '<div class="lab-note">' + topLens.map(g => '<button class="rs-copy cl-kl" data-kl="' + g.keyLen + '">len ' + g.keyLen + ' (IC ' + g.ic.toFixed(3) + ')</button>').join(' ') + '</div>' +
              '<div id="clKlOut"></div>';
            const klOut = outEl.querySelector('#clKlOut');
            function doRecover(kl) {
              const key = recoverRepeatingKey(b, kl);
              const dec = xorKey(b, key);
              klOut.innerHTML = '<div class="lab-panel"><div class="lab-panel-h">clave len ' + kl +
                ' recuperada: <code>' + esc(toHex(key)) + '</code> ' +
                '<span class="lab-dim">(' + esc(printableKey(key)) + ')</span></div>' +
                '<div class="lab-panel-b"></div></div>';
              const box = document.createElement('div');
              box.innerHTML = resultBox(dec, 'XOR clave repetida');
              klOut.appendChild(box);
              wireCopies(box, dec);
            }
            outEl.querySelectorAll('.cl-kl').forEach(btn => btn.onclick = () => doRecover(+btn.dataset.kl));
            if (topLens.length) doRecover(topLens[0].keyLen);
          } catch (e) { outEl.innerHTML = '<div class="lab-err">⚠ ' + esc(e.message) + '</div>'; }
        };
      } else if (mode === 'key') {
        panel.innerHTML =
          '<div class="cv-keyrow"><label>Algoritmo:</label><select class="cv-key" id="clAlg" style="max-width:120px">' +
          '<option value="xor">XOR</option><option value="rc4">RC4</option></select></div>' +
          '<div class="cv-keyrow"><label>Clave:</label><input class="cv-key" id="clKey" placeholder="texto, o hex con prefijo 0x / \\x"></div>' +
          '<div class="cv-keyrow"><label>Clave en:</label><select class="cv-key" id="clKeyFmt" style="max-width:120px">' +
          '<option value="text">texto</option><option value="hex">hex</option></select></div>' +
          '<div class="lab-actions"><button class="cv-btn" id="clRun">Aplicar ▸</button></div>';
        panel.querySelector('#clRun').onclick = () => {
          try {
            const b = getBytes();
            const kRaw = panel.querySelector('#clKey').value;
            const key = panel.querySelector('#clKeyFmt').value === 'hex' ? parseBytes(kRaw, 'hex') : new TextEncoder().encode(kRaw);
            if (!key.length) { outEl.innerHTML = '<div class="lab-err">Definí una clave.</div>'; return; }
            const alg = panel.querySelector('#clAlg').value;
            const dec = alg === 'rc4' ? rc4(b, key) : xorKey(b, key);
            outEl.innerHTML = '';
            const box = document.createElement('div');
            box.innerHTML = resultBox(dec, alg.toUpperCase() + ' con clave (' + key.length + ' B)');
            outEl.appendChild(box);
            wireCopies(box, dec);
          } catch (e) { outEl.innerHTML = '<div class="lab-err">⚠ ' + esc(e.message) + '</div>'; }
        };
      } else if (mode === 'aes') {
        panel.innerHTML =
          '<div class="cv-keyrow"><label>Modo:</label><select class="cv-key" id="clMode" style="max-width:120px">' +
          '<option value="cbc">CBC</option><option value="ctr">CTR</option><option value="gcm">GCM</option></select>' +
          '<label style="margin-left:14px">Operación:</label><select class="cv-key" id="clDir" style="max-width:130px">' +
          '<option value="dec">descifrar</option><option value="enc">cifrar</option></select></div>' +
          '<div class="cv-keyrow"><label>Clave (hex):</label><input class="cv-key" id="clKey" placeholder="32/48/64 hex = 128/192/256 bits"></div>' +
          '<div class="cv-keyrow"><label>IV / nonce (hex):</label><input class="cv-key" id="clIv" placeholder="CBC/CTR=16B · GCM=12B"></div>' +
          '<div class="lab-note">GCM espera el tag (16 B) anexado al final del ciphertext, como produce la mayoría de las libs.</div>' +
          '<div class="lab-actions"><button class="cv-btn" id="clRun">Ejecutar ▸</button></div>';
        panel.querySelector('#clRun').onclick = async () => {
          try {
            const b = getBytes();
            const key = parseBytes(panel.querySelector('#clKey').value, 'hex');
            const iv = parseBytes(panel.querySelector('#clIv').value, 'hex');
            const m = panel.querySelector('#clMode').value;
            const dec = panel.querySelector('#clDir').value === 'dec';
            outEl.innerHTML = '<div class="lab-dim">procesando…</div>';
            const r = await aes(b, key, iv, m, dec);
            outEl.innerHTML = '';
            const box = document.createElement('div');
            box.innerHTML = resultBox(r, 'AES-' + m.toUpperCase() + (dec ? ' descifrado' : ' cifrado'));
            outEl.appendChild(box);
            wireCopies(box, r);
          } catch (e) {
            outEl.innerHTML = '<div class="lab-err">⚠ ' + esc(e.message || e) +
              '<br><span class="lab-dim">En descifrado, un error suele ser clave/IV/modo incorrectos (o tag GCM inválido).</span></div>';
          }
        };
      }
      outEl.innerHTML = '';
    }
    function printableKey(key) {
      let s = '';
      for (const b of key) s += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '·';
      return s;
    }

    container.querySelectorAll('.cv-btn[data-m]').forEach(b => b.onclick = () => {
      container.querySelectorAll('.cv-btn[data-m]').forEach(x => x.classList.remove('on'));
      b.classList.add('on');
      mode = b.dataset.m;
      renderPanel();
    });
    inEl.addEventListener('input', () => { try { getBytes(); } catch (e) { statEl.textContent = ''; } });
    renderPanel();
  }

  if (typeof window !== 'undefined' && window.LAB) {
    LAB.registerTool({ id: 'cryptolab', label: 'Crypto / Payload Lab', icon: '🔐', group: '🧪 LAB / TOOLS', render });
  }
  if (typeof window !== 'undefined') window.__CRYPTOLAB_CORE = CORE;
  return CORE;
})();
