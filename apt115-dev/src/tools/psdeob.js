// APT115 CODEX ARCANUM — PowerShell deob/obf
// quod est superius est sicut quod inferius
//
// Desarma las capas de ofuscación más comunes de PowerShell para leer el
// comando real: `-EncodedCommand`/base64 (UTF-16LE), `[char]NN`, concatenación
// de strings, operador de formato `-f`, y backticks de evasión. Aparte,
// descomprime blobs gzip/deflate en base64 (DecompressionStream). Lado generador:
// produce un `-enc` base64 desde un comando. Todo local, NADA se ejecuta.
//
// Pensado para cruzar con el analyzer `maldoc` (expone `window.apt115Deob`).

export const psdeob = (function () {
  'use strict';

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // ── base64 / encodings ────────────────────────────────────────────────
  function b64bytes(b64) {
    const bin = atob(String(b64).replace(/\s+/g, ''));
    const u = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u;
  }
  function utf16le(bytes) {
    let s = '';
    for (let i = 0; i + 1 < bytes.length; i += 2) s += String.fromCharCode(bytes[i] | (bytes[i + 1] << 8));
    return s;
  }
  function decodeEnc(b64) { return utf16le(b64bytes(b64)); }

  /** -EncodedCommand de PowerShell: base64 de UTF-16LE. @param {string} cmd */
  function obfuscateEnc(cmd) {
    let bin = '';
    for (const ch of String(cmd)) { const n = ch.charCodeAt(0); bin += String.fromCharCode(n & 0xff, (n >> 8) & 0xff); }
    return btoa(bin);
  }

  function printableRatio(s) {
    if (!s) return 0;
    let p = 0;
    for (let i = 0; i < s.length; i++) { const n = s.charCodeAt(i); if (n === 9 || n === 10 || n === 13 || (n >= 32 && n < 127)) p++; }
    return p / s.length;
  }
  function looksLikeBareB64(s) {
    const t = s.trim();
    return /^[A-Za-z0-9+/=\s]+$/.test(t) && t.replace(/\s/g, '').length >= 24 && t.replace(/\s/g, '').length % 4 === 0;
  }
  function findEncoded(s) {
    const m = /-e(?:c|nc|ncodedcommand)?\s+["']?([A-Za-z0-9+/=]{20,})["']?/i.exec(s);
    return m ? decodeEnc(m[1]) : null;
  }

  // ── transforms sincrónicos ────────────────────────────────────────────
  /** Convierte escapes conocidos y quita los backticks de evasión. */
  function stripBackticks(s) {
    return s.replace(/`n/g, '\n').replace(/`t/g, '\t').replace(/`r/g, '\r').replace(/`0/g, '\0').replace(/`/g, '');
  }
  /** Colapsa concatenaciones de literales: 'a'+'b' → 'ab', "a"+"b" → "ab". */
  function joinConcat(s) {
    let prev;
    do {
      prev = s;
      s = s.replace(/'([^']*)'\s*\+\s*'([^']*)'/g, (m, a, b) => "'" + a + b + "'");
      s = s.replace(/"([^"]*)"\s*\+\s*"([^"]*)"/g, (m, a, b) => '"' + a + b + '"');
    } while (s !== prev);
    return s;
  }
  /** [char]105 / [char]0x69 → 'i' (luego joinConcat los une). */
  function charCodes(s) {
    return s.replace(/\[char\]\s*(0x[0-9a-f]+|\d+)/gi, (m, n) => {
      const code = parseInt(n);
      return (code >= 0 && code <= 0x10ffff) ? "'" + String.fromCharCode(code) + "'" : m;
    });
  }
  /** "{0}{1}" -f 'a','b' → "ab". */
  function formatOperator(s) {
    return s.replace(/(['"])((?:\{\d+\}|[^'"])*)\1\s*-f\s*((?:\s*(?:'[^']*'|"[^"]*")\s*,?)+)/gi, (m, q, fmt, args) => {
      const list = [...args.matchAll(/'([^']*)'|"([^"]*)"/g)].map(x => x[1] !== undefined ? x[1] : x[2]);
      if (!/\{\d+\}/.test(fmt)) return m;
      const out = fmt.replace(/\{(\d+)\}/g, (mm, i) => list[+i] !== undefined ? list[+i] : mm);
      return q + out + q;
    });
  }

  /**
   * Deofusca capas comunes hasta punto fijo. Síncrono (la descompresión gzip va
   * aparte en decompressB64). @param {string} input @returns {{ok:boolean, layers:string[], output:string}}
   */
  function deobfuscate(input) {
    let text = String(input == null ? '' : input);
    const layers = [];

    const enc = findEncoded(text);
    if (enc && printableRatio(enc) > 0.7) { layers.push('-EncodedCommand → UTF-16LE'); text = enc; }
    else if (looksLikeBareB64(text)) {
      const t16 = decodeEnc(text);
      if (printableRatio(t16) > 0.85) { layers.push('base64 → UTF-16LE'); text = t16; }
      else { const t8 = new TextDecoder().decode(b64bytes(text)); if (printableRatio(t8) > 0.85) { layers.push('base64 → UTF-8'); text = t8; } }
    }

    for (let i = 0; i < 25; i++) {
      const before = text;
      let step = charCodes(text);
      if (step !== text && !layers.includes('[char] → literal')) layers.push('[char] → literal');
      text = step;
      step = formatOperator(text);
      if (step !== text && !layers.includes('operador -f')) layers.push('operador -f');
      text = step;
      step = stripBackticks(text);
      if (step !== text && !layers.includes('backticks')) layers.push('backticks');
      text = step;
      step = joinConcat(text);
      if (step !== text && !layers.includes('concatenación')) layers.push('concatenación');
      text = step;
      if (text === before) break;
    }
    return { ok: true, layers, output: text };
  }

  // ── descompresión (async) ─────────────────────────────────────────────
  async function inflate(bytes, fmt) {
    const ds = new DecompressionStream(fmt);
    const w = ds.writable.getWriter();
    // El writer rechaza si el formato no matchea; lo silenciamos para que no
    // quede como unhandled rejection — el error real sale al leer el readable.
    (async () => { await w.write(/** @type {BufferSource} */(bytes)); await w.close(); })().catch(() => {});
    const ab = await new Response(ds.readable).arrayBuffer();
    return new Uint8Array(ab);
  }
  /** Descomprime un blob base64 (gzip / zlib / deflate-raw). @param {string} b64 */
  async function decompressB64(b64) {
    let bytes;
    try { bytes = b64bytes(b64); } catch (e) { return { ok: false, error: 'base64 inválido.' }; }
    const order = (bytes[0] === 0x1f && bytes[1] === 0x8b) ? ['gzip'] : ['deflate', 'deflate-raw', 'gzip'];
    for (const fmt of order) {
      try { return { ok: true, format: fmt, text: new TextDecoder().decode(await inflate(bytes, fmt)) }; }
      catch (e) { /* probar el siguiente */ }
    }
    return { ok: false, error: 'No se pudo descomprimir (probé gzip/zlib/deflate).' };
  }

  // ── Render ────────────────────────────────────────────────────────────
  let lastOut = '';

  function render(container) {
    container.innerHTML =
      '<div class="lab-sec">' +
      '<div class="lab-intro"><b>PowerShell deob / obf.</b> Pegá un one-liner ofuscado y desarmo las capas ' +
      '(<code>-enc</code>/base64, <code>[char]</code>, concatenación, <code>-f</code>, backticks). También ' +
      'descomprimo blobs gzip/deflate en base64. Nada se ejecuta — es lectura estática.</div>' +
      '<textarea id="psIn" class="cv-io" spellcheck="false" style="min-height:120px" ' +
      'placeholder="powershell -enc SQBFAFgA…   ó   I`E`X (&#39;i&#39;+&#39;ex&#39;)  ([char]105+[char]101+[char]120)"></textarea>' +
      '<div class="x5-actions"><button id="psGo" class="cv-btn">Deofuscar</button>' +
      '<button id="psGz" class="cv-btn">Descomprimir gzip/b64</button>' +
      '<button id="psCopy" class="cv-btn">copiar</button></div>' +
      '<div id="psLayers"></div>' +
      '<textarea id="psOut" class="cv-io out" readonly spellcheck="false" style="min-height:120px"></textarea>' +
      '<div class="lab-panel collapsed"><div class="lab-panel-h" onclick="this.parentElement.classList.toggle(\'collapsed\')">' +
      '<span>🛠 Generar -EncodedCommand</span><span class="lab-panel-x">▾</span></div><div class="lab-panel-b">' +
      '<div class="cp-row"><input id="psGenIn" class="cv-key" placeholder="comando, ej: whoami" spellcheck="false">' +
      '<button id="psGen" class="cv-btn">→ -enc</button></div><div id="psGenOut"></div></div></div>' +
      '</div>';

    const inEl = container.querySelector('#psIn');
    const outEl = container.querySelector('#psOut');
    const layersEl = container.querySelector('#psLayers');
    const showLayers = (layers) => {
      layersEl.innerHTML = layers && layers.length
        ? '<div class="lab-note">Capas: ' + layers.map(l => '<span class="x5-tag">' + esc(l) + '</span>').join(' ') + '</div>'
        : '<div class="lab-note">Sin capas reconocidas (texto ya plano).</div>';
    };
    container.querySelector('#psGo').onclick = () => {
      const r = deobfuscate(inEl.value);
      lastOut = r.output; outEl.value = r.output; showLayers(r.layers);
    };
    container.querySelector('#psGz').onclick = async () => {
      const raw = inEl.value.trim();
      const m = /([A-Za-z0-9+/=]{20,})/.exec(raw);
      if (!m) { layersEl.innerHTML = '<div class="lab-note">No encontré un blob base64.</div>'; return; }
      const r = await decompressB64(m[1]);
      if (!r.ok) { layersEl.innerHTML = '<div class="lab-note">' + esc(r.error) + '</div>'; return; }
      lastOut = r.text; outEl.value = r.text;
      layersEl.innerHTML = '<div class="lab-note">Descomprimido (' + esc(r.format) + ').</div>';
    };
    container.querySelector('#psCopy').onclick = () => { if (window.LAB) window.LAB.copy(lastOut); };
    container.querySelector('#psGen').onclick = () => {
      const b64 = obfuscateEnc(container.querySelector('#psGenIn').value);
      container.querySelector('#psGenOut').innerHTML =
        '<table class="lab-kv mono"><tbody><tr><th>-enc</th><td><code>' + esc(b64) + '</code></td></tr>' +
        '<tr><th>completo</th><td><code>powershell -enc ' + esc(b64) + '</code></td></tr></tbody></table>';
    };

    // Puente desde maldoc: recibir PowerShell extraído y deofuscarlo.
    window.apt115Deob = (text) => { inEl.value = String(text || ''); const r = deobfuscate(inEl.value); lastOut = r.output; outEl.value = r.output; showLayers(r.layers); };
  }

  if (typeof window !== 'undefined' && window.LAB) {
    window.LAB.registerTool({ id: 'psdeob', label: 'PowerShell deob', icon: '⚡', group: '🧪 LAB / TOOLS', render });
  }
  return { decodeEnc, obfuscateEnc, stripBackticks, joinConcat, charCodes, formatOperator, deobfuscate, decompressB64 };
})();
