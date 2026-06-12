// APT115 CODEX ARCANUM — Stego Lab (crear esteganografía)
// solve et coagula
//
// Contraparte del analyzer `steg` del triage: EMBEBE y EXTRAE payloads en imágenes.
// Herramienta personal para investigación blue/red en entorno controlado. Tres modos:
//
//   · LSB       — escribe el payload en el bit menos significativo de R/G/B (salida PNG,
//                 sin pérdida). El detector lo levanta con su chi² + stream LSB.
//   · Append    — pega el payload tras el EOF del contenedor (salida = formato original).
//   · Metadata  — guarda el payload en un chunk de texto PNG (tEXt, keyword "A115").
//
// CIFRADO OPCIONAL: con passphrase, el payload se cifra con AES-GCM 256 (clave derivada
// por PBKDF2-SHA256, 200k iters) ANTES de embeber. El blob lleva salt+iv. Sin passphrase
// va en claro. Arquitectura abierta a esquemas avanzados (F5/matrix encoding) a futuro.
//
// 100% local: Canvas + Web Crypto, nada de red. Núcleo (pack/LSB/crc32) verificable en Node.

export const stego = (function () {
  'use strict';

  // ── Núcleo (puro, sin DOM — testeable en Node) ──────────────────────────────
  const MAGIC = [0x41, 0x31, 0x31, 0x35]; // "A115"
  const HDR = 9;                           // magic(4)+flags(1)+len(4)

  // Envuelve el cuerpo con cabecera reconocible. enc=1 ⇒ el cuerpo es salt+iv+ct.
  function pack(body, enc) {
    const out = new Uint8Array(HDR + body.length);
    out[0] = MAGIC[0]; out[1] = MAGIC[1]; out[2] = MAGIC[2]; out[3] = MAGIC[3];
    out[4] = enc ? 1 : 0;
    out[5] = (body.length >>> 24) & 255; out[6] = (body.length >>> 16) & 255;
    out[7] = (body.length >>> 8) & 255; out[8] = body.length & 255;
    out.set(body, HDR);
    return out;
  }
  function isMagic(b, o) { o = o || 0; return b[o] === MAGIC[0] && b[o + 1] === MAGIC[1] && b[o + 2] === MAGIC[2] && b[o + 3] === MAGIC[3]; }
  // Parsea un blob empaquetado a partir de `o`. Devuelve {enc, body} o null.
  function unpack(b, o) {
    o = o || 0;
    if (b.length < o + HDR || !isMagic(b, o)) return null;
    const enc = b[o + 4] & 1;
    const len = (b[o + 5] << 24 | b[o + 6] << 16 | b[o + 7] << 8 | b[o + 8]) >>> 0;
    if (o + HDR + len > b.length) return null;
    return { enc: !!enc, body: b.subarray(o + HDR, o + HDR + len) };
  }
  function scanMagic(b) { for (let i = 0; i + HDR <= b.length; i++) if (isMagic(b, i)) { const u = unpack(b, i); if (u) return u; } return null; }

  // LSB: bit i → píxel (i/3), canal (i%3). Capacidad = floor(N*3/8) bytes.
  function chIdx(bi) { return ((bi / 3) | 0) * 4 + (bi % 3); }
  function lsbCapacity(N) { return (N * 3) >> 3; }
  function embedLSB(data, N, blob) {
    const cap = lsbCapacity(N);
    if (blob.length > cap) throw new Error('el payload (' + blob.length + ' B) excede la capacidad LSB (' + cap + ' B)');
    const bits = blob.length * 8;
    for (let bi = 0; bi < bits; bi++) {
      const bit = (blob[bi >> 3] >> (7 - (bi & 7))) & 1;
      const idx = chIdx(bi);
      data[idx] = (data[idx] & 0xFE) | bit;
    }
  }
  function extractLSB(data, N) {
    const cap = lsbCapacity(N);
    if (cap < HDR) return { found: false };
    let bp = 0;
    const rd = (count) => {
      const o = new Uint8Array(count);
      for (let k = 0; k < count; k++) { let v = 0; for (let j = 0; j < 8; j++) { v = (v << 1) | (data[chIdx(bp)] & 1); bp++; } o[k] = v; }
      return o;
    };
    const h = rd(HDR);
    if (!isMagic(h, 0)) return { found: false };
    const enc = h[4] & 1;
    const len = (h[5] << 24 | h[6] << 16 | h[7] << 8 | h[8]) >>> 0;
    if (HDR + len > cap) return { found: true, error: 'longitud declarada (' + len + ' B) excede la capacidad' };
    return { found: true, enc: !!enc, body: rd(len) };
  }

  // CRC-32 (PNG) para insertar chunks tEXt válidos.
  const CRCT = (function () {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); t[n] = c >>> 0; }
    return t;
  })();
  function crc32(b, start, end) {
    start = start || 0; end = (end == null) ? b.length : end;
    let c = 0xFFFFFFFF;
    for (let i = start; i < end; i++) c = CRCT[(c ^ b[i]) & 0xFF] ^ (c >>> 8);
    return (c ^ 0xFFFFFFFF) >>> 0;
  }
  // Inserta un chunk tEXt (keyword\0text) justo antes del IEND.
  function insertPngText(png, keyword, text) {
    let p = 8, iend = -1;
    while (p + 8 <= png.length) {
      const len = (png[p] << 24 | png[p + 1] << 16 | png[p + 2] << 8 | png[p + 3]) >>> 0;
      const type = String.fromCharCode(png[p + 4], png[p + 5], png[p + 6], png[p + 7]);
      if (type === 'IEND') { iend = p; break; }
      p = p + 12 + len;
    }
    if (iend < 0) throw new Error('PNG sin IEND — ¿no es un PNG válido?');
    const kw = strBytes(keyword), tx = strBytes(text);
    const dlen = kw.length + 1 + tx.length;
    const chunk = new Uint8Array(12 + dlen);
    chunk[0] = (dlen >>> 24) & 255; chunk[1] = (dlen >>> 16) & 255; chunk[2] = (dlen >>> 8) & 255; chunk[3] = dlen & 255;
    chunk[4] = 0x74; chunk[5] = 0x45; chunk[6] = 0x58; chunk[7] = 0x74; // tEXt
    let q = 8; kw.forEach(x => chunk[q++] = x); chunk[q++] = 0; tx.forEach(x => chunk[q++] = x);
    const crc = crc32(chunk, 4, 8 + dlen);
    chunk[8 + dlen] = (crc >>> 24) & 255; chunk[9 + dlen] = (crc >>> 16) & 255; chunk[10 + dlen] = (crc >>> 8) & 255; chunk[11 + dlen] = crc & 255;
    const out = new Uint8Array(png.length + chunk.length);
    out.set(png.subarray(0, iend), 0); out.set(chunk, iend); out.set(png.subarray(iend), iend + chunk.length);
    return out;
  }
  function findPngText(png, keyword) {
    let p = 8;
    while (p + 8 <= png.length) {
      const len = (png[p] << 24 | png[p + 1] << 16 | png[p + 2] << 8 | png[p + 3]) >>> 0;
      const type = String.fromCharCode(png[p + 4], png[p + 5], png[p + 6], png[p + 7]);
      if (type === 'tEXt') {
        let s = p + 8; const e = s + len; let kw = '';
        while (s < e && png[s] !== 0) kw += String.fromCharCode(png[s++]);
        if (kw === keyword) { let t = ''; for (let i = s + 1; i < e; i++) t += String.fromCharCode(png[i]); return t; }
      }
      if (type === 'IEND') break;
      p = p + 12 + len;
    }
    return null;
  }

  function strBytes(s) { const a = []; for (let i = 0; i < s.length; i++) a.push(s.charCodeAt(i) & 0xff); return a; }
  function b64enc(bytes) { let s = ''; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s); }
  function b64dec(str) { const s = atob(str); const o = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) o[i] = s.charCodeAt(i); return o; }

  // ── Cripto: AES-GCM con clave derivada por PBKDF2 (Web Crypto / Node webcrypto) ──
  async function deriveKey(pass, salt) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function encryptPayload(bytes, pass) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(pass, salt);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));
    const blob = new Uint8Array(16 + 12 + ct.length);
    blob.set(salt, 0); blob.set(iv, 16); blob.set(ct, 28);
    return blob;
  }
  async function decryptPayload(blob, pass) {
    if (blob.length < 28) throw new Error('blob cifrado demasiado corto');
    const salt = blob.subarray(0, 16), iv = blob.subarray(16, 28), ct = blob.subarray(28);
    const key = await deriveKey(pass, salt);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
  }

  // Construye el cuerpo a embeber: cifra si hay passphrase. Devuelve {body, enc}.
  async function buildBody(payload, pass) {
    if (pass) return { body: await encryptPayload(payload, pass), enc: 1 };
    return { body: payload, enc: 0 };
  }
  async function recoverPayload(u, pass) {
    if (!u.enc) return u.body;
    if (!pass) throw new Error('el payload está cifrado — hace falta la passphrase');
    return decryptPayload(u.body, pass);
  }

  // ── Browser-only: decode/encode de imagen vía Canvas ────────────────────────
  async function toImageData(bytes) {
    const bmp = await createImageBitmap(new Blob([bytes]));
    const cv = document.createElement('canvas');
    cv.width = bmp.width; cv.height = bmp.height;
    const cx = cv.getContext('2d', { willReadFrequently: true });
    cx.drawImage(bmp, 0, 0); bmp.close && bmp.close();
    return { id: cx.getImageData(0, 0, cv.width, cv.height), canvas: cv, ctx: cx };
  }
  function canvasToPngBytes(canvas) {
    return new Promise((res, rej) => canvas.toBlob(b => {
      if (!b) return rej(new Error('toBlob falló'));
      b.arrayBuffer().then(ab => res(new Uint8Array(ab)));
    }, 'image/png'));
  }

  // ── Estado de UI ────────────────────────────────────────────────────────────
  function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
  function fmtB(n) { return n < 1024 ? n + ' B' : (n / 1024).toFixed(1) + ' KB'; }

  let carrier = null;     // { bytes, name, ext } imagen portadora (embeber)
  let payloadFile = null; // Uint8Array opcional (archivo como payload)
  let stImg = null;       // { bytes, name } imagen a extraer (extraer)
  let lastOut = null;     // { bytes, name, url }

  function render(container) {
    container.innerHTML =
      '<div class="sec-hdr"><div class="sec-title">🖼 Stego Lab</div>' +
      '<span class="sec-cmds-badge">embeber · extraer</span></div>' +
      '<div class="lab-intro">Esconde y recupera payloads en imágenes — <b>LSB</b>, <b>append</b> ' +
      'tras el EOF o <b>metadata</b> PNG, con <b>cifrado AES-GCM opcional</b> (passphrase). ' +
      'Contraparte del analyzer de esteganografía. 100% local — Canvas + Web Crypto, nada sale del navegador.</div>' +
      '<div class="ds-bar st-tabs">' +
        '<button class="cv-btn st-tab" data-tab="enc" style="border-color:var(--accent)">▸ Embeber</button>' +
        '<button class="cv-btn st-tab" data-tab="dec">◂ Extraer</button>' +
      '</div>' +
      '<div class="st-pane st-enc"></div>' +
      '<div class="st-pane st-dec" style="display:none"></div>';

    renderEnc(container.querySelector('.st-enc'));
    renderDec(container.querySelector('.st-dec'));

    container.querySelectorAll('.st-tab').forEach(b => {
      b.onclick = () => {
        container.querySelectorAll('.st-tab').forEach(x => x.style.borderColor = '');
        b.style.borderColor = 'var(--accent)';
        const enc = b.dataset.tab === 'enc';
        container.querySelector('.st-enc').style.display = enc ? '' : 'none';
        container.querySelector('.st-dec').style.display = enc ? 'none' : '';
      };
    });
  }

  function modeBar(sel) {
    return '<div class="ds-bar st-modes">' +
      ['lsb', 'append', 'meta'].map(m => '<button class="cv-btn st-mode" data-mode="' + m + '"' +
        (m === sel ? ' style="border-color:var(--accent)"' : '') + '>' +
        (m === 'lsb' ? 'LSB' : m === 'append' ? 'Append (EOF)' : 'Metadata (PNG)') + '</button>').join('') +
      '</div>';
  }
  function wireModes(pane, state) {
    pane.querySelectorAll('.st-mode').forEach(b => {
      b.onclick = () => {
        pane.querySelectorAll('.st-mode').forEach(x => x.style.borderColor = '');
        b.style.borderColor = 'var(--accent)'; state.mode = b.dataset.mode;
      };
    });
  }

  // ── EMBEBER ─────────────────────────────────────────────────────────────────
  function renderEnc(pane) {
    const st = { mode: 'lsb' };
    pane.innerHTML =
      '<div class="lab-drop" id="stCarrier" tabindex="0"><div class="lab-drop-ic">⬡</div>' +
      '<div class="lab-drop-t">Portadora: arrastrá una imagen (PNG/JPEG/GIF/BMP/WEBP)</div>' +
      '<div class="lab-drop-s st-carrier-info">la salida LSB/Metadata siempre se re-codifica a PNG (sin pérdida)</div></div>' +
      '<input type="file" id="stCarrierF" accept="image/*" style="display:none">' +
      '<div class="lab-sub">Payload</div>' +
      '<textarea class="cv-io" id="stPayload" style="min-height:80px" placeholder="Texto a esconder… (o subí un archivo abajo)" spellcheck="false"></textarea>' +
      '<div class="cv-keyrow"><label>o archivo:</label><input type="file" id="stPayloadF"><span class="lab-dim st-pf-info"></span></div>' +
      '<div class="lab-sub">Modo</div>' + modeBar('lsb') +
      '<div class="cv-keyrow"><label>passphrase (opcional):</label><input class="cv-key" id="stPass" placeholder="vacío = sin cifrar" spellcheck="false"></div>' +
      '<div class="ds-bar"><button class="yr-run" id="stGen">▶ Generar</button>' +
      '<span class="yr-status lab-dim st-status"></span></div>' +
      '<div class="st-out"></div>';

    wireDrop(pane.querySelector('#stCarrier'), pane.querySelector('#stCarrierF'), async (bytes, name) => {
      carrier = { bytes, name, ext: extOf(name, bytes) };
      const cap = await capacityNote(bytes);
      pane.querySelector('.st-carrier-info').innerHTML = esc(name) + ' · ' + fmtB(bytes.length) + cap;
    });
    pane.querySelector('#stPayloadF').onchange = (e) => {
      const f = e.target.files[0]; if (!f) { payloadFile = null; return; }
      f.arrayBuffer().then(ab => { payloadFile = new Uint8Array(ab); pane.querySelector('.st-pf-info').textContent = '✓ ' + f.name + ' (' + fmtB(payloadFile.length) + ') — tiene prioridad sobre el texto'; });
    };
    wireModes(pane, st);
    pane.querySelector('#stGen').onclick = () => generate(pane, st);
  }

  async function capacityNote(bytes) {
    try { const { id } = await toImageData(bytes); return ' · capacidad LSB ≈ ' + fmtB(lsbCapacity(id.width * id.height) - HDR); }
    catch (e) { return ''; }
  }

  async function generate(pane, st) {
    const status = pane.querySelector('.st-status');
    const out = pane.querySelector('.st-out');
    out.innerHTML = ''; status.textContent = '';
    if (!carrier) { out.innerHTML = '<div class="lab-err">Falta la imagen portadora.</div>'; return; }
    const pass = pane.querySelector('#stPass').value || '';
    const txt = pane.querySelector('#stPayload').value || '';
    const payload = payloadFile || new TextEncoder().encode(txt);
    if (!payload.length) { out.innerHTML = '<div class="lab-err">El payload está vacío.</div>'; return; }

    status.textContent = 'procesando…';
    try {
      const { body, enc } = await buildBody(payload, pass);
      const blob = pack(body, enc);
      let outBytes, outName, note;

      if (st.mode === 'lsb') {
        const { id, canvas, ctx } = await toImageData(carrier.bytes);
        embedLSB(id.data, id.width * id.height, blob);
        ctx.putImageData(id, 0, 0);
        outBytes = await canvasToPngBytes(canvas);
        outName = baseName(carrier.name) + '.stego.png';
        note = 'LSB en ' + id.width + '×' + id.height + ' · usado ' + fmtB(blob.length) + ' de ' + fmtB(lsbCapacity(id.width * id.height)) + ' (PNG sin pérdida)';
      } else if (st.mode === 'append') {
        outBytes = new Uint8Array(carrier.bytes.length + blob.length);
        outBytes.set(carrier.bytes, 0); outBytes.set(blob, carrier.bytes.length);
        outName = baseName(carrier.name) + '.stego.' + (carrier.ext || 'bin');
        note = 'payload apendizado tras el EOF (' + fmtB(blob.length) + ') — formato original preservado';
      } else { // meta
        if (carrier.ext !== 'png') { out.innerHTML = '<div class="lab-err">El modo Metadata requiere un PNG como portadora.</div>'; status.textContent = ''; return; }
        outBytes = insertPngText(carrier.bytes, 'A115', b64enc(blob));
        outName = baseName(carrier.name) + '.stego.png';
        note = 'payload en chunk tEXt "A115" (base64' + (enc ? ', cifrado' : '') + ')';
      }

      if (lastOut && lastOut.url) URL.revokeObjectURL(lastOut.url);
      const url = URL.createObjectURL(new Blob([outBytes], { type: st.mode === 'append' && carrier.ext !== 'png' ? 'application/octet-stream' : 'image/png' }));
      lastOut = { bytes: outBytes, name: outName, url };
      status.textContent = '';
      out.innerHTML =
        '<div class="lab-note">✓ Generado · ' + esc(note) + (enc ? ' · <b>AES-GCM</b>' : '') + '</div>' +
        '<div class="lab-row1"><a class="lab-ext" href="' + url + '" download="' + esc(outName) + '">↓ Descargar ' + esc(outName) + '</a> ' +
        '<span class="lab-dim">' + fmtB(outBytes.length) + '</span></div>' +
        (st.mode !== 'append' ? '<img src="' + url + '" style="max-width:220px;margin-top:8px;border:1px solid var(--border-color);image-rendering:auto">' : '');
    } catch (e) {
      console.error('[stego] generate', e);
      status.textContent = '';
      out.innerHTML = '<div class="lab-err">' + esc(e && e.message || e) + '</div>';
    }
  }

  // ── EXTRAER ─────────────────────────────────────────────────────────────────
  function renderDec(pane) {
    const st = { mode: 'lsb' };
    pane.innerHTML =
      '<div class="lab-drop" id="stDecDrop" tabindex="0"><div class="lab-drop-ic">⬡</div>' +
      '<div class="lab-drop-t">Imagen a inspeccionar (la generada acá u otra)</div>' +
      '<div class="lab-drop-s st-dec-info">extrae el payload con el formato de cabecera "A115"</div></div>' +
      '<input type="file" id="stDecF" accept="image/*" style="display:none">' +
      '<div class="lab-sub">Modo</div>' + modeBar('lsb') +
      '<div class="cv-keyrow"><label>passphrase (si cifrado):</label><input class="cv-key" id="stDecPass" placeholder="vacío = sin cifrar" spellcheck="false"></div>' +
      '<div class="ds-bar"><button class="yr-run" id="stExtract">▶ Extraer</button>' +
      '<span class="yr-status lab-dim st-dec-status"></span></div>' +
      '<div class="st-dec-out"></div>';

    wireDrop(pane.querySelector('#stDecDrop'), pane.querySelector('#stDecF'), (bytes, name) => {
      stImg = { bytes, name };
      pane.querySelector('.st-dec-info').textContent = name + ' · ' + fmtB(bytes.length);
    });
    wireModes(pane, st);
    pane.querySelector('#stExtract').onclick = () => extract(pane, st);
  }

  async function extract(pane, st) {
    const status = pane.querySelector('.st-dec-status');
    const out = pane.querySelector('.st-dec-out');
    out.innerHTML = '';
    if (!stImg) { out.innerHTML = '<div class="lab-err">Falta la imagen.</div>'; return; }
    const pass = pane.querySelector('#stDecPass').value || '';
    status.textContent = 'procesando…';
    try {
      let u = null;
      if (st.mode === 'lsb') {
        const { id } = await toImageData(stImg.bytes);
        const r = extractLSB(id.data, id.width * id.height);
        if (!r.found) { fail(out, 'No se encontró la cabecera "A115" en el plano LSB. ¿Modo o imagen equivocados?'); status.textContent = ''; return; }
        if (r.error) { fail(out, r.error); status.textContent = ''; return; }
        u = { enc: r.enc, body: r.body };
      } else if (st.mode === 'append') {
        u = scanMagic(stImg.bytes);
        if (!u) { fail(out, 'No se encontró un blob "A115" apendizado.'); status.textContent = ''; return; }
      } else {
        const t = findPngText(stImg.bytes, 'A115');
        if (!t) { fail(out, 'No hay chunk tEXt "A115" en el PNG.'); status.textContent = ''; return; }
        u = unpack(b64dec(t.trim()), 0);
        if (!u) { fail(out, 'El chunk "A115" no tiene un blob válido.'); status.textContent = ''; return; }
      }

      const payload = await recoverPayload(u, pass);
      status.textContent = '';
      out.innerHTML = renderRecovered(payload, u.enc);
      const a = out.querySelector('.st-dl');
      if (a) {
        const url = URL.createObjectURL(new Blob([payload]));
        a.href = url; a.download = 'payload.bin';
      }
    } catch (e) {
      console.error('[stego] extract', e);
      status.textContent = '';
      fail(out, (e && e.name === 'OperationError') ? 'Descifrado fallido: passphrase incorrecta o datos corruptos.' : (e && e.message || e));
    }
  }

  function renderRecovered(bytes, enc) {
    let printable = 0;
    for (let i = 0; i < bytes.length; i++) { const b = bytes[i]; if ((b >= 0x20 && b < 0x7F) || b === 9 || b === 10 || b === 13) printable++; }
    const isText = bytes.length && printable / bytes.length > 0.85;
    let html = '<div class="lab-note">✓ Payload recuperado · ' + fmtB(bytes.length) + (enc ? ' · descifrado AES-GCM' : '') + '</div>';
    if (isText) {
      let s = ''; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      try { s = new TextDecoder().decode(bytes); } catch (e) {}
      html += '<textarea class="cv-io out" readonly style="min-height:80px">' + esc(s) + '</textarea>';
    } else {
      html += '<div class="lab-row1">Payload binario.</div>';
    }
    html += '<div class="lab-row1"><a class="lab-ext st-dl" href="#">↓ Descargar payload</a></div>';
    return html;
  }
  function fail(out, msg) { out.innerHTML = '<div class="lab-err">' + esc(msg) + '</div>'; }

  // ── helpers de UI ───────────────────────────────────────────────────────────
  function wireDrop(drop, input, onFile) {
    const handle = (f) => { if (!f) return; f.arrayBuffer().then(ab => onFile(new Uint8Array(ab), f.name)); };
    drop.onclick = () => input.click();
    drop.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } };
    input.onchange = () => handle(input.files[0]);
    drop.ondragover = (e) => { e.preventDefault(); drop.classList.add('over'); };
    drop.ondragleave = () => drop.classList.remove('over');
    drop.ondrop = (e) => { e.preventDefault(); drop.classList.remove('over'); handle(e.dataTransfer.files[0]); };
  }
  function extOf(name, bytes) {
    const t = (typeof window !== 'undefined' && window.Triage && Triage.util) ? Triage.util.detectType(bytes) : null;
    if (t && t.ext) return t.ext;
    const m = /\.([a-z0-9]+)$/i.exec(name || ''); return m ? m[1].toLowerCase() : 'bin';
  }
  function baseName(name) { return String(name || 'out').replace(/\.[^.]+$/, ''); }

  if (typeof window !== 'undefined' && window.LAB) {
    LAB.registerTool({ id: 'stego', label: 'Stego Lab', icon: '🖼', group: '🧪 LAB / TOOLS', render });
  }
  return {
      pack, unpack, scanMagic, embedLSB, extractLSB, lsbCapacity, crc32,
      insertPngText, findPngText, b64enc, b64dec, buildBody, recoverPayload,
      encryptPayload, decryptPayload, MAGIC,
    };
})();
