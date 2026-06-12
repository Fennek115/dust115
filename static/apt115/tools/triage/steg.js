// APT115 CODEX ARCANUM — Triage analyzer: steg (esteganografía / esteganálisis)
// quod est superius est sicut quod inferius
//
// Análisis de esteganografía sobre imágenes (PNG/JPEG/GIF/BMP/WEBP). Dos niveles:
//
//   1. Contenedor (síncrono, byte-level): encuentra el FINAL lógico de la imagen y
//      detecta datos APENDIZADOS tras el EOF (el truco clásico "archivo pegado al
//      final"); hace CARVING de magics embebidos dentro del cuerpo; extrae
//      METADATOS/comentarios (chunks de texto PNG, COM de JPEG, comentario GIF).
//
//   2. Píxel (perezoso, navegador): decodifica con Canvas y corre planos de bit
//      (la viz de Aperi'Solve), un ataque CHI-CUADRADO estilo StegExpose que estima
//      la tasa de embebido LSB, y la extracción del stream LSB → strings.
//
// LÍMITE HONESTO: detecta LSB-replacement / append / metadata. NO rompe esquemas con
// clave (Steghide/F5 con passphrase) — eso es fuerza bruta sin fin; se marca y deriva.
// El nivel de píxel se decodifica recién al apretar (no por cada triage).
//
// 100% local: nada se sube. El decode usa createImageBitmap + Canvas (navegador).
// La matemática del chi-cuadrado (gammp) es pura → verificable en Node sin Canvas.

if (typeof window !== 'undefined') window.Triage = window.Triage || {};

(function () {
  'use strict';

  function U() { return window.Triage.util; }

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  function hx(n) { return '0x' + (n >>> 0).toString(16); }

  // Magics que vale la pena carvear DENTRO de una imagen (≥3 bytes para no ahogarse
  // en falsos positivos; MZ de 2 bytes queda fuera del barrido interno por ruidoso).
  const CARVE = [
    { name: 'ZIP / Office / JAR / APK', sig: [0x50, 0x4B, 0x03, 0x04] },
    { name: 'RAR', sig: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07] },
    { name: '7-Zip', sig: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] },
    { name: 'PDF', sig: [0x25, 0x50, 0x44, 0x46] },
    { name: 'gzip', sig: [0x1F, 0x8B, 0x08] },
    { name: 'ELF', sig: [0x7F, 0x45, 0x4C, 0x46] },
    { name: 'PNG embebido', sig: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] },
    { name: 'JPEG embebido', sig: [0xFF, 0xD8, 0xFF] },
    { name: 'PK ZIP (EOCD)', sig: [0x50, 0x4B, 0x05, 0x06] },
  ];

  // ── 1. Final lógico del contenedor (para detectar trailing) ─────────────────
  // Devuelve { end, kind, width, height, depth } o null si no se pudo recorrer.
  // `end` = offset justo después del último byte legítimo de la imagen.

  function endPNG(b) {
    let p = 8, w = 0, h = 0, depth = 0, color = 0;
    while (p + 8 <= b.length) {
      const len = (b[p] << 24 | b[p + 1] << 16 | b[p + 2] << 8 | b[p + 3]) >>> 0;
      const type = String.fromCharCode(b[p + 4], b[p + 5], b[p + 6], b[p + 7]);
      if (type === 'IHDR' && p + 8 + 13 <= b.length) {
        w = (b[p + 8] << 24 | b[p + 9] << 16 | b[p + 10] << 8 | b[p + 11]) >>> 0;
        h = (b[p + 12] << 24 | b[p + 13] << 16 | b[p + 14] << 8 | b[p + 15]) >>> 0;
        depth = b[p + 16]; color = b[p + 17];
      }
      const next = p + 12 + len; // len(4)+type(4)+data(len)+crc(4)
      if (type === 'IEND') return { end: p + 12 + len, kind: 'PNG', width: w, height: h, depth, color };
      if (next <= p || next > b.length) return { end: b.length, kind: 'PNG', width: w, height: h, depth, color, truncated: true };
      p = next;
    }
    return { end: b.length, kind: 'PNG', width: w, height: h, depth, color, truncated: true };
  }

  function endJPEG(b) {
    let p = 2; // tras SOI (FFD8)
    while (p + 1 < b.length) {
      if (b[p] !== 0xFF) { p++; continue; }
      let mk = b[p + 1];
      while (mk === 0xFF && p + 1 < b.length) { p++; mk = b[p + 1]; } // relleno de FF
      if (mk === 0xD9) return { end: p + 2, kind: 'JPEG' }; // EOI
      if (mk === 0x01 || (mk >= 0xD0 && mk <= 0xD7)) { p += 2; continue; } // sin payload
      const len = (b[p + 2] << 8 | b[p + 3]);
      if (len < 2) return { end: b.length, kind: 'JPEG', truncated: true };
      if (mk === 0xDA) {
        // SOS: salta el header y barre la entropía hasta el próximo marcador real.
        let q = p + 2 + len;
        while (q + 1 < b.length) {
          if (b[q] === 0xFF) {
            const m2 = b[q + 1];
            if (m2 === 0x00 || (m2 >= 0xD0 && m2 <= 0xD7)) { q += 2; continue; } // stuffing / RST
            p = q; break; // marcador real (EOI u otro scan)
          }
          q++;
        }
        if (q + 1 >= b.length) return { end: b.length, kind: 'JPEG', truncated: true };
        continue;
      }
      p += 2 + len;
    }
    return { end: b.length, kind: 'JPEG', truncated: true };
  }

  function endGIF(b) {
    let p = 6;
    if (p + 7 > b.length) return null;
    const w = b[p] | b[p + 1] << 8, h = b[p + 2] | b[p + 3] << 8;
    const flags = b[p + 4]; p += 7;
    if (flags & 0x80) p += 3 * (1 << ((flags & 7) + 1)); // global color table
    const skipSub = () => { while (p < b.length) { const n = b[p++]; if (n === 0) break; p += n; } };
    while (p < b.length) {
      const blk = b[p++];
      if (blk === 0x3B) return { end: p, kind: 'GIF', width: w, height: h }; // trailer
      if (blk === 0x21) { p++; skipSub(); }                                  // extension
      else if (blk === 0x2C) {
        if (p + 9 > b.length) break;
        const lf = b[p + 8]; p += 9;
        if (lf & 0x80) p += 3 * (1 << ((lf & 7) + 1)); // local color table
        p++; // LZW min code size
        skipSub();
      } else break;
    }
    return { end: b.length, kind: 'GIF', width: w, height: h, truncated: true };
  }

  function endBMP(b) {
    if (b.length < 6) return null;
    const sz = (b[2] | b[3] << 8 | b[4] << 16 | b[5] << 24) >>> 0;
    const w = b.length >= 22 ? (b[18] | b[19] << 8 | b[20] << 16 | b[21] << 24) : 0;
    const h = b.length >= 26 ? (b[22] | b[23] << 8 | b[24] << 16 | b[25] << 24) : 0;
    if (sz >= 14 && sz <= b.length) return { end: sz, kind: 'BMP', width: w, height: Math.abs(h | 0) };
    return { end: b.length, kind: 'BMP', width: w, height: Math.abs(h | 0), truncated: true };
  }

  function endWEBP(b) {
    if (b.length < 12) return null;
    const riff = (b[4] | b[5] << 8 | b[6] << 16 | b[7] << 24) >>> 0; // tamaño RIFF
    const end = 8 + riff;
    if (end <= b.length) return { end, kind: 'WEBP' };
    return { end: b.length, kind: 'WEBP', truncated: true };
  }

  function containerEnd(bytes, ext) {
    try {
      switch (ext) {
        case 'png': return endPNG(bytes);
        case 'jpg': return endJPEG(bytes);
        case 'gif': return endGIF(bytes);
        case 'bmp': return endBMP(bytes);
        case 'webp': return endWEBP(bytes);
      }
    } catch (e) { /* parser robusto: si revienta, sin final lógico */ }
    return null;
  }

  // ── Metadatos / comentarios de texto ────────────────────────────────────────
  function readUntilNul(b, p, max) {
    let s = '';
    while (p < max && b[p] !== 0) { s += String.fromCharCode(b[p]); p++; }
    return { s, next: p + 1 };
  }

  function pngText(bytes) {
    const out = [];
    let p = 8;
    while (p + 8 <= bytes.length) {
      const len = (bytes[p] << 24 | bytes[p + 1] << 16 | bytes[p + 2] << 8 | bytes[p + 3]) >>> 0;
      const type = String.fromCharCode(bytes[p + 4], bytes[p + 5], bytes[p + 6], bytes[p + 7]);
      const dStart = p + 8, dEnd = dStart + len;
      if (dEnd > bytes.length) break;
      if (type === 'tEXt') {
        const k = readUntilNul(bytes, dStart, dEnd);
        out.push({ key: k.s, val: asc(bytes, k.next, dEnd), kind: 'tEXt' });
      } else if (type === 'iTXt') {
        const k = readUntilNul(bytes, dStart, dEnd);
        // iTXt: keyword\0 compFlag compMethod lang\0 translated\0 text
        let q = k.next + 2;
        const lang = readUntilNul(bytes, q, dEnd); q = lang.next;
        const tr = readUntilNul(bytes, q, dEnd); q = tr.next;
        out.push({ key: k.s, val: bytes[k.next] ? '(comprimido)' : asc(bytes, q, dEnd), kind: 'iTXt' });
      } else if (type === 'zTXt') {
        const k = readUntilNul(bytes, dStart, dEnd);
        out.push({ key: k.s, val: '(zlib comprimido — ' + (dEnd - k.next - 1) + ' B)', kind: 'zTXt' });
      }
      if (type === 'IEND') break;
      p = dEnd + 4;
    }
    return out;
  }

  function asc(b, a, e) { let s = ''; for (let i = a; i < e; i++) s += String.fromCharCode(b[i]); return s; }

  function jpegComments(bytes) {
    const out = []; let p = 2;
    while (p + 3 < bytes.length) {
      if (bytes[p] !== 0xFF) { p++; continue; }
      const mk = bytes[p + 1];
      if (mk === 0xD9 || mk === 0xDA) break; // EOI o scan: cortamos
      if (mk === 0x01 || (mk >= 0xD0 && mk <= 0xD7)) { p += 2; continue; }
      const len = (bytes[p + 2] << 8 | bytes[p + 3]);
      if (len < 2) break;
      const dS = p + 4, dE = p + 2 + len;
      if (mk === 0xFE) out.push({ key: 'COM', val: asc(bytes, dS, Math.min(dE, bytes.length)), kind: 'comment' });
      else if (mk === 0xE1) {
        const tag = asc(bytes, dS, Math.min(dS + 6, dE));
        if (/Exif/.test(tag)) out.push({ key: 'APP1', val: 'EXIF presente (' + (len - 2) + ' B)', kind: 'exif' });
        else if (/http/.test(tag)) out.push({ key: 'APP1', val: 'XMP presente (' + (len - 2) + ' B)', kind: 'xmp' });
      }
      p = dE;
    }
    return out;
  }

  function gifComments(bytes) {
    const out = []; let p = 6;
    if (p + 7 > bytes.length) return out;
    const flags = bytes[p + 4]; p += 7;
    if (flags & 0x80) p += 3 * (1 << ((flags & 7) + 1));
    const readSub = () => { let s = ''; while (p < bytes.length) { const n = bytes[p++]; if (!n) break; s += asc(bytes, p, p + n); p += n; } return s; };
    while (p < bytes.length) {
      const blk = bytes[p++];
      if (blk === 0x3B) break;
      if (blk === 0x21) {
        const label = bytes[p++];
        if (label === 0xFE) out.push({ key: 'Comment', val: readSub(), kind: 'comment' });
        else { while (p < bytes.length) { const n = bytes[p++]; if (!n) break; p += n; } }
      } else if (blk === 0x2C) {
        if (p + 9 > bytes.length) break;
        const lf = bytes[p + 8]; p += 9;
        if (lf & 0x80) p += 3 * (1 << ((lf & 7) + 1));
        p++; while (p < bytes.length) { const n = bytes[p++]; if (!n) break; p += n; }
      } else break;
    }
    return out;
  }

  function metadata(bytes, ext) {
    try {
      if (ext === 'png') return pngText(bytes);
      if (ext === 'jpg') return jpegComments(bytes);
      if (ext === 'gif') return gifComments(bytes);
    } catch (e) { /* robusto */ }
    return [];
  }

  // ── Carving de magics embebidos dentro de [start,endScan) ───────────────────
  function carve(bytes, start, endScan) {
    const hits = [];
    const lim = Math.min(endScan, bytes.length);
    for (let i = Math.max(1, start); i < lim; i++) {
      for (const c of CARVE) {
        if (bytes[i] !== c.sig[0]) continue;
        let ok = true;
        for (let j = 1; j < c.sig.length; j++) { if (bytes[i + j] !== c.sig[j]) { ok = false; break; } }
        if (ok) { hits.push({ off: i, name: c.name }); if (hits.length > 64) return hits; }
      }
    }
    return hits;
  }

  // ── Chi-cuadrado (ataque de Westfeld a LSB-replacement) ─────────────────────
  // gammp = gamma incompleta inferior regularizada (Numerical Recipes). p_embebido
  // = 1 - P(χ² ≤ chi | df): bajo embebido los pares (2k,2k+1) se igualan ⇒ chi chico
  // ⇒ p cerca de 1. Pura matemática, sin DOM (verificable en Node).
  function gammln(x) {
    const c = [76.18009172947146, -86.50532032941677, 24.01409824083091,
      -1.231739572450155, 0.1208650973866179e-2, -0.5395239384953e-5];
    let y = x, tmp = x + 5.5; tmp -= (x + 0.5) * Math.log(tmp);
    let ser = 1.000000000190015;
    for (let j = 0; j < 6; j++) { y++; ser += c[j] / y; }
    return -tmp + Math.log(2.5066282746310005 * ser / x);
  }
  function gammp(a, x) {
    if (x <= 0 || a <= 0) return 0;
    if (x < a + 1) {
      let ap = a, sum = 1 / a, del = sum;
      for (let n = 0; n < 300; n++) { ap++; del *= x / ap; sum += del; if (Math.abs(del) < Math.abs(sum) * 1e-13) break; }
      return sum * Math.exp(-x + a * Math.log(x) - gammln(a));
    }
    const FPMIN = 1e-300;
    let bb = x + 1 - a, c = 1 / FPMIN, d = 1 / bb, h = d;
    for (let i = 1; i <= 300; i++) {
      const an = -i * (i - a); bb += 2; d = an * d + bb;
      if (Math.abs(d) < FPMIN) d = FPMIN;
      c = bb + an / c; if (Math.abs(c) < FPMIN) c = FPMIN;
      d = 1 / d; const del = d * c; h *= del;
      if (Math.abs(del - 1) < 1e-13) break;
    }
    return 1 - Math.exp(-x + a * Math.log(x) - gammln(a)) * h;
  }

  // hist = Uint32Array(256) de un canal. Devuelve la probabilidad de embebido LSB.
  function chiSquareEmbed(hist) {
    let chi = 0, df = 0;
    for (let k = 0; k < 128; k++) {
      const a = hist[2 * k], b = hist[2 * k + 1], n = a + b;
      if (n < 1) continue;
      const exp = n / 2;
      chi += (a - exp) * (a - exp) / exp;
      df++;
    }
    if (df < 1) return { p: 0, chi: 0, df: 0 };
    return { p: 1 - gammp((df) / 2, chi / 2), chi, df };
  }

  // ── Estado para el handler perezoso de píxel ────────────────────────────────
  let lastCtx = null, lastImageData = null;

  // ── UI: nivel contenedor (síncrono) + botón para el nivel de píxel ──────────
  function analyze(ctx) {
    lastCtx = ctx; lastImageData = null;
    const u = U();
    const t = u.detectType(ctx.bytes);
    const ext = (t && t.ext) || '';
    const info = containerEnd(ctx.bytes, ext);

    let html = '<div class="lab-row1">Esteganálisis de imagen — detecta datos <b>apendizados</b>, ' +
      'archivos <b>embebidos</b>, <b>metadatos</b> y, a nivel de píxel, <b>LSB</b>. ' +
      '<span class="lab-dim">No rompe esquemas con clave (Steghide/F5); eso se deriva a una herramienta dedicada.</span></div>';

    // Estructura + trailing
    html += '<div class="lab-sub">Contenedor</div>';
    if (info) {
      const dims = (info.width && info.height) ? (info.width + '×' + info.height + ' px') : '—';
      const rows = [
        ['Formato', esc(info.kind) + (info.depth ? ' · ' + info.depth + ' bit/canal' : '')],
        ['Dimensiones', dims],
        ['Final lógico', hx(info.end) + (info.truncated ? ' <span class="ds-warn">(no se halló el marcador EOF — truncado/corrupto)</span>' : '')],
        ['Tamaño de archivo', u.formatBytes(ctx.bytes.length)],
      ];
      html += kv(rows);

      const trail = ctx.bytes.length - info.end;
      if (trail > 0) {
        const slice = ctx.bytes.subarray(info.end);
        const tt = u.detectType(slice);
        const ent = u.entropy(slice);
        html += '<div class="lab-note">⚠ <b>' + u.formatBytes(trail) + ' apendizados tras el EOF</b> @ ' + hx(info.end) +
          ' — el patrón clásico de datos ocultos al final.' +
          (tt ? ' Identificado como <b>' + esc(tt.name) + '</b>.' : '') +
          ' Entropía ' + ent.toFixed(2) + (ent >= 7.2 ? ' (comprimido/cifrado).' : '.') + '</div>';
        const strs = u.extractStrings(slice, 5, 40);
        if (strs.strings.length) {
          html += '<div class="lab-strings dim">' + strs.strings.slice(0, 12).map(s =>
            '<div class="lab-str"><span class="lab-off"> ' + hx(info.end + s.off) + '</span><code>' + esc(s.s.slice(0, 120)) + '</code></div>').join('') + '</div>';
        }
      } else {
        html += '<div class="lab-dim" style="margin:4px 0">Sin datos tras el EOF.</div>';
      }
    } else {
      html += '<div class="lab-note">No se pudo recorrer la estructura del contenedor (' + esc(ext || 'formato desconocido') + ').</div>';
    }

    // Metadatos / comentarios
    const meta = metadata(ctx.bytes, ext);
    if (meta.length) {
      html += '<div class="lab-sub">Metadatos / comentarios (' + meta.length + ')</div>';
      html += kv(meta.map(m => [esc(m.key) + ' <span class="lab-dim">' + m.kind + '</span>', '<code>' + esc(String(m.val).slice(0, 300)) + '</code>']));
    }

    // Carving interno (magics embebidos, excluyendo el header en off 0)
    const scanEnd = info ? Math.min(info.end + 0, ctx.bytes.length) : ctx.bytes.length;
    const hits = carve(ctx.bytes, 16, info && info.end ? Math.max(info.end, ctx.bytes.length) : ctx.bytes.length);
    if (hits.length) {
      html += '<div class="lab-sub">Magics embebidos (carving · ' + hits.length + ')</div>';
      html += '<div class="lab-strings dim">' + hits.slice(0, 32).map(h =>
        '<div class="lab-str"><span class="lab-off"> ' + hx(h.off) + '</span><code>' + esc(h.name) +
        (info && h.off >= info.end ? ' · en la cola' : ' · dentro del cuerpo') + '</code></div>').join('') + '</div>';
      html += '<div class="lab-dim" style="font-size:10.5px;margin-top:3px">Un magic dentro del cuerpo puede ser ruido del flujo comprimido; revisalo con el offset.</div>';
    }

    // Botón perezoso para el nivel de píxel (decode + LSB)
    html += '<div class="lab-sub">Nivel de píxel (LSB)</div>';
    if (['png', 'jpg', 'gif', 'bmp', 'webp'].indexOf(ext) >= 0) {
      html += '<div class="ds-bar">' +
        '<button class="yr-run" onclick="Triage.steg.pixels(this)">▶ Analizar LSB y planos de bit</button>' +
        '<span class="lab-dim">decodifica la imagen localmente — chi-cuadrado + planos de bit + stream LSB</span>' +
        '</div><div class="steg-px"></div>';
    } else {
      html += '<div class="lab-dim">Formato sin decode de píxel en v1.</div>';
    }
    return html;
  }

  // ── Nivel de píxel (perezoso, navegador): decode → chi² + planos + LSB strings ─
  async function pixels(btn) {
    const panel = btn.closest('.lab-panel-b');
    const out = panel.querySelector('.steg-px');
    const ctx = lastCtx;
    if (!ctx) { out.innerHTML = '<div class="lab-err">No hay imagen cargada.</div>'; return; }
    btn.disabled = true;
    out.innerHTML = '<div class="lab-loading">⬡ Decodificando la imagen…</div>';
    try {
      const id = await decode(ctx.bytes);
      lastImageData = id;
      const W = id.width, H = id.height, d = id.data, N = W * H;

      // Histogramas por canal + chi-cuadrado (global y por mitades para localizar).
      const hist = [new Uint32Array(256), new Uint32Array(256), new Uint32Array(256)];
      for (let i = 0; i < N; i++) {
        hist[0][d[i * 4]]++; hist[1][d[i * 4 + 1]]++; hist[2][d[i * 4 + 2]]++;
      }
      const names = ['R', 'G', 'B'];
      const chi = hist.map(chiSquareEmbed);
      const maxP = Math.max(chi[0].p, chi[1].p, chi[2].p);

      let html = '<div class="lab-row1">' + W + '×' + H + ' px · ' + N.toLocaleString() + ' píxeles</div>';
      const verdict = maxP > 0.9 ? ['hi', 'Probable embebido LSB'] : maxP > 0.5 ? ['mid', 'Indicios débiles'] : ['lo', 'Sin señal LSB clara'];
      html += '<div class="lab-sub">Ataque chi-cuadrado (LSB-replacement)</div>';
      html += kv(names.map((n, i) => [n + ' — p(embebido)',
        '<span class="lab-ent ' + (chi[i].p > 0.9 ? 'hi' : chi[i].p > 0.5 ? 'mid' : 'lo') + '">' + chi[i].p.toFixed(4) + '</span>' +
        ' <span class="lab-dim">χ²=' + chi[i].chi.toFixed(1) + ', df=' + chi[i].df + '</span>']));
      html += '<div class="lab-note ' + (maxP > 0.9 ? '' : '') + '"><b>' + verdict[1] + '</b> (p máx ' + maxP.toFixed(4) + '). ' +
        'p≈1 sugiere que el bit menos significativo fue reemplazado de forma uniforme. ' +
        '<span class="lab-dim">Embebido localizado/parcial puede diluir el global — mirá los planos de bit.</span></div>';

      // Planos de bit: canvases que dibujo tras insertar el HTML.
      html += '<div class="lab-sub">Planos de bit <span class="lab-dim">— elegí el bit (0 = LSB)</span></div>';
      html += '<div class="ds-bar steg-bitsel">' +
        [0, 1, 2, 3, 4, 5, 6, 7].map(b => '<button class="cv-btn steg-bit" data-bit="' + b + '"' + (b === 0 ? ' style="border-color:var(--accent)"' : '') + '>bit ' + b + '</button>').join('') +
        '</div>';
      html += '<div class="steg-planes" style="display:flex;gap:10px;flex-wrap:wrap"></div>';

      // Stream LSB → strings (LSB de R,G,B en orden, empaquetado a bytes).
      const lsbBytes = packLSB(d, N);
      const ls = U().extractStrings(lsbBytes, 5, 60);
      html += '<div class="lab-sub">Stream LSB → strings (' + ls.strings.length + ')</div>';
      if (ls.strings.length) {
        html += '<div class="lab-strings dim">' + ls.strings.slice(0, 20).map(s =>
          '<div class="lab-str"><code>' + esc(s.s.slice(0, 160)) + '</code></div>').join('') + '</div>';
      } else {
        html += '<div class="lab-dim">Sin texto legible en el plano LSB (RGB row-major). Podría ser binario, ordenado distinto o cifrado.</div>';
      }

      out.innerHTML = html;
      drawPlanes(out, id, 0);
      out.querySelectorAll('.steg-bit').forEach(bt => {
        bt.onclick = () => {
          out.querySelectorAll('.steg-bit').forEach(x => x.style.borderColor = '');
          bt.style.borderColor = 'var(--accent)';
          drawPlanes(out, lastImageData, parseInt(bt.dataset.bit, 10) || 0);
        };
      });
    } catch (e) {
      console.error('[triage] steg pixels', e);
      out.innerHTML = '<div class="lab-err">No se pudo decodificar la imagen: ' + esc(e && e.message || e) + '</div>';
    } finally {
      btn.disabled = false;
    }
  }

  // createImageBitmap + canvas → ImageData (RGBA). 100% local.
  async function decode(bytes) {
    const blob = new Blob([bytes]);
    const bmp = await createImageBitmap(blob);
    const cv = document.createElement('canvas');
    cv.width = bmp.width; cv.height = bmp.height;
    const cx = cv.getContext('2d', { willReadFrequently: true });
    cx.drawImage(bmp, 0, 0);
    bmp.close && bmp.close();
    return cx.getImageData(0, 0, cv.width, cv.height);
  }

  // Empaqueta el bit LSB de cada canal R,G,B (row-major) en bytes (MSB primero).
  function packLSB(d, N) {
    const out = new Uint8Array(Math.floor(N * 3 / 8));
    let acc = 0, nb = 0, oi = 0;
    for (let i = 0; i < N; i++) {
      for (let c = 0; c < 3; c++) {
        acc = (acc << 1) | (d[i * 4 + c] & 1); nb++;
        if (nb === 8) { out[oi++] = acc; acc = 0; nb = 0; if (oi >= out.length) return out; }
      }
    }
    return out;
  }

  // Dibuja el plano de bit `bit` de cada canal R/G/B en canvases dentro de `out`.
  function drawPlanes(out, id, bit) {
    const host = out.querySelector('.steg-planes');
    if (!host) return;
    host.innerHTML = '';
    const W = id.width, H = id.height, d = id.data, N = W * H, mask = 1 << bit;
    ['R', 'G', 'B'].forEach((nm, c) => {
      const cv = document.createElement('canvas');
      cv.width = W; cv.height = H;
      cv.style.cssText = 'max-width:180px;height:auto;image-rendering:pixelated;border:1px solid var(--border-color)';
      const cx = cv.getContext('2d');
      const plane = cx.createImageData(W, H);
      const pd = plane.data;
      for (let i = 0; i < N; i++) {
        const v = (d[i * 4 + c] & mask) ? 255 : 0;
        pd[i * 4] = pd[i * 4 + 1] = pd[i * 4 + 2] = v; pd[i * 4 + 3] = 255;
      }
      cx.putImageData(plane, 0, 0);
      const wrap = document.createElement('div');
      wrap.style.cssText = 'text-align:center;font-size:11px';
      const lbl = document.createElement('div');
      lbl.className = 'lab-dim'; lbl.textContent = nm + ' · bit ' + bit;
      wrap.appendChild(cv); wrap.appendChild(lbl);
      host.appendChild(wrap);
    });
  }

  // ── helper de render ────────────────────────────────────────────────────────
  function kv(rows) {
    return '<table class="lab-kv"><tbody>' +
      rows.map(r => '<tr><th>' + r[0] + '</th><td>' + r[1] + '</td></tr>').join('') + '</tbody></table>';
  }

  const Tri = (typeof window !== 'undefined' && window.Triage) || null;
  if (Tri) Tri.steg = { pixels, _internals: { containerEnd, metadata, carve, chiSquareEmbed, gammp, packLSB } };

  if (Tri && Tri.analyzers) {
    Tri.analyzers.register({
      id: 'steg', title: 'Esteganografía (imagen)', icon: '🖼',
      applies(ctx) {
        if (ctx.pe || ctx.elf) return false;
        const t = Tri.util.detectType(ctx.bytes);
        return !!(t && t.cat === 'image' && ['png', 'jpg', 'gif', 'bmp', 'webp'].indexOf(t.ext) >= 0);
      },
      run(ctx) { return analyze(ctx); },
    });
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { containerEnd, metadata, carve, chiSquareEmbed, gammp, gammln, packLSB,
      endPNG, endJPEG, endGIF, endBMP, endWEBP, pngText, jpegComments, gifComments };
  }
})();
