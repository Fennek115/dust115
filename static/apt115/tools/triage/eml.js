// APT115 CODEX ARCANUM — Triage analyzer: eml (email RFC822 / MIME)
// quod est superius est sicut quod inferius
//
// Triage de correos .eml: el vector #1 de acceso inicial (phishing). Parsea headers,
// la cadena Received, autenticación (SPF/DKIM/DMARC), spoofing del From, URLs del cuerpo,
// y los ADJUNTOS (decodifica base64/quoted-printable → magic bytes + sha256 + extensiones
// peligrosas / dobles). 100% local — el .eml se procesa en el navegador, nada se sube.
//
// Núcleo (parser de headers/MIME, decodificadores) verificable en Node contra el módulo
// `email` de la stdlib de Python.

if (typeof window !== 'undefined') window.Triage = window.Triage || {};

(function () {
  'use strict';

  function U() { return window.Triage.util; }
  function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

  // ── ¿Parece un .eml? Heurística sobre los primeros headers ──────────────────
  function isEml(bytes) {
    if (!bytes.length) return false;
    if (bytes[0] === 0 || (bytes[0] < 0x09)) return false; // binario
    const head = new TextDecoder('latin1').decode(bytes.subarray(0, 8192));
    const first = head.slice(0, 2000);
    if (!/^[\x21-\x39\x3b-\x7e]+:[ \t]/m.test(first)) return false; // alguna línea "Header: "
    let score = 0;
    for (const re of [/^Received:/mi, /^Return-Path:/mi, /^Message-ID:/mi, /^DKIM-Signature:/mi,
      /^Authentication-Results:/mi, /^MIME-Version:/mi]) if (re.test(head)) score += 2;
    if (/^From:.*@/mi.test(head)) score++;
    if (/^(Subject|Date|To):/mi.test(head)) score++;
    return score >= 3;
  }

  // ── Parser de headers (con unfolding) ───────────────────────────────────────
  function splitHeadBody(text) {
    const m = /\r?\n\r?\n/.exec(text);
    if (!m) return { head: text, body: '' };
    return { head: text.slice(0, m.index), body: text.slice(m.index + m[0].length) };
  }

  function parseHeaders(headText) {
    const unfolded = headText.replace(/\r?\n[ \t]+/g, ' '); // continuation lines
    const lines = unfolded.split(/\r?\n/);
    const map = {}; const list = [];
    for (const ln of lines) {
      const c = ln.indexOf(':');
      if (c < 0) continue;
      const k = ln.slice(0, c).trim().toLowerCase();
      const v = ln.slice(c + 1).trim();
      list.push([k, v]);
      if (map[k] === undefined) map[k] = v; // primero gana para single-value
    }
    return { map, list };
  }
  function allOf(list, key) { return list.filter(([k]) => k === key).map(([, v]) => v); }

  // ── Direcciones ─────────────────────────────────────────────────────────────
  function parseAddr(v) {
    if (!v) return null;
    const m = /<([^>]+)>/.exec(v);
    const addr = (m ? m[1] : v).trim().replace(/^"|"$/g, '');
    const display = m ? v.slice(0, m.index).trim().replace(/^"|"$/g, '') : '';
    const at = addr.lastIndexOf('@');
    return { raw: v, display, addr, domain: at >= 0 ? addr.slice(at + 1).toLowerCase() : '' };
  }

  // ── Decodificadores ─────────────────────────────────────────────────────────
  function b64ToBytes(str) {
    const clean = str.replace(/[^A-Za-z0-9+/=]/g, '');
    try {
      const bin = atob(clean);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    } catch (e) { return new Uint8Array(0); }
  }
  function qpToString(str) {
    return str.replace(/=\r?\n/g, '').replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  }
  function decodePart(body, enc) {
    enc = (enc || '').toLowerCase().trim();
    if (enc === 'base64') return b64ToBytes(body);
    if (enc === 'quoted-printable') { const s = qpToString(body); const o = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) o[i] = s.charCodeAt(i) & 0xff; return o; }
    const o = new Uint8Array(body.length); for (let i = 0; i < body.length; i++) o[i] = body.charCodeAt(i) & 0xff; return o;
  }

  // ── MIME: recorre partes (recursivo) ────────────────────────────────────────
  function ctParam(ct, name) {
    const re = new RegExp(name + '\\s*=\\s*"([^"]*)"|' + name + '\\s*=\\s*([^;\\s]+)', 'i');
    const m = re.exec(ct || '');
    return m ? (m[1] != null ? m[1] : m[2]) : '';
  }

  function walkParts(headers, body, out, depth) {
    if (depth > 12) return;
    const ct = headers.map['content-type'] || 'text/plain';
    const type = ct.split(';')[0].trim().toLowerCase();
    if (type.startsWith('multipart/')) {
      const boundary = ctParam(ct, 'boundary');
      if (!boundary) return;
      const segs = body.split('--' + boundary);
      for (let i = 1; i < segs.length; i++) {
        let seg = segs[i];
        if (/^--/.test(seg)) break; // cierre --boundary--
        seg = seg.replace(/^\r?\n/, '');
        const sb = splitHeadBody(seg);
        const ph = parseHeaders(sb.head);
        walkParts(ph, sb.body, out, depth + 1);
      }
      return;
    }
    // Hoja
    const enc = headers.map['content-transfer-encoding'] || '';
    const disp = headers.map['content-disposition'] || '';
    const filename = ctParam(disp, 'filename') || ctParam(ct, 'name') || '';
    const isAttach = /attachment/i.test(disp) || !!filename || !/^text\//.test(type);
    out.push({ type, enc, filename, isAttach, body, ct, disp });
  }

  // ── URLs del cuerpo de texto ────────────────────────────────────────────────
  function extractUrls(text) {
    const set = new Set();
    let m; const re = /\b(?:https?|ftp):\/\/[^\s"'<>)\]}]+/gi;
    while ((m = re.exec(text)) !== null) set.add(m[0].replace(/[.,;)]+$/, ''));
    return [...set];
  }

  const DANGER = new Set(('exe scr pif com bat cmd js jse vbs vbe wsf wsh hta jar lnk iso img ' +
    'vhd vhdx msi ps1 psm1 reg dll cpl scf url application gadget inf').split(' '));

  function dangerOf(filename) {
    if (!filename) return null;
    const parts = filename.toLowerCase().split('.');
    if (parts.length < 2) return null;
    const ext = parts[parts.length - 1];
    const doubleExt = parts.length > 2 && /^(pdf|doc|docx|xls|xlsx|jpg|png|txt|invoice|scan)$/.test(parts[parts.length - 2]);
    if (DANGER.has(ext)) return doubleExt ? 'doble extensión ejecutable (.' + parts[parts.length - 2] + '.' + ext + ')' : 'extensión ejecutable (.' + ext + ')';
    if (ext === 'html' || ext === 'htm') return 'HTML adjunto (phishing/redirección)';
    if (/^(zip|rar|7z|gz|cab|ace|iso)$/.test(ext)) return 'archivo comprimido (puede ocultar ejecutables)';
    return null;
  }

  // ── Render ──────────────────────────────────────────────────────────────────
  function kv(rows) { return '<table class="lab-kv"><tbody>' + rows.map(r => '<tr><th>' + r[0] + '</th><td>' + r[1] + '</td></tr>').join('') + '</tbody></table>'; }
  function authBadge(label, val) {
    if (!val) return '<span class="lab-mit off" style="cursor:default">' + label + ': n/a</span>';
    const ok = /^pass/i.test(val);
    return '<span class="lab-mit ' + (ok ? 'on' : 'off') + '" style="cursor:default">' + label + ': ' + esc(val) + '</span>';
  }

  async function analyze(ctx) {
    const text = new TextDecoder('latin1').decode(ctx.bytes);
    const { head, body } = splitHeadBody(text);
    const H = parseHeaders(head);
    const get = (k) => H.map[k] || '';

    const from = parseAddr(get('from'));
    const returnPath = parseAddr(get('return-path'));
    const replyTo = parseAddr(get('reply-to'));
    const received = allOf(H.list, 'received');

    // Autenticación
    const ar = allOf(H.list, 'authentication-results').join(' ; ');
    const spf = (ar.match(/spf=(\w+)/i) || [])[1] || (get('received-spf').match(/^(\w+)/) || [])[1] || '';
    const dkim = (ar.match(/dkim=(\w+)/i) || [])[1] || (get('dkim-signature') ? 'present' : '');
    const dmarc = (ar.match(/dmarc=(\w+)/i) || [])[1] || '';

    let html = '<div class="lab-sub">Cabecera</div>';
    const rows = [
      ['From', from ? '<b>' + esc(from.display || from.addr) + '</b> &lt;' + esc(from.addr) + '&gt;' : '—'],
      ['Subject', esc(get('subject')) || '<span class="lab-dim">—</span>'],
      ['To', esc(get('to')) || '—'],
      ['Date', esc(get('date')) || '—'],
    ];
    if (returnPath) rows.push(['Return-Path', esc(returnPath.addr)]);
    if (replyTo) rows.push(['Reply-To', esc(replyTo.addr)]);
    if (get('message-id')) rows.push(['Message-ID', esc(get('message-id'))]);
    html += kv(rows);

    // Autenticación
    html += '<div class="lab-sub">Autenticación</div><div class="lab-badges">' +
      authBadge('SPF', spf) + authBadge('DKIM', dkim) + authBadge('DMARC', dmarc) + '</div>';

    // Indicadores de spoofing
    const sus = [];
    if (from && returnPath && from.domain && returnPath.domain && from.domain !== returnPath.domain)
      sus.push('From (' + from.domain + ') ≠ Return-Path (' + returnPath.domain + ') — posible spoofing del remitente');
    if (from && replyTo && replyTo.domain && from.domain && replyTo.domain !== from.domain)
      sus.push('Reply-To (' + replyTo.domain + ') ≠ From (' + from.domain + ') — respuestas van a otro dominio');
    if (from && from.display && /@/.test(from.display) && from.display.indexOf(from.addr) < 0)
      sus.push('el display name simula una dirección (' + esc(from.display) + ') distinta del From real');
    if (from && from.display && /\b(paypal|microsoft|apple|amazon|google|bank|netflix|office ?365|docusign|fedex|dhl)\b/i.test(from.display) &&
        from.domain && !/(paypal|microsoft|apple|amazon|google|netflix|docusign|fedex|dhl)\./i.test(from.domain))
      sus.push('display name menciona una marca ("' + esc(from.display) + '") pero el dominio es ' + esc(from.domain) + ' — impersonación de marca');
    if (spf && /fail/i.test(spf)) sus.push('SPF ' + spf);
    if (dmarc && /fail/i.test(dmarc)) sus.push('DMARC ' + dmarc);
    if (sus.length) html += '<div class="lab-note">⚠ ' + sus.map(esc).join('<br>⚠ ') + '</div>';

    // Cadena Received
    if (received.length) {
      const origin = received[received.length - 1];
      const ip = (origin.match(/\[?(\d{1,3}(?:\.\d{1,3}){3})\]?/) || [])[1] || '';
      html += '<div class="lab-sub">Ruta (Received: ' + received.length + ' hops)</div>';
      html += kv([['Origen (IP)', ip ? '<code>' + esc(ip) + '</code>' : '<span class="lab-dim">no resoluble</span>']]);
      html += '<details class="lab-dll"><summary>Cadena completa</summary><div class="lab-strings dim">' +
        received.map(r => '<div class="lab-str"><code>' + esc(r.slice(0, 240)) + '</code></div>').join('') + '</div></details>';
    }

    // MIME: partes + adjuntos
    const parts = [];
    walkParts(H, body, parts, 0);
    const attaches = parts.filter(p => p.isAttach);
    const bodies = parts.filter(p => !p.isAttach);

    // URLs (de los cuerpos de texto decodificados)
    const urlSet = new Set();
    for (const p of bodies) {
      const txt = (p.enc || '').toLowerCase() === 'base64'
        ? new TextDecoder('latin1').decode(b64ToBytes(p.body))
        : ((p.enc || '').toLowerCase() === 'quoted-printable' ? qpToString(p.body) : p.body);
      extractUrls(txt).forEach(u => urlSet.add(u));
    }
    extractUrls(get('subject')).forEach(u => urlSet.add(u));
    const urls = [...urlSet];
    if (urls.length) {
      html += '<div class="lab-sub">URLs (' + urls.length + ')</div><div class="lab-strings dim">' +
        urls.slice(0, 40).map(u => '<div class="lab-str"><code>' + esc(u.slice(0, 220)) + '</code></div>').join('') + '</div>';
    }

    // Adjuntos
    if (attaches.length) {
      html += '<div class="lab-sub">Adjuntos (' + attaches.length + ')</div>';
      html += '<table class="lab-table"><thead><tr><th>Nombre</th><th>Tipo (magic)</th><th>Tamaño</th><th>SHA-256</th></tr></thead><tbody>';
      for (const a of attaches) {
        const data = decodePart(a.body, a.enc);
        const mt = U().detectType(data);
        const danger = dangerOf(a.filename) || (mt && /exec/.test(mt.cat) ? 'ejecutable (' + mt.name + ')' : null);
        let sha = '';
        try { sha = await sha256(data); } catch (e) {}
        html += '<tr><td>' + (danger ? '<span class="lab-imp sus" title="' + esc(danger) + '">' : '<span>') + esc(a.filename || '(sin nombre)') + '</span></td>' +
          '<td>' + (mt ? esc(mt.name) : esc(a.type)) + '</td>' +
          '<td>' + U().formatBytes(data.length) + '</td>' +
          '<td><code class="lab-hash" onclick="Triage.copy(this.textContent)">' + esc(sha.slice(0, 32)) + '…</code></td></tr>';
      }
      html += '</tbody></table>';
      const dangers = attaches.map(a => ({ f: a.filename, d: dangerOf(a.filename) })).filter(x => x.d);
      if (dangers.length) html += '<div class="lab-note">⚠ ' + dangers.map(x => esc(x.f) + ': ' + esc(x.d)).join('<br>⚠ ') + '</div>';
    }

    if (!sus.length && !attaches.some(a => dangerOf(a.filename))) {
      html += '<div class="lab-note">Sin indicadores de spoofing ni adjuntos peligrosos evidentes. Revisá igual las URLs y el contexto.</div>';
    }
    return html;
  }

  async function sha256(bytes) {
    const buf = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    const d = await crypto.subtle.digest('SHA-256', buf);
    return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
  }

  const Tri = (typeof window !== 'undefined' && window.Triage) || null;
  if (Tri && Tri.analyzers) {
    Tri.analyzers.register({
      id: 'eml', title: 'Email (.eml)', icon: '✉',
      applies(ctx) { return !ctx.pe && !ctx.elf && isEml(ctx.bytes); },
      run(ctx) { return analyze(ctx); },
    });
  }
  if (typeof module !== 'undefined' && module.exports)
    module.exports = { isEml, splitHeadBody, parseHeaders, parseAddr, walkParts, b64ToBytes, qpToString, decodePart, extractUrls, dangerOf, ctParam };
})();
