// APT115 CODEX ARCANUM — X.509 Certificate Inspector
// quod est superius est sicut quod inferius
//
// Pegás un certificado PEM (o soltás un .crt/.cer/.pem/.der) y lo decodifico
// localmente: ASN.1/DER → subject/issuer, validez, número de serie, algoritmo de
// firma, algoritmo y tamaño de clave pública, SAN, key usage / extended key
// usage, basic constraints, autofirmado y huellas SHA-1/SHA-256 (Web Crypto).
// Marca debilidades: firma MD5/SHA-1, RSA < 2048 bits, vencido / aún no válido.
//
// El lector ASN.1/DER (tlv/kids/oidStr/derText) está PORTADO del parser
// Authenticode de src/triage/pe.js (mismo algoritmo TLV acotado), acá
// parametrizado sobre un buffer arbitrario para poder reusarlo y testearlo.
// 100% local, sin red; nada se valida contra una cadena ni se verifica la firma.

export const x509 = (function () {
  'use strict';

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // ── OIDs conocidos ────────────────────────────────────────────────────
  const RDN_OID = {
    '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST',
    '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.5': 'serialNumber',
    '2.5.4.4': 'SN', '2.5.4.42': 'GN', '0.9.2342.19200300.100.1.25': 'DC',
    '1.2.840.113549.1.9.1': 'emailAddress',
  };
  const SIG_OID = {
    '1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
    '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
    '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
    '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
    '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
    '1.2.840.113549.1.1.10': 'RSASSA-PSS',
    '1.2.840.10045.4.1': 'ecdsa-with-SHA1',
    '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
    '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
    '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
    '1.3.101.112': 'Ed25519', '1.3.101.113': 'Ed448',
  };
  const PUBKEY_OID = {
    '1.2.840.113549.1.1.1': 'RSA', '1.2.840.10045.2.1': 'EC',
    '1.3.101.112': 'Ed25519', '1.3.101.113': 'Ed448',
  };
  const CURVE_OID = {
    '1.2.840.10045.3.1.7': { name: 'P-256 (prime256v1)', bits: 256 },
    '1.3.132.0.34': { name: 'P-384 (secp384r1)', bits: 384 },
    '1.3.132.0.35': { name: 'P-521 (secp521r1)', bits: 521 },
    '1.3.132.0.10': { name: 'secp256k1', bits: 256 },
  };
  const EKU_OID = {
    '1.3.6.1.5.5.7.3.1': 'serverAuth', '1.3.6.1.5.5.7.3.2': 'clientAuth',
    '1.3.6.1.5.5.7.3.3': 'codeSigning', '1.3.6.1.5.5.7.3.4': 'emailProtection',
    '1.3.6.1.5.5.7.3.8': 'timeStamping', '1.3.6.1.5.5.7.3.9': 'OCSPSigning',
    '2.5.29.37.0': 'anyExtendedKeyUsage',
  };
  const KU_BITS = ['digitalSignature', 'nonRepudiation', 'keyEncipherment',
    'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign',
    'encipherOnly', 'decipherOnly'];
  const EXT = {
    SAN: '2.5.29.17', KU: '2.5.29.15', EKU: '2.5.29.37', BC: '2.5.29.19',
    SKI: '2.5.29.14', AKI: '2.5.29.35',
  };

  // ── Lector ASN.1/DER (portado de src/triage/pe.js, parametrizado) ─────
  function makeReader(bytes) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    function tlv(p, limit) {
      if (p + 2 > limit) return null;
      const tag = bytes[p];
      let lb = bytes[p + 1], hlen = 2, len = 0;
      if (lb < 0x80) { len = lb; }
      else {
        const n = lb & 0x7f;
        if (n > 4 || p + 2 + n > limit) return null;
        for (let i = 0; i < n; i++) len = len * 256 + bytes[p + 2 + i];
        hlen = 2 + n;
      }
      const start = p + hlen, end = start + len;
      if (end > limit) return null;
      return { tag, start, len, end, p };
    }
    function kids(node, limit) {
      const out = []; const lim = Math.min(node.end, limit == null ? node.end : limit); let p = node.start;
      for (let i = 0; i < 8192 && p < lim; i++) { const t = tlv(p, lim); if (!t) break; out.push(t); if (t.end <= p) break; p = t.end; }
      return out;
    }
    function oidStr(node) {
      if (!node || node.tag !== 0x06 || node.len < 1) return '';
      const o = []; const v = bytes[node.start]; o.push(Math.floor(v / 40)); o.push(v % 40);
      let acc = 0;
      for (let i = 1; i < node.len; i++) { const b = bytes[node.start + i]; acc = acc * 128 + (b & 0x7f); if (!(b & 0x80)) { o.push(acc); acc = 0; } }
      return o.join('.');
    }
    function derText(node) {
      if (node.tag === 0x1e) { // BMPString (UTF-16BE)
        let s = ''; for (let i = 0; i + 1 < node.len; i += 2) { const c = (bytes[node.start + i] << 8) | bytes[node.start + i + 1]; if (c) s += String.fromCharCode(c); } return s.trim();
      }
      const sub = bytes.subarray(node.start, node.start + node.len);
      if (node.tag === 0x0c) return new TextDecoder().decode(sub).trim(); // UTF8String
      let s = ''; for (let i = 0; i < sub.length; i++) { const c = sub[i]; if (c) s += String.fromCharCode(c); }
      return s.trim();
    }
    function ascii(node) { let s = ''; for (let i = 0; i < node.len; i++) s += String.fromCharCode(bytes[node.start + i]); return s; }
    function hexOf(node, max) { let h = ''; const n = max == null ? node.len : Math.min(node.len, max); for (let i = 0; i < n; i++) h += bytes[node.start + i].toString(16).padStart(2, '0'); return h; }
    function intVal(node) { let v = 0; for (let i = 0; i < node.len && i < 6; i++) v = v * 256 + bytes[node.start + i]; return v; }
    return { bytes, dv, tlv, kids, oidStr, derText, ascii, hexOf, intVal };
  }

  function parseName(R, nameNode) {
    const parts = []; const map = {};
    for (const rdn of R.kids(nameNode)) {
      for (const atv of R.kids(rdn)) {
        const cs = R.kids(atv);
        if (cs.length >= 2 && cs[0].tag === 0x06) {
          const oid = R.oidStr(cs[0]);
          const key = RDN_OID[oid] || oid;
          const val = R.derText(cs[1]);
          parts.push([key, val]);
          if (!(key in map)) map[key] = val;
        }
      }
    }
    return { parts, map, dn: parts.map(p => p[0] + '=' + p[1]).join(', ') };
  }

  function parseTime(R, node) {
    const s = R.ascii(node);
    let date = null;
    const mU = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);   // UTCTime
    const mG = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);   // GeneralizedTime
    if (node.tag === 0x17 && mU) {
      const yy = +mU[1]; const yyyy = yy < 50 ? 2000 + yy : 1900 + yy;
      date = new Date(Date.UTC(yyyy, +mU[2] - 1, +mU[3], +mU[4], +mU[5], +mU[6]));
    } else if (mG) {
      date = new Date(Date.UTC(+mG[1], +mG[2] - 1, +mG[3], +mG[4], +mG[5], +mG[6]));
    }
    return { raw: s, date, iso: date ? date.toISOString() : s };
  }

  /** Bits del módulo RSA dentro de un SubjectPublicKey BIT STRING. */
  function rsaBits(R, bitStr) {
    const inner = R.tlv(bitStr.start + 1, bitStr.end); // saltar el byte "unused bits"
    if (!inner || inner.tag !== 0x30) return null;
    const seq = R.kids(inner);
    const mod = seq[0]; if (!mod || mod.tag !== 0x02) return null;
    let start = mod.start, len = mod.len;
    while (len > 0 && R.bytes[start] === 0x00) { start++; len--; } // quitar el byte de signo
    if (len === 0) return 0;
    let top = R.bytes[start], topBits = 0; while (top) { topBits++; top >>= 1; }
    return (len - 1) * 8 + topBits;
  }

  function ipStr(R, node) {
    const b = R.bytes; const o = node.start;
    if (node.len === 4) return b[o] + '.' + b[o + 1] + '.' + b[o + 2] + '.' + b[o + 3];
    if (node.len === 16) { const h = []; for (let i = 0; i < 16; i += 2) h.push(((b[o + i] << 8) | b[o + i + 1]).toString(16)); return h.join(':'); }
    return R.hexOf(node);
  }

  function parseSAN(R, octet) {
    const seq = R.tlv(octet.start, octet.end);
    if (!seq) return [];
    const out = [];
    for (const gn of R.kids(seq)) {
      const t = gn.tag;
      if (t === 0x82) out.push('DNS:' + R.ascii(gn));
      else if (t === 0x81) out.push('email:' + R.ascii(gn));
      else if (t === 0x86) out.push('URI:' + R.ascii(gn));
      else if (t === 0x87) out.push('IP:' + ipStr(R, gn));
      else if (t === 0x88) out.push('RID:' + R.oidStr(gn));
      else out.push('other(0x' + t.toString(16) + ')');
    }
    return out;
  }

  function parseKeyUsage(R, octet) {
    const bs = R.tlv(octet.start, octet.end);
    if (!bs || bs.tag !== 0x03) return [];
    const out = []; let bit = 0;
    for (let i = bs.start + 1; i < bs.end; i++) {
      const byte = R.bytes[i];
      for (let b = 7; b >= 0; b--) { if ((byte >> b) & 1) { if (KU_BITS[bit]) out.push(KU_BITS[bit]); } bit++; }
    }
    return out;
  }

  function parseEku(R, octet) {
    const seq = R.tlv(octet.start, octet.end);
    if (!seq) return [];
    return R.kids(seq).filter(n => n.tag === 0x06).map(n => { const o = R.oidStr(n); return EKU_OID[o] || o; });
  }

  function parseBC(R, octet) {
    const seq = R.tlv(octet.start, octet.end);
    const res = { ca: false, pathLen: null };
    if (!seq || seq.tag !== 0x30) return res;
    for (const n of R.kids(seq)) {
      if (n.tag === 0x01) res.ca = R.bytes[n.start] !== 0;
      else if (n.tag === 0x02) res.pathLen = R.intVal(n);
    }
    return res;
  }

  /**
   * Parsea un certificado X.509 desde su DER. @param {Uint8Array} der
   * @returns {any} estructura con todos los campos + warnings.
   */
  function parseCert(der) {
    const R = makeReader(der);
    const cert = R.tlv(0, der.length);
    if (!cert || cert.tag !== 0x30) throw new Error('No es un certificado DER (se esperaba SEQUENCE).');
    const top = R.kids(cert);
    const tbs = top[0];
    if (!tbs || tbs.tag !== 0x30) throw new Error('TBSCertificate ausente.');
    const tk = R.kids(tbs);
    let i = 0, version = 1;
    if (tk[0] && tk[0].tag === 0xa0) { const v = R.kids(tk[0])[0]; if (v) version = R.intVal(v) + 1; i = 1; }
    const serialN = tk[i];
    const issuerN = tk[i + 2];
    const validityN = tk[i + 3];
    const subjectN = tk[i + 4];
    const spkiN = tk[i + 5];
    const extsWrap = tk.slice(i + 6).find(n => n.tag === 0xa3);

    // Algoritmo de firma (el externo es el autoritativo).
    const sigOid = R.oidStr(R.kids(top[1])[0]);
    const sigAlg = SIG_OID[sigOid] || sigOid;

    const issuer = parseName(R, issuerN);
    const subject = parseName(R, subjectN);

    const vk = R.kids(validityN);
    const notBefore = vk[0] ? parseTime(R, vk[0]) : null;
    const notAfter = vk[1] ? parseTime(R, vk[1]) : null;

    // Clave pública.
    const spk = R.kids(spkiN);
    const algId = spk[0]; const bitStr = spk[1];
    const algK = R.kids(algId);
    const pkOid = R.oidStr(algK[0]);
    const pubAlg = PUBKEY_OID[pkOid] || pkOid;
    const pubKey = { alg: pubAlg, bits: null, curve: null };
    if (pubAlg === 'RSA') pubKey.bits = rsaBits(R, bitStr);
    else if (pubAlg === 'EC' && algK[1]) { const c = CURVE_OID[R.oidStr(algK[1])]; if (c) { pubKey.curve = c.name; pubKey.bits = c.bits; } else pubKey.curve = R.oidStr(algK[1]); }
    else if (pubAlg === 'Ed25519') pubKey.bits = 256;

    // Extensiones.
    const exts = {};
    if (extsWrap) {
      const seq = R.kids(extsWrap)[0];
      if (seq) for (const ext of R.kids(seq)) {
        const ek = R.kids(ext);
        if (!ek.length || ek[0].tag !== 0x06) continue;
        const octet = ek[ek.length - 1];
        if (octet.tag === 0x04) exts[R.oidStr(ek[0])] = octet;
      }
    }
    const san = exts[EXT.SAN] ? parseSAN(R, exts[EXT.SAN]) : [];
    const keyUsage = exts[EXT.KU] ? parseKeyUsage(R, exts[EXT.KU]) : [];
    const extKeyUsage = exts[EXT.EKU] ? parseEku(R, exts[EXT.EKU]) : [];
    const basicConstraints = exts[EXT.BC] ? parseBC(R, exts[EXT.BC]) : null;

    const selfSigned = issuer.dn === subject.dn && issuer.dn !== '';

    // Debilidades.
    const warnings = [];
    if (/md5|md2|sha1/i.test(sigAlg)) warnings.push('Algoritmo de firma débil (' + sigAlg + ')');
    if (pubAlg === 'RSA' && pubKey.bits && pubKey.bits < 2048) warnings.push('Clave RSA chica (' + pubKey.bits + ' bits < 2048)');
    const now = Date.now();
    if (notAfter && notAfter.date && notAfter.date.getTime() < now) warnings.push('Certificado VENCIDO (' + notAfter.iso + ')');
    if (notBefore && notBefore.date && notBefore.date.getTime() > now) warnings.push('Aún NO válido (notBefore ' + notBefore.iso + ')');

    return {
      version, serial: R.hexOf(serialN), sigAlg, sigOid,
      issuer, subject, notBefore, notAfter,
      pubKey, san, keyUsage, extKeyUsage, basicConstraints,
      selfSigned, warnings,
    };
  }

  // ── PEM/DER → bytes ───────────────────────────────────────────────────
  function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  /** Normaliza la entrada (PEM, base64 suelto o DER) a bytes DER. */
  function toDer(input) {
    if (input instanceof Uint8Array) {
      if (input[0] === 0x30) return input;        // ya es DER
      input = new TextDecoder().decode(input);     // era un PEM en un archivo
    }
    const s = String(input == null ? '' : input).trim();
    const m = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/.exec(s);
    const b64 = (m ? m[1] : s).replace(/[^A-Za-z0-9+/=]/g, '');
    if (!b64) return null;
    return b64ToBytes(b64);
  }

  async function fingerprints(der) {
    const hex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
    const view = der.buffer.byteLength === der.byteLength ? der : der.slice();
    const sha1 = hex(await crypto.subtle.digest('SHA-1', view));
    const sha256 = hex(await crypto.subtle.digest('SHA-256', view));
    return { sha1, sha256 };
  }

  /** Entrada→análisis completo (async por las huellas Web Crypto). */
  async function analyze(input) {
    let der;
    try { der = toDer(input); } catch (e) { return { ok: false, error: String((e && e.message) || e) }; }
    if (!der || der.length < 2) return { ok: false, error: 'No se reconoció un certificado PEM/DER.' };
    let cert;
    try { cert = parseCert(der); } catch (e) { return { ok: false, error: String((e && e.message) || e) }; }
    let fp = null;
    try { fp = await fingerprints(der); } catch (_) { /* Web Crypto no disponible */ }
    return { ok: true, cert, fingerprints: fp };
  }

  // ── Render ────────────────────────────────────────────────────────────
  function colonHex(h) { return (h.match(/../g) || []).join(':').toUpperCase(); }

  function dnTable(name) {
    if (!name.parts.length) return '<span class="lab-dim">(vacío)</span>';
    return '<table class="lab-kv"><tbody>' +
      name.parts.map(p => '<tr><th>' + esc(p[0]) + '</th><td>' + esc(p[1]) + '</td></tr>').join('') +
      '</tbody></table>';
  }

  function render(container) {
    container.innerHTML =
      '<div class="lab-sec">' +
      '<div class="lab-intro"><b>X.509 Certificate Inspector.</b> Pegá un certificado <b>PEM</b> ' +
      '(<code>-----BEGIN CERTIFICATE-----</code>) o soltá un <code>.crt/.cer/.pem/.der</code>. ' +
      'Decodifico ASN.1/DER local: subject/issuer, validez, clave, SAN, usos, autofirmado y huellas SHA-1/256. ' +
      'No verifico la firma ni la cadena — es un decodificador, no un validador.</div>' +
      '<textarea id="x5In" class="cv-io" spellcheck="false" style="min-height:130px" ' +
      'placeholder="-----BEGIN CERTIFICATE-----&#10;MIIE...&#10;-----END CERTIFICATE-----"></textarea>' +
      '<div class="x5-actions"><button id="x5Go" class="cv-btn">Analizar</button>' +
      '<button id="x5Drop" class="cv-btn">Cargar archivo…</button>' +
      '<input type="file" id="x5File" style="display:none"></div>' +
      '<div id="x5Out"></div></div>';

    const out = container.querySelector('#x5Out');
    const ta = container.querySelector('#x5In');
    const run = (input) => {
      out.innerHTML = '<div class="lab-loading">Decodificando…</div>';
      analyze(input).then(res => renderOut(out, res)).catch(e =>
        out.innerHTML = '<div class="lab-note">Error: ' + esc(String((e && e.message) || e)) + '</div>');
    };
    container.querySelector('#x5Go').onclick = () => run(ta.value);
    const file = container.querySelector('#x5File');
    container.querySelector('#x5Drop').onclick = () => file.click();
    file.onchange = () => { const f = file.files[0]; if (f) f.arrayBuffer().then(ab => run(new Uint8Array(ab))); };
  }

  function renderOut(out, res) {
    if (!res.ok) { out.innerHTML = '<div class="lab-note">No se pudo parsear: ' + esc(res.error) + '</div>'; return; }
    const c = res.cert;
    let html = '';

    if (c.warnings.length) {
      html += '<div class="x5-warn"><b>⚠ Advertencias</b><ul>' +
        c.warnings.map(w => '<li>' + esc(w) + '</li>').join('') + '</ul></div>';
    }

    const kv = (rows) => '<table class="lab-kv"><tbody>' +
      rows.map(r => '<tr><th>' + esc(r[0]) + '</th><td>' + r[1] + '</td></tr>').join('') + '</tbody></table>';

    const keyDesc = c.pubKey.alg + (c.pubKey.bits ? ' ' + c.pubKey.bits + ' bits' : '') +
      (c.pubKey.curve ? ' — ' + c.pubKey.curve : '');

    html += '<div class="lab-panel"><div class="lab-panel-h" onclick="this.parentElement.classList.toggle(\'collapsed\')">' +
      '<span>📜 Certificado' + (c.selfSigned ? ' <span class="x5-tag">autofirmado</span>' : '') +
      (c.basicConstraints && c.basicConstraints.ca ? ' <span class="x5-tag">CA</span>' : '') +
      '</span><span class="lab-panel-x">▾</span></div><div class="lab-panel-b">' +
      kv([
        ['Versión', 'v' + esc(c.version)],
        ['Serial', '<code>' + esc(colonHex(c.serial)) + '</code>'],
        ['Firma', esc(c.sigAlg) + (/md5|sha1/i.test(c.sigAlg) ? ' <span class="x5-bad">débil</span>' : '')],
        ['Clave pública', esc(keyDesc)],
        ['No antes', notBeforeStr(c)],
        ['No después', notAfterStr(c)],
      ]) + '</div></div>';

    html += '<div class="lab-panel"><div class="lab-panel-h" onclick="this.parentElement.classList.toggle(\'collapsed\')">' +
      '<span>🪪 Subject</span><span class="lab-panel-x">▾</span></div><div class="lab-panel-b">' + dnTable(c.subject) + '</div></div>';
    html += '<div class="lab-panel"><div class="lab-panel-h" onclick="this.parentElement.classList.toggle(\'collapsed\')">' +
      '<span>🏛 Issuer</span><span class="lab-panel-x">▾</span></div><div class="lab-panel-b">' + dnTable(c.issuer) + '</div></div>';

    if (c.san.length || c.keyUsage.length || c.extKeyUsage.length || c.basicConstraints) {
      const rows = [];
      if (c.san.length) rows.push(['SAN', c.san.map(s => '<code class="x5-san">' + esc(s) + '</code>').join(' ')]);
      if (c.keyUsage.length) rows.push(['Key Usage', c.keyUsage.map(esc).join(', ')]);
      if (c.extKeyUsage.length) rows.push(['Ext Key Usage', c.extKeyUsage.map(esc).join(', ')]);
      if (c.basicConstraints) rows.push(['Basic Constraints', 'CA: ' + (c.basicConstraints.ca ? 'TRUE' : 'FALSE') +
        (c.basicConstraints.pathLen != null ? ', pathlen: ' + c.basicConstraints.pathLen : '')]);
      html += '<div class="lab-panel"><div class="lab-panel-h" onclick="this.parentElement.classList.toggle(\'collapsed\')">' +
        '<span>🧩 Extensiones</span><span class="lab-panel-x">▾</span></div><div class="lab-panel-b">' + kv(rows) + '</div></div>';
    }

    if (res.fingerprints) {
      html += '<div class="lab-panel"><div class="lab-panel-h" onclick="this.parentElement.classList.toggle(\'collapsed\')">' +
        '<span>🔑 Huellas</span><span class="lab-panel-x">▾</span></div><div class="lab-panel-b">' +
        kv([
          ['SHA-1', '<code>' + esc(colonHex(res.fingerprints.sha1)) + '</code>'],
          ['SHA-256', '<code>' + esc(colonHex(res.fingerprints.sha256)) + '</code>'],
        ]) + '</div></div>';
    }

    out.innerHTML = html;
  }
  function notBeforeStr(c) { return c.notBefore ? esc(c.notBefore.iso) : '—'; }
  function notAfterStr(c) {
    if (!c.notAfter) return '—';
    const expired = c.notAfter.date && c.notAfter.date.getTime() < Date.now();
    return esc(c.notAfter.iso) + (expired ? ' <span class="x5-bad">vencido</span>' : '');
  }

  if (typeof window !== 'undefined' && window.LAB) {
    window.LAB.registerTool({ id: 'x509', label: 'X.509 Cert', icon: '📜', group: '🧪 LAB / TOOLS', render });
  }
  // Hook de test: núcleo verificable desde Node.
  return { toDer, parseCert, fingerprints, analyze, makeReader, parseName };
})();
