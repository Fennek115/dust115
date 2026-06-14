// APT115 CODEX ARCANUM — PCAP / PCAPNG Forensic Analyzer
// quod est superius est sicut quod inferius
//
// Disector forense de capturas de red, portado de cero desde las specs públicas:
//   - PCAP clásico  (spec Kaitai formats.kaitai.io/pcap, CC0; libpcap savefile)
//   - PCAPNG        (draft-tuexen-opsawg-pcapng; bloques SHB/IDB/EPB/SPB)
//   - LinkTypes     (registro IETF/tcpdump)
// El tráfico es agnóstico al SO → cubre Windows y Linux por igual. Máximo valor
// forense (C2, exfiltración, beacons, reconstrucción de sesiones).
//
// 100% local — el archivo se procesa en el navegador, nada se sube. Núcleo PURO
// testeable en Node (parse / dissect*), verificado byte-a-byte contra scapy/tcpdump.
//
// Alcance v1: contenedor PCAP (LE/BE/µs/ns) + PCAPNG (SHB/IDB/EPB/SPB). Disección
// Ethernet/VLAN/NULL/RAW/SLL → IPv4/IPv6 → TCP/UDP/ICMP. Extracción de DNS
// (queries/responses), HTTP (host/URI/UA) y SNI de TLS ClientHello. Conversaciones
// por 5-tupla. IOCs estructurales (complementa la tool `ioc`). Límite: no reensambla
// streams TCP (sin tallado de payloads multi-segmento en v1); fragmentación IP no
// reensamblada; descifrado TLS fuera de alcance.

if (typeof window !== 'undefined') window.Triage = window.Triage || {};

export const pcap = (function () {
  'use strict';

  // Cap de paquetes por defecto (memoria: pcaps pueden ser grandes).
  const DEFAULT_MAX = 200000;

  // ── LinkTypes relevantes (registro tcpdump/IETF) ──────────────────────
  const LINKTYPES = {
    0: 'NULL/LOOPBACK', 1: 'ETHERNET', 9: 'PPP', 12: 'RAW', 14: 'RAW',
    101: 'RAW', 105: 'IEEE802_11', 108: 'LOOP', 113: 'LINUX_SLL',
    127: 'IEEE802_11_RADIOTAP', 228: 'IPV4', 229: 'IPV6', 276: 'LINUX_SLL2',
  };
  const linkName = (n) => LINKTYPES[n] || ('LINKTYPE_' + n);

  // ── Helpers de formato (puros, sin DOM) ───────────────────────────────
  function ipv4(b, o) { return b[o] + '.' + b[o + 1] + '.' + b[o + 2] + '.' + b[o + 3]; }

  function ipv6(b, o) {
    // 8 grupos de 16 bits → compresión RFC 5952 (la corrida de ceros más larga).
    const g = [];
    for (let i = 0; i < 8; i++) g.push((b[o + i * 2] << 8) | b[o + i * 2 + 1]);
    // hallar la corrida de ceros más larga (longitud >= 2)
    let best = -1, bestLen = 0, cur = -1, curLen = 0;
    for (let i = 0; i < 8; i++) {
      if (g[i] === 0) { if (cur < 0) cur = i; curLen++; if (curLen > bestLen) { bestLen = curLen; best = cur; } }
      else { cur = -1; curLen = 0; }
    }
    if (bestLen < 2) best = -1;
    let out = '';
    for (let i = 0; i < 8; i++) {
      if (i === best) { out += (i === 0 ? '::' : ':'); i += bestLen - 1; if (i === 7) out += ''; continue; }
      out += g[i].toString(16) + (i < 7 ? ':' : '');
    }
    // limpiar dobles de cola
    out = out.replace(/:::+/, '::');
    if (out.endsWith(':') && !out.endsWith('::')) out = out.slice(0, -1);
    return out || '::';
  }

  function ascii(b, o, n) {
    let s = '';
    for (let i = 0; i < n && o + i < b.length; i++) {
      const c = b[o + i];
      s += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : '.';
    }
    return s;
  }

  // Como ascii() pero preserva los bytes tal cual (latin1) — para parsear HTTP
  // donde el framing CRLF importa.
  function raw(b, o, n) {
    let s = '';
    for (let i = 0; i < n && o + i < b.length; i++) s += String.fromCharCode(b[o + i]);
    return s;
  }

  // ── Cabecera del contenedor (autodetección PCAP vs PCAPNG) ────────────
  function detect(bytes) {
    if (bytes.length < 4) return null;
    const m = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    const mu = m >>> 0;
    // m se compone big-endian; los bytes EN DISCO determinan el byte order:
    //   a1 b2 c3 d4 → archivo big-endian (µs) · a1 b2 3c 4d → BE nanosec
    //   d4 c3 b2 a1 → archivo little-endian (µs) · 4d 3c b2 a1 → LE nanosec
    if (mu === 0xa1b2c3d4 || mu === 0xa1b23c4d) return { fmt: 'pcap', le: false, nano: mu === 0xa1b23c4d };
    if (mu === 0xd4c3b2a1 || mu === 0x4d3cb2a1) return { fmt: 'pcap', le: true, nano: mu === 0x4d3cb2a1 };
    if (mu === 0x0a0d0d0a) return { fmt: 'pcapng' };
    return null;
  }

  // ── Parser PCAP clásico ───────────────────────────────────────────────
  function parsePcap(bytes, det, max) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const le = det.le;
    const u16 = (o) => dv.getUint16(o, le), u32 = (o) => dv.getUint32(o, le);
    const snaplen = u32(16), linkType = u32(20);
    const ver = u16(4) + '.' + u16(6);
    const packets = [];
    let off = 24, count = 0, truncated = false;
    const tsScale = det.nano ? 1e-9 : 1e-6;
    while (off + 16 <= bytes.length) {
      const tsSec = u32(off), tsFrac = u32(off + 4);
      const inclLen = u32(off + 8), origLen = u32(off + 12);
      off += 16;
      if (inclLen > bytes.length - off + 8 && off + inclLen > bytes.length) {
        // registro truncado al final
        if (off + inclLen > bytes.length) { truncated = true; break; }
      }
      const end = Math.min(off + inclLen, bytes.length);
      const ts = tsSec + tsFrac * tsScale;
      if (count < max) {
        packets.push(dissectFrame(bytes, off, end, linkType, ts, origLen, count));
      } else { truncated = true; }
      off = off + inclLen; // avanzar por inclLen aunque el frame esté capado
      count++;
      if (off > bytes.length) { truncated = true; break; }
    }
    return {
      format: 'pcap', byteOrder: le ? 'little-endian' : 'big-endian',
      tsRes: det.nano ? 'nanosegundos' : 'microsegundos', version: ver,
      snaplen, linkType, linkTypeName: linkName(linkType),
      packetCount: count, packets, truncated,
    };
  }

  // ── Parser PCAPNG ─────────────────────────────────────────────────────
  function parsePcapng(bytes, max) {
    // El byte-order lo fija el byte_order_magic del primer SHB.
    let le = true;
    {
      const probe = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      // SHB body: a partir de off 8 está byte_order_magic
      const bom = probe.getUint32(8, true);
      le = (bom >>> 0) === 0x1a2b3c4d;
    }
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const u16 = (o) => dv.getUint16(o, le), u32 = (o) => dv.getUint32(o, le);

    const interfaces = []; // { linkType, snaplen, tsresol (segundos por tick) }
    const packets = [];
    let off = 0, count = 0, truncated = false, version = '', snaplen = 0;
    let linkType = -1;

    while (off + 12 <= bytes.length) {
      const type = u32(off) >>> 0;
      const totalLen = u32(off + 4) >>> 0;
      if (totalLen < 12 || off + totalLen > bytes.length) { truncated = true; break; }
      const bodyOff = off + 8;

      if (type === 0x0a0d0d0a) {
        // SHB: byte_order_magic(4) major(2) minor(2) section_len(8) options
        version = u16(bodyOff + 4) + '.' + u16(bodyOff + 6);
      } else if (type === 0x00000001) {
        // IDB: linktype(2) reserved(2) snaplen(4) options
        const lt = u16(bodyOff);
        const snap = u32(bodyOff + 4);
        let tsresol = 1e-6; // default
        // recorrer opciones buscando if_tsresol (code 9)
        let oo = bodyOff + 8;
        const optEnd = off + totalLen - 4;
        while (oo + 4 <= optEnd) {
          const oc = u16(oo), olen = u16(oo + 2);
          if (oc === 0) break; // opt_endofopt
          if (oc === 9 && olen >= 1) {
            const v = bytes[oo + 4];
            tsresol = (v & 0x80) ? Math.pow(2, -(v & 0x7f)) : Math.pow(10, -v);
          }
          oo += 4 + olen + ((4 - (olen & 3)) & 3); // padding a 4
        }
        interfaces.push({ linkType: lt, snaplen: snap, tsresol });
        if (linkType < 0) { linkType = lt; snaplen = snap; }
      } else if (type === 0x00000006) {
        // EPB: interface_id(4) ts_high(4) ts_low(4) caplen(4) origlen(4) data...
        const ifId = u32(bodyOff);
        const tsHigh = u32(bodyOff + 4) >>> 0, tsLow = u32(bodyOff + 8) >>> 0;
        const capLen = u32(bodyOff + 12) >>> 0, origLen = u32(bodyOff + 16) >>> 0;
        const dataOff = bodyOff + 20;
        const iface = interfaces[ifId] || interfaces[0] || { linkType: linkType, tsresol: 1e-6 };
        const ticks = tsHigh * 4294967296 + tsLow;
        const ts = ticks * (iface.tsresol || 1e-6);
        const end = Math.min(dataOff + capLen, bytes.length);
        if (count < max) packets.push(dissectFrame(bytes, dataOff, end, iface.linkType, ts, origLen, count));
        else truncated = true;
        count++;
      } else if (type === 0x00000003) {
        // SPB: orig_len(4) data...
        const origLen = u32(bodyOff) >>> 0;
        const iface = interfaces[0] || { linkType: linkType };
        const capLen = Math.min(origLen, (iface.snaplen || origLen) || origLen);
        const dataOff = bodyOff + 4;
        const end = Math.min(dataOff + capLen, bytes.length);
        if (count < max) packets.push(dissectFrame(bytes, dataOff, end, iface.linkType, 0, origLen, count));
        else truncated = true;
        count++;
      }
      off += totalLen;
    }
    return {
      format: 'pcapng', byteOrder: le ? 'little-endian' : 'big-endian',
      tsRes: 'según IDB (if_tsresol)', version,
      snaplen, linkType, linkTypeName: linkName(linkType),
      interfaces: interfaces.length, packetCount: count, packets, truncated,
    };
  }

  // ── Disección de un frame (link → IP → L4 → app) ──────────────────────
  function dissectFrame(b, start, end, linkType, ts, origLen, idx) {
    const pkt = { idx, ts, len: origLen, capLen: end - start };
    let off = start, etherType = -1;
    // Capa de enlace → ubicar el inicio de la capa de red + etherType
    if (linkType === 1) { // ETHERNET
      if (off + 14 > end) return tag(pkt, 'trunc');
      etherType = (b[off + 12] << 8) | b[off + 13];
      off += 14;
      while (etherType === 0x8100 || etherType === 0x88a8) { // VLAN 802.1Q / QinQ
        if (off + 4 > end) return tag(pkt, 'trunc');
        etherType = (b[off + 2] << 8) | b[off + 3];
        off += 4;
      }
    } else if (linkType === 0 || linkType === 108) { // NULL / LOOP (BSD): family u32
      if (off + 4 > end) return tag(pkt, 'trunc');
      const fam = (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0;
      etherType = (fam === 2) ? 0x0800 : (fam === 24 || fam === 28 || fam === 30) ? 0x86dd : -1;
      off += 4;
    } else if (linkType === 12 || linkType === 14 || linkType === 101 || linkType === 228 || linkType === 229) {
      // RAW IP: discriminar por la versión del primer nibble
      const v = (b[off] >> 4);
      etherType = v === 4 ? 0x0800 : v === 6 ? 0x86dd : -1;
    } else if (linkType === 113) { // LINUX_SLL (cooked v1): 16 bytes, proto en off+14
      if (off + 16 > end) return tag(pkt, 'trunc');
      etherType = (b[off + 14] << 8) | b[off + 15];
      off += 16;
    } else if (linkType === 276) { // LINUX_SLL2: protocol(2) reserved(2) ifindex(4) ...
      if (off + 20 > end) return tag(pkt, 'trunc');
      etherType = (b[off] << 8) | b[off + 1];
      off += 20;
    } else {
      return tag(pkt, linkName(linkType));
    }
    return dissectL3(b, off, end, etherType, pkt);
  }

  function tag(pkt, t) { pkt.l3 = t; pkt.proto = t; return pkt; }

  function dissectL3(b, off, end, etherType, pkt) {
    if (etherType === 0x0806) { pkt.l3 = 'ARP'; pkt.proto = 'ARP'; return pkt; }
    if (etherType === 0x0800) { // IPv4
      if (off + 20 > end) return tag(pkt, 'IPv4?');
      const ihl = (b[off] & 0x0f) * 4;
      const proto = b[off + 9];
      pkt.l3 = 'IPv4'; pkt.src = ipv4(b, off + 12); pkt.dst = ipv4(b, off + 16);
      return dissectL4(b, off + ihl, end, proto, pkt);
    }
    if (etherType === 0x86dd) { // IPv6
      if (off + 40 > end) return tag(pkt, 'IPv6?');
      let nh = b[off + 6];
      pkt.l3 = 'IPv6'; pkt.src = ipv6(b, off + 8); pkt.dst = ipv6(b, off + 24);
      let p = off + 40;
      // saltar extension headers comunes (hop-by-hop/routing/dest tienen len en bloques de 8)
      let guard = 0;
      while ((nh === 0 || nh === 43 || nh === 60) && p + 2 <= end && guard++ < 8) {
        const hlen = (b[p + 1] + 1) * 8; nh = b[p]; p += hlen;
      }
      if (nh === 44 && p + 8 <= end) { nh = b[p]; p += 8; } // fragment header (no reensambla)
      return dissectL4(b, p, end, nh, pkt);
    }
    return tag(pkt, etherType > 0 ? 'eth:0x' + etherType.toString(16) : 'unknown');
  }

  function dissectL4(b, off, end, proto, pkt) {
    if (proto === 6) { // TCP
      if (off + 20 > end) return tag(pkt, 'TCP?');
      pkt.proto = 'TCP';
      pkt.sport = (b[off] << 8) | b[off + 1];
      pkt.dport = (b[off + 2] << 8) | b[off + 3];
      pkt.flags = b[off + 13] & 0x3f;
      const dataOff = ((b[off + 12] >> 4) & 0x0f) * 4;
      const payOff = off + dataOff, payLen = end - payOff;
      if (payLen > 0) dissectApp(b, payOff, end, pkt, payLen);
      pkt.info = pkt.info || (tcpFlags(pkt.flags) + ' ' + pkt.sport + '→' + pkt.dport);
      return pkt;
    }
    if (proto === 17) { // UDP
      if (off + 8 > end) return tag(pkt, 'UDP?');
      pkt.proto = 'UDP';
      pkt.sport = (b[off] << 8) | b[off + 1];
      pkt.dport = (b[off + 2] << 8) | b[off + 3];
      const payOff = off + 8;
      if (end - payOff > 0) dissectApp(b, payOff, end, pkt, end - payOff);
      pkt.info = pkt.info || (pkt.sport + '→' + pkt.dport);
      return pkt;
    }
    if (proto === 1) { pkt.proto = 'ICMP'; if (off < end) pkt.info = 'type ' + b[off] + ' code ' + b[off + 1]; return pkt; }
    if (proto === 58) { pkt.proto = 'ICMPv6'; if (off < end) pkt.info = 'type ' + b[off] + ' code ' + b[off + 1]; return pkt; }
    pkt.proto = 'IPproto/' + proto;
    return pkt;
  }

  function tcpFlags(f) {
    let s = '';
    if (f & 0x02) s += 'S'; if (f & 0x10) s += 'A'; if (f & 0x01) s += 'F';
    if (f & 0x04) s += 'R'; if (f & 0x08) s += 'P'; if (f & 0x20) s += 'U';
    return '[' + (s || '.') + ']';
  }

  // ── Capa de aplicación: DNS / HTTP / TLS-SNI ──────────────────────────
  function dissectApp(b, off, end, pkt, payLen) {
    // DNS por puerto 53 (UDP o TCP — TCP lleva prefijo de longitud de 2 bytes)
    if (pkt.sport === 53 || pkt.dport === 53) {
      let o = off;
      if (pkt.proto === 'TCP') o += 2; // length prefix
      const dns = parseDns(b, o, end);
      if (dns) { pkt.app = 'DNS'; pkt.dns = dns; pkt.info = dnsInfo(dns); return; }
    }
    // TLS ClientHello (record 0x16 handshake, msg 0x01) — típico 443 pero buscamos por contenido
    if (b[off] === 0x16 && off + 5 < end && b[off + 1] === 0x03) {
      const sni = parseTlsSni(b, off, end);
      if (sni !== null) { pkt.app = 'TLS'; pkt.tls = { sni }; pkt.info = 'ClientHello SNI=' + (sni || '(vacío)'); return; }
      pkt.app = 'TLS'; pkt.info = 'TLS record';
    }
    // HTTP request/response (texto)
    const head = ascii(b, off, Math.min(payLen, 16));
    if (/^(GET |POST |PUT |HEAD |DELETE|OPTIONS|PATCH |CONNECT|TRACE )/.test(head)) {
      const http = parseHttpReq(b, off, end);
      if (http) { pkt.app = 'HTTP'; pkt.http = http; pkt.info = http.method + ' ' + http.host + http.uri; }
    } else if (/^HTTP\/1\./.test(head)) {
      const line = raw(b, off, Math.min(payLen, 80)).split('\r')[0];
      pkt.app = 'HTTP'; pkt.http = { response: line }; pkt.info = line;
    }
  }

  // DNS: nombre con compresión. Devuelve { qname, qtype, answers:[{name,type,data}] }
  function parseDns(b, off, end) {
    if (off + 12 > end) return null;
    const id = (b[off] << 8) | b[off + 1];
    const flags = (b[off + 2] << 8) | b[off + 3];
    const qd = (b[off + 4] << 8) | b[off + 5];
    const an = (b[off + 6] << 8) | b[off + 7];
    if (qd > 50 || an > 200) return null; // sanity (no es DNS)
    const qr = (flags >> 15) & 1;
    let p = off + 12;
    const readName = (start) => {
      let s = '', o = start, jumped = false, jumps = 0, consumed = 0;
      while (o < end && jumps < 20) {
        const len = b[o];
        if (len === 0) { if (!jumped) consumed = o + 1 - start; break; }
        if ((len & 0xc0) === 0xc0) {
          if (o + 1 >= end) break;
          const ptr = ((len & 0x3f) << 8) | b[o + 1];
          if (!jumped) consumed = o + 2 - start;
          o = off + ptr; jumped = true; jumps++;
          continue;
        }
        if (o + 1 + len > end) break;
        s += (s ? '.' : '') + ascii(b, o + 1, len);
        o += 1 + len;
      }
      return [s, jumped ? 0 : consumed];
    };
    let qname = '', qtype = 0;
    if (qd > 0) {
      const [nm, used] = readName(p);
      qname = nm; p += used;
      if (p + 4 <= end) { qtype = (b[p] << 8) | b[p + 1]; p += 4; }
    }
    const answers = [];
    for (let i = 0; i < an && p + 10 <= end; i++) {
      const [nm, used] = readName(p);
      p += used > 0 ? used : 2;
      if (p + 10 > end) break;
      const type = (b[p] << 8) | b[p + 1];
      const rdlen = (b[p + 8] << 8) | b[p + 9];
      const rdoff = p + 10;
      let data = '';
      if (type === 1 && rdlen === 4) data = ipv4(b, rdoff);
      else if (type === 28 && rdlen === 16) data = ipv6(b, rdoff);
      else if (type === 5) data = readName(rdoff)[0]; // CNAME
      answers.push({ name: nm, type: dnsType(type), data });
      p = rdoff + rdlen;
    }
    return { id, qr, qname, qtype: dnsType(qtype), answers };
  }
  function dnsType(t) {
    return ({ 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 65: 'HTTPS' })[t] || ('TYPE' + t);
  }
  function dnsInfo(d) {
    if (d.qr) {
      const a = d.answers.filter(x => x.data).map(x => x.data);
      return 'respuesta ' + d.qname + (a.length ? ' → ' + a.join(', ') : '');
    }
    return 'consulta ' + d.qtype + ' ' + d.qname;
  }

  function parseHttpReq(b, off, end) {
    const text = raw(b, off, Math.min(end - off, 2048));
    const lines = text.split('\r\n');
    const m = /^(\S+)\s+(\S+)\s+HTTP\/1\.\d/.exec(lines[0]);
    if (!m) return null;
    const http = { method: m[1], uri: m[2], host: '', ua: '' };
    for (let i = 1; i < lines.length; i++) {
      const ln = lines[i]; if (!ln) break;
      const c = ln.indexOf(':'); if (c < 0) continue;
      const k = ln.slice(0, c).toLowerCase().trim(), v = ln.slice(c + 1).trim();
      if (k === 'host') http.host = v;
      else if (k === 'user-agent') http.ua = v;
      else if (k === 'referer') http.referer = v;
    }
    return http;
  }

  // TLS ClientHello → SNI. Devuelve la cadena, '' si hay ClientHello sin SNI, o null.
  function parseTlsSni(b, off, end) {
    let p = off;
    if (b[p] !== 0x16) return null; // handshake
    const recLen = (b[p + 3] << 8) | b[p + 4];
    p += 5;
    const recEnd = Math.min(p + recLen, end);
    if (b[p] !== 0x01) return null; // ClientHello
    const hsLen = (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3];
    p += 4;
    const hsEnd = Math.min(p + hsLen, recEnd);
    p += 2; // client version
    p += 32; // random
    if (p >= hsEnd) return null;
    const sidLen = b[p]; p += 1 + sidLen; // session id
    if (p + 2 > hsEnd) return null;
    const csLen = (b[p] << 8) | b[p + 1]; p += 2 + csLen; // cipher suites
    if (p >= hsEnd) return null;
    const cmLen = b[p]; p += 1 + cmLen; // compression methods
    if (p + 2 > hsEnd) return ''; // sin extensiones
    const extTotal = (b[p] << 8) | b[p + 1]; p += 2;
    const extEnd = Math.min(p + extTotal, hsEnd);
    while (p + 4 <= extEnd) {
      const et = (b[p] << 8) | b[p + 1];
      const el = (b[p + 2] << 8) | b[p + 3];
      const eo = p + 4;
      if (et === 0) { // server_name
        // server_name_list len(2), then entries: type(1) name_len(2) name
        let q = eo + 2;
        if (q + 3 <= eo + el) {
          const nameLen = (b[q + 1] << 8) | b[q + 2];
          return ascii(b, q + 3, nameLen);
        }
        return '';
      }
      p = eo + el;
    }
    return ''; // ClientHello sin SNI
  }

  // ── Agregación: conversaciones, protocolos, app, IOCs ─────────────────
  function summarize(parsed) {
    const convs = new Map();
    const protoStats = {};
    const dns = [], http = [], tls = [];
    const ips = new Set(), domains = new Set(), urls = new Set();
    let tsMin = Infinity, tsMax = -Infinity;

    for (const p of parsed.packets) {
      protoStats[p.proto] = (protoStats[p.proto] || 0) + 1;
      if (p.ts) { if (p.ts < tsMin) tsMin = p.ts; if (p.ts > tsMax) tsMax = p.ts; }
      if (p.src && p.dst) {
        if (p.l3 === 'IPv4' || p.l3 === 'IPv6') { ips.add(p.src); ips.add(p.dst); }
        // clave canónica bidireccional
        const a = p.src + (p.sport != null ? ':' + p.sport : '');
        const z = p.dst + (p.dport != null ? ':' + p.dport : '');
        const key = (a < z ? a + '|' + z : z + '|' + a) + '|' + p.proto;
        let c = convs.get(key);
        if (!c) { c = { a: a < z ? a : z, b: a < z ? z : a, proto: p.proto, packets: 0, bytes: 0 }; convs.set(key, c); }
        c.packets++; c.bytes += p.len || p.capLen || 0;
      }
      if (p.dns) {
        dns.push({ idx: p.idx, ...p.dns });
        if (p.dns.qname) domains.add(p.dns.qname.toLowerCase());
        for (const an of p.dns.answers) {
          if (an.type === 'A' || an.type === 'AAAA') { if (an.data) ips.add(an.data); }
          if (an.type === 'CNAME' && an.data) domains.add(an.data.toLowerCase());
        }
      }
      if (p.http) {
        http.push({ idx: p.idx, ...p.http });
        if (p.http.host) {
          domains.add(p.http.host.replace(/:\d+$/, '').toLowerCase());
          if (p.http.uri && p.http.uri.startsWith('/')) urls.add('http://' + p.http.host + p.http.uri);
        }
      }
      if (p.tls) { tls.push({ idx: p.idx, sni: p.tls.sni }); if (p.tls.sni) domains.add(p.tls.sni.toLowerCase()); }
    }

    const conversations = [...convs.values()].sort((x, y) => y.bytes - x.bytes);
    const duration = (tsMax >= tsMin && isFinite(tsMin)) ? (tsMax - tsMin) : 0;
    return {
      conversations, protoStats, dns, http, tls,
      tsMin: isFinite(tsMin) ? tsMin : 0, tsMax: isFinite(tsMax) ? tsMax : 0, duration,
      indicators: {
        ips: [...ips].sort(),
        domains: [...domains].filter(d => /\./.test(d)).sort(),
        urls: [...urls].sort(),
      },
    };
  }

  // ── Entrada del núcleo ────────────────────────────────────────────────
  function parse(bytes, opts) {
    const max = (opts && opts.max) || DEFAULT_MAX;
    const det = detect(bytes);
    if (!det) return null;
    const parsed = det.fmt === 'pcap' ? parsePcap(bytes, det, max) : parsePcapng(bytes, max);
    parsed.summary = summarize(parsed);
    return parsed;
  }

  // ══════════════════════════════ UI ════════════════════════════════════
  function render(container) {
    container.innerHTML =
      '<div class="sec-hdr"><div class="sec-title">📡 PCAP Analyzer</div>' +
      '<span class="sec-cmds-badge">local · red forense</span></div>' +
      '<div class="lab-intro">Disecciona una captura <b>.pcap</b>/<b>.pcapng</b>: conversaciones, ' +
      'DNS, HTTP, SNI de TLS e <b>IOCs</b> del tráfico. Cross-platform (Windows/Linux). ' +
      'Todo <b>100% local</b> — nada se sube.</div>' +
      '<div class="lab-drop" id="pcDrop" tabindex="0"><div class="lab-drop-ic">📡</div>' +
      '<div class="lab-drop-t">Arrastrá una captura acá o hacé click</div>' +
      '<div class="lab-drop-s">.pcap .pcapng .cap (libpcap / PCAPNG)</div></div>' +
      '<input type="file" id="pcFile" style="display:none"><div id="pcOut"></div>';
    const drop = container.querySelector('#pcDrop'), input = container.querySelector('#pcFile');
    drop.onclick = () => input.click();
    drop.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } };
    input.onchange = () => { if (input.files[0]) load(input.files[0], container); };
    drop.ondragover = (e) => { e.preventDefault(); drop.classList.add('over'); };
    drop.ondragleave = () => drop.classList.remove('over');
    drop.ondrop = (e) => { e.preventDefault(); drop.classList.remove('over'); if (e.dataTransfer.files[0]) load(e.dataTransfer.files[0], container); };
  }

  let st = null;

  function load(file, container) {
    const out = container.querySelector('#pcOut');
    const esc = window.Triage.util.esc;
    out.innerHTML = '<div class="lab-loading">⬡ Leyendo ' + esc(file.name) + ' …</div>';
    const reader = new FileReader();
    reader.onload = (e) => {
      const bytes = new Uint8Array(e.target.result);
      if (!detect(bytes)) { out.innerHTML = '<div class="lab-err">No es un PCAP/PCAPNG (magic desconocido).</div>'; return; }
      const parsed = parse(bytes);
      st = { parsed, name: file.name };
      out.innerHTML = renderReport(parsed, file.name);
      wire(out, parsed);
    };
    reader.readAsArrayBuffer(file);
  }

  function kv(rows) {
    return '<div class="lab-kv">' + rows.map(([k, v]) =>
      '<div class="lab-kv-k">' + k + '</div><div class="lab-kv-v">' + v + '</div>').join('') + '</div>';
  }

  function renderReport(p, name) {
    const U = window.Triage.util, esc = U.esc, fb = U.formatBytes;
    const s = p.summary;
    let html = '<div class="lab-panel"><div class="lab-panel-h">📡 ' + esc(name) + '</div><div class="lab-panel-b">' + kv([
      ['Formato', p.format.toUpperCase() + ' <span class="lab-dim">(' + p.byteOrder + ')</span>'],
      ['Versión', esc(p.version || '—')],
      ['Link type', esc(p.linkTypeName) + ' <span class="lab-dim">(' + p.linkType + ')</span>'],
      ['Timestamps', esc(p.tsRes)],
      ['Paquetes', p.packetCount + (p.truncated ? ' <span class="lab-warn">(capado a ' + p.packets.length + ' — archivo grande/truncado)</span>' : '')],
      ['Duración', s.duration ? s.duration.toFixed(3) + ' s' : '—'],
    ]) + '</div></div>';

    // Protocolos
    const protoRows = Object.entries(s.protoStats).sort((a, b) => b[1] - a[1]);
    html += '<div class="lab-panel"><div class="lab-panel-h">📊 Protocolos</div><div class="lab-panel-b"><div class="lab-imps">' +
      protoRows.map(([k, v]) => '<span class="lab-imp">' + esc(k) + ' <span class="lab-dim">' + v + '</span></span>').join('') +
      '</div></div></div>';

    // Conversaciones
    html += '<div class="lab-panel"><div class="lab-panel-h">🔀 Conversaciones <span class="lab-dim">(' + s.conversations.length + ')</span></div><div class="lab-panel-b"><div style="overflow:auto"><table class="lab-table"><thead><tr><th>Endpoint A</th><th>Endpoint B</th><th>Proto</th><th>Paq.</th><th>Bytes</th></tr></thead><tbody>' +
      s.conversations.slice(0, 200).map(c => '<tr><td><code>' + esc(c.a) + '</code></td><td><code>' + esc(c.b) + '</code></td><td>' + esc(c.proto) + '</td><td>' + c.packets + '</td><td>' + fb(c.bytes) + '</td></tr>').join('') +
      '</tbody></table></div></div></div>';

    // DNS
    if (s.dns.length) {
      const q = s.dns.filter(d => !d.qr), r = s.dns.filter(d => d.qr);
      html += '<div class="lab-panel"><div class="lab-panel-h">🌐 DNS <span class="lab-dim">(' + s.dns.length + ')</span></div><div class="lab-panel-b"><div style="overflow:auto"><table class="lab-table"><thead><tr><th>#</th><th></th><th>Tipo</th><th>Nombre</th><th>Respuesta</th></tr></thead><tbody>' +
        s.dns.slice(0, 300).map(d => '<tr><td class="lab-dim">' + d.idx + '</td><td>' + (d.qr ? '↩' : '↪') + '</td><td>' + esc(d.qtype) + '</td><td><code>' + esc(d.qname) + '</code></td><td>' + esc(d.answers.filter(a => a.data).map(a => a.data).join(', ')) + '</td></tr>').join('') +
        '</tbody></table></div><div class="lab-note">' + q.length + ' consultas · ' + r.length + ' respuestas</div></div></div>';
    }

    // HTTP
    if (s.http.length) {
      html += '<div class="lab-panel"><div class="lab-panel-h">🔗 HTTP <span class="lab-dim">(' + s.http.length + ')</span></div><div class="lab-panel-b"><div style="overflow:auto"><table class="lab-table"><thead><tr><th>#</th><th>Método</th><th>Host</th><th>URI</th><th>User-Agent</th></tr></thead><tbody>' +
        s.http.slice(0, 300).map(h => '<tr><td class="lab-dim">' + h.idx + '</td><td>' + esc(h.method || '—') + '</td><td><code>' + esc(h.host || '') + '</code></td><td>' + esc((h.uri || h.response || '').slice(0, 80)) + '</td><td class="lab-dim">' + esc((h.ua || '').slice(0, 60)) + '</td></tr>').join('') +
        '</tbody></table></div></div></div>';
    }

    // TLS
    if (s.tls.length) {
      const sniSet = [...new Set(s.tls.map(t => t.sni).filter(Boolean))];
      html += '<div class="lab-panel"><div class="lab-panel-h">🔒 TLS SNI <span class="lab-dim">(' + sniSet.length + ')</span></div><div class="lab-panel-b"><div class="lab-imps">' +
        sniSet.map(sni => '<span class="lab-imp">' + esc(sni) + '</span>').join('') + '</div></div></div>';
    }

    // IOCs
    const ind = s.indicators;
    const total = ind.ips.length + ind.domains.length + ind.urls.length;
    html += '<div class="lab-panel"><div class="lab-panel-h">🧬 IOCs <span class="lab-dim">(' + total + ')</span></div><div class="lab-panel-b">';
    html += '<div class="lab-actions"><button class="cv-btn" id="pcCopyIoc">copiar IOCs</button> <button class="cv-btn" id="pcNote">→ nota</button> <button class="cv-btn" id="pcExport">exportar JSON</button></div>';
    html += iocGroup('🌐 IPs', ind.ips) + iocGroup('🏷 Dominios', ind.domains) + iocGroup('🔗 URLs', ind.urls);
    html += '<div class="lab-note">Indicadores estructurales del tráfico (DNS/HTTP/TLS + endpoints). Complementan la tool <code>IOC Extractor</code>.</div>';
    html += '</div></div>';
    return html;
  }

  function iocGroup(label, list) {
    if (!list.length) return '';
    return '<div class="ioc-grp"><div class="ioc-grp-h"><span>' + label + ' <span class="lab-dim">(' + list.length + ')</span></span></div>' +
      '<div class="ioc-list">' + list.slice(0, 500).map(v => {
        const e = window.Triage.util.esc(v);
        return '<div class="ioc-item" data-v="' + e.replace(/"/g, '&quot;') + '"><code>' + e + '</code></div>';
      }).join('') + '</div></div>';
  }

  function iocText(ind) {
    const parts = [];
    if (ind.ips.length) parts.push('# IPs (' + ind.ips.length + ')', ...ind.ips, '');
    if (ind.domains.length) parts.push('# Dominios (' + ind.domains.length + ')', ...ind.domains, '');
    if (ind.urls.length) parts.push('# URLs (' + ind.urls.length + ')', ...ind.urls, '');
    return parts.join('\n').trim();
  }

  function wire(out, p) {
    const s = p.summary;
    out.querySelectorAll('.ioc-item').forEach(el => { el.onclick = () => { if (window.LAB) LAB.copy(el.dataset.v); }; });
    const ci = out.querySelector('#pcCopyIoc');
    if (ci) ci.onclick = () => { if (window.LAB) LAB.copy(iocText(s.indicators)); };
    const note = out.querySelector('#pcNote');
    if (note) note.onclick = () => {
      if (typeof window.apt115CreateNote !== 'function') return;
      window.apt115CreateNote('PCAP · ' + (st ? st.name : 'captura'), noteMarkdown(p));
    };
    const exp = out.querySelector('#pcExport');
    if (exp) exp.onclick = () => downloadJson(p);
  }

  function noteMarkdown(p) {
    const s = p.summary;
    let md = '# PCAP · ' + (st ? st.name : 'captura') + '\n\n';
    md += '- Formato: ' + p.format.toUpperCase() + ' (' + p.byteOrder + ')\n';
    md += '- Link type: ' + p.linkTypeName + '\n';
    md += '- Paquetes: ' + p.packetCount + (p.truncated ? ' (capado)' : '') + '\n';
    md += '- Duración: ' + (s.duration ? s.duration.toFixed(3) + ' s' : '—') + '\n\n';
    md += '## Conversaciones top\n\n';
    s.conversations.slice(0, 15).forEach(c => { md += '- ' + c.a + ' ↔ ' + c.b + ' (' + c.proto + ', ' + c.packets + ' paq)\n'; });
    if (s.indicators.domains.length) md += '\n## Dominios\n\n' + s.indicators.domains.map(d => '- ' + d).join('\n') + '\n';
    if (s.indicators.ips.length) md += '\n## IPs\n\n' + s.indicators.ips.map(d => '- ' + d).join('\n') + '\n';
    if (s.indicators.urls.length) md += '\n## URLs\n\n' + s.indicators.urls.map(d => '- ' + d).join('\n') + '\n';
    return md;
  }

  function downloadJson(p) {
    const s = p.summary;
    const data = {
      file: st ? st.name : null, format: p.format, linkType: p.linkTypeName,
      packetCount: p.packetCount, truncated: p.truncated, duration: s.duration,
      protocols: s.protoStats,
      conversations: s.conversations,
      dns: s.dns, http: s.http, tls: s.tls,
      indicators: s.indicators,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = (st && st.name ? st.name.replace(/\.[^.]+$/, '') : 'pcap') + '.apt115.json';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  if (typeof window !== 'undefined' && window.LAB) {
    LAB.registerTool({ id: 'pcap', label: 'PCAP Analyzer', icon: '📡', group: '🔬 Forensics', render });
  }
  // Hook de test (no-op en browser): núcleo puro.
  return { detect, parse, parsePcap, parsePcapng, dissectFrame, parseDns, parseTlsSni, parseHttpReq, summarize, ipv6, ipv4 };
})();
