// APT115 CODEX ARCANUM — Network helpers
// Calculadora de subred/CIDR (IPv4 + IPv6) + planificador VLSM + referencia de
// puertos comunes. Todo local, sin red. IPv6 y VLSM usan BigInt para el conteo.

export const netcalc = (function () {
  'use strict';

  function esc(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
  const i2ip = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  function ip2i(ip) {
    const p = ip.trim().split('.');
    if (p.length !== 4) return null;
    let n = 0;
    for (const o of p) { const v = +o; if (!/^\d+$/.test(o) || v < 0 || v > 255) return null; n = (n << 8) | v; }
    return n >>> 0;
  }

  // ── IPv4: subred/CIDR + clasificación ──────────────────────────────────
  function calc(input) {
    const m = input.trim().match(/^(\d+\.\d+\.\d+\.\d+)(?:\/(\d+))?$/);
    if (!m) return { err: 'Formato: a.b.c.d/n  (ej: 10.10.14.7/24)' };
    const ip = ip2i(m[1]);
    if (ip === null) return { err: 'IP inválida.' };
    const n = m[2] === undefined ? 32 : +m[2];
    if (n < 0 || n > 32) return { err: 'Prefijo /n entre 0 y 32.' };
    const mask = n === 0 ? 0 : (0xFFFFFFFF << (32 - n)) >>> 0;
    const wild = (~mask) >>> 0;
    const net = (ip & mask) >>> 0;
    const bcast = (net | wild) >>> 0;
    const total = Math.pow(2, 32 - n);
    let first, last, usable;
    if (n >= 31) { first = net; last = bcast; usable = total; }     // /31, /32: sin net/bcast reservados
    else { first = (net + 1) >>> 0; last = (bcast - 1) >>> 0; usable = total - 2; }
    return {
      rows: [
        ['CIDR', m[1] + '/' + n],
        ['Netmask', i2ip(mask)],
        ['Wildcard', i2ip(wild)],
        ['Network', i2ip(net)],
        ['Broadcast', i2ip(bcast)],
        ['Rango usable', i2ip(first) + ' – ' + i2ip(last)],
        ['Hosts usables', usable.toLocaleString()],
        ['Total direcciones', total.toLocaleString()],
        ['Tipo', ipv4Kind(ip)],
      ],
    };
  }

  // Clasificación de una IPv4 según rangos especiales (RFC1918, loopback, etc.).
  function ipv4Kind(ip) {
    const a = (ip >>> 24) & 255, b = (ip >>> 16) & 255;
    if (a === 10) return 'Privada (RFC1918 10/8)';
    if (a === 172 && b >= 16 && b <= 31) return 'Privada (RFC1918 172.16/12)';
    if (a === 192 && b === 168) return 'Privada (RFC1918 192.168/16)';
    if (a === 127) return 'Loopback (127/8)';
    if (a === 169 && b === 254) return 'Link-local / APIPA (169.254/16)';
    if (a === 100 && b >= 64 && b <= 127) return 'CGNAT (100.64/10)';
    if (a >= 224 && a <= 239) return 'Multicast (224/4)';
    if (a >= 240) return 'Reservada (240/4)';
    if (a === 0) return 'Esta red (0/8)';
    return 'Pública (global)';
  }

  // ── IPv6: expandir/comprimir + red + conteo (BigInt) + tipo ─────────────
  // Parsea una dirección IPv6 (con IPv4 embebida opcional) a un BigInt de 128b.
  function ipv6ToBig(str) {
    let s = String(str).trim();
    if (s.indexOf('::') !== s.lastIndexOf('::')) return null; // sólo un "::"
    // IPv4 embebida al final (::ffff:1.2.3.4) → dos grupos hex.
    const v4 = s.match(/(.*:)(\d+\.\d+\.\d+\.\d+)$/);
    if (v4) {
      const n = ip2i(v4[2]);
      if (n === null) return null;
      const hi = (n >>> 16) & 0xffff, lo = n & 0xffff;
      s = v4[1] + hi.toString(16) + ':' + lo.toString(16);
    }
    let head, tail;
    if (s.indexOf('::') >= 0) {
      const parts = s.split('::');
      head = parts[0] ? parts[0].split(':') : [];
      tail = parts[1] ? parts[1].split(':') : [];
      if (head.length + tail.length > 7) return null; // "::" debe valer ≥1 grupo
    } else {
      head = s.split(':'); tail = [];
      if (head.length !== 8) return null;
    }
    const fill = 8 - head.length - tail.length;
    const groups = head.concat(Array(fill).fill('0'), tail);
    let big = 0n;
    for (const g of groups) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
      big = (big << 16n) | BigInt(parseInt(g, 16));
    }
    return big;
  }

  // BigInt 128b → 8 grupos hex sin comprimir (con ceros).
  function bigToGroups(big) {
    const g = [];
    for (let i = 7; i >= 0; i--) g.push(Number((big >> BigInt(i * 16)) & 0xffffn).toString(16));
    return g;
  }
  const expandV6 = (groups) => groups.map(g => g.padStart(4, '0')).join(':');

  // Compresión RFC5952: corre el "::" sobre la racha de ceros más larga (≥2).
  function compressV6(groups) {
    let best = -1, bestLen = 0, cur = -1, curLen = 0;
    for (let i = 0; i < 8; i++) {
      if (groups[i] === '0') { if (cur < 0) cur = i; curLen++; if (curLen > bestLen) { bestLen = curLen; best = cur; } }
      else { cur = -1; curLen = 0; }
    }
    if (bestLen < 2) return groups.join(':');
    const head = groups.slice(0, best).join(':');
    const tail = groups.slice(best + bestLen).join(':');
    return head + '::' + tail;
  }

  function ipv6Kind(big) {
    if (big === 0n) return 'Unspecified (::)';
    if (big === 1n) return 'Loopback (::1)';
    const top16 = big >> 112n;
    if ((top16 & 0xffc0n) === 0xfe80n) return 'Link-local (fe80::/10)';
    if ((top16 & 0xfe00n) === 0xfc00n) return 'ULA / privada (fc00::/7)';
    if ((top16 & 0xff00n) === 0xff00n) return 'Multicast (ff00::/8)';
    if ((top16 & 0xe000n) === 0x2000n) return 'Global unicast (2000::/3)';
    return 'Reservada / otra';
  }

  function ipv6Info(input) {
    const m = String(input).trim().match(/^([0-9a-fA-F:.]+)(?:\/(\d+))?$/);
    if (!m) return { err: 'Formato: dirección IPv6 con /prefijo opcional (ej: 2001:db8::1/64)' };
    const big = ipv6ToBig(m[1]);
    if (big === null) return { err: 'IPv6 inválida.' };
    const n = m[2] === undefined ? 128 : +m[2];
    if (n < 0 || n > 128) return { err: 'Prefijo /n entre 0 y 128.' };
    const mask = n === 0 ? 0n : ((1n << BigInt(n)) - 1n) << BigInt(128 - n);
    const net = big & mask;
    const count = 1n << BigInt(128 - n);
    const groups = bigToGroups(big);
    const netGroups = bigToGroups(net);
    return {
      compressed: compressV6(groups),
      expanded: expandV6(groups),
      rows: [
        ['Comprimida', compressV6(groups)],
        ['Expandida', expandV6(groups)],
        ['Prefijo', '/' + n],
        ['Red', compressV6(netGroups) + '/' + n],
        ['Direcciones', count.toLocaleString()],
        ['Tipo', ipv6Kind(big)],
      ],
    };
  }

  // ── VLSM: planificador de subredes largest-first sobre un bloque IPv4 ───
  // base = "10.0.0.0/24"; reqs = [{name, size}] (size = hosts requeridos).
  function vlsm(base, reqs) {
    const m = String(base).trim().match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
    if (!m) return { err: 'Bloque base: a.b.c.d/n (ej: 10.0.0.0/24)' };
    const baseIp = ip2i(m[1]);
    const baseN = +m[2];
    if (baseIp === null || baseN < 0 || baseN > 32) return { err: 'Bloque base inválido.' };
    const baseNet = (baseN === 0 ? 0 : (baseIp & ((0xFFFFFFFF << (32 - baseN)) >>> 0))) >>> 0;
    const baseSize = Math.pow(2, 32 - baseN);
    const baseEnd = baseNet + baseSize; // exclusivo

    // Cada pedido → bloque mínimo que lo contiene (size + red + broadcast).
    const items = (reqs || [])
      .map(r => ({ name: String(r.name || '?'), size: Math.max(0, +r.size || 0) }))
      .filter(r => r.size > 0)
      .map(r => {
        const needed = r.size + 2;             // + network + broadcast
        let hostBits = 1;
        while (Math.pow(2, hostBits) < needed) hostBits++;
        return { ...r, hostBits, block: Math.pow(2, hostBits), prefix: 32 - hostBits };
      })
      .sort((a, b) => b.block - a.block);       // largest-first

    const rows = [];
    let cursor = baseNet;
    for (const it of items) {
      const start = Math.ceil(cursor / it.block) * it.block; // alineación al bloque
      if (start + it.block > baseEnd) { rows.push({ ...it, err: 'no entra en el bloque base' }); continue; }
      const net = start >>> 0;
      const bcast = (start + it.block - 1) >>> 0;
      const usable = it.hostBits >= 1 ? Math.pow(2, it.hostBits) - 2 : 0;
      rows.push({
        name: it.name, size: it.size, prefix: it.prefix,
        network: i2ip(net), broadcast: i2ip(bcast),
        range: i2ip((net + 1) >>> 0) + ' – ' + i2ip((bcast - 1) >>> 0),
        mask: i2ip((0xFFFFFFFF << it.hostBits) >>> 0),
        usable,
      });
      cursor = start + it.block;
    }
    const used = cursor - baseNet;
    return { rows, baseNet: i2ip(baseNet), baseN, used, free: Math.max(0, baseSize - used), total: baseSize };
  }

  // Referencia curada de puertos relevantes para pentest (no es nmap-services).
  const PORTS = [
    [21, 'tcp', 'FTP'], [22, 'tcp', 'SSH'], [23, 'tcp', 'Telnet'], [25, 'tcp', 'SMTP'],
    [53, 'tcp/udp', 'DNS'], [67, 'udp', 'DHCP server'], [69, 'udp', 'TFTP'], [80, 'tcp', 'HTTP'],
    [88, 'tcp', 'Kerberos'], [110, 'tcp', 'POP3'], [111, 'tcp/udp', 'rpcbind / NFS portmap'],
    [123, 'udp', 'NTP'], [135, 'tcp', 'MSRPC'], [137, 'udp', 'NetBIOS-NS'], [139, 'tcp', 'NetBIOS / SMB'],
    [143, 'tcp', 'IMAP'], [161, 'udp', 'SNMP'], [162, 'udp', 'SNMP trap'], [179, 'tcp', 'BGP'],
    [389, 'tcp', 'LDAP'], [443, 'tcp', 'HTTPS'], [445, 'tcp', 'SMB / CIFS'], [464, 'tcp', 'Kerberos kpasswd'],
    [465, 'tcp', 'SMTPS'], [500, 'udp', 'IKE / IPsec'], [514, 'udp', 'Syslog'], [587, 'tcp', 'SMTP submission'],
    [593, 'tcp', 'RPC over HTTP'], [623, 'udp', 'IPMI'], [636, 'tcp', 'LDAPS'], [873, 'tcp', 'rsync'],
    [990, 'tcp', 'FTPS'], [993, 'tcp', 'IMAPS'], [995, 'tcp', 'POP3S'], [1080, 'tcp', 'SOCKS proxy'],
    [1099, 'tcp', 'Java RMI'], [1433, 'tcp', 'MSSQL'], [1521, 'tcp', 'Oracle DB'], [1723, 'tcp', 'PPTP'],
    [2049, 'tcp', 'NFS'], [2375, 'tcp', 'Docker API (sin TLS)'], [2376, 'tcp', 'Docker API (TLS)'],
    [3128, 'tcp', 'Squid proxy'], [3268, 'tcp', 'LDAP Global Catalog'], [3306, 'tcp', 'MySQL'],
    [3389, 'tcp', 'RDP'], [4444, 'tcp', 'Metasploit (por defecto)'], [4505, 'tcp', 'SaltStack'],
    [5432, 'tcp', 'PostgreSQL'], [5601, 'tcp', 'Kibana'], [5672, 'tcp', 'AMQP / RabbitMQ'],
    [5900, 'tcp', 'VNC'], [5985, 'tcp', 'WinRM HTTP'], [5986, 'tcp', 'WinRM HTTPS'], [6379, 'tcp', 'Redis'],
    [6443, 'tcp', 'Kubernetes API'], [7001, 'tcp', 'WebLogic'], [8000, 'tcp', 'HTTP alt'],
    [8080, 'tcp', 'HTTP proxy / alt'], [8443, 'tcp', 'HTTPS alt'], [8888, 'tcp', 'HTTP alt'],
    [9000, 'tcp', 'SonarQube / PHP-FPM'], [9200, 'tcp', 'Elasticsearch'], [10000, 'tcp', 'Webmin'],
    [11211, 'tcp', 'Memcached'], [27017, 'tcp', 'MongoDB'], [50000, 'tcp', 'SAP'],
  ];

  function render(container) {
    container.innerHTML =
      '<div class="sec-hdr"><div class="sec-title">🌐 Network Calc</div>' +
      '<span class="sec-cmds-badge">ipv4 · ipv6 · vlsm · ports</span></div>' +
      '<div class="lab-intro">Subred/CIDR (IPv4 e IPv6), planificador VLSM y referencia de puertos — útil para scoping. Todo local.</div>' +
      '<div class="lab-sub">IPv4 — Subnet / CIDR</div>' +
      '<input class="cv-key" id="ncIn" style="max-width:260px" placeholder="10.10.14.7/24" value="10.10.14.7/24">' +
      '<div id="ncOut"></div>' +
      '<div class="lab-sub">IPv6</div>' +
      '<input class="cv-key" id="ncV6" style="max-width:320px" placeholder="2001:db8::1/64" value="2001:db8::1/64">' +
      '<div id="ncV6Out"></div>' +
      '<div class="lab-sub">VLSM — subredes desde un bloque</div>' +
      '<input class="cv-key" id="ncVlsmBase" style="max-width:200px" placeholder="10.0.0.0/24" value="10.0.0.0/24">' +
      '<textarea class="cv-io" id="ncVlsmReq" style="min-height:80px" ' +
        'placeholder="una subred por línea:  nombre, hosts&#10;Ventas, 50&#10;TI, 25&#10;Enlace, 2">Ventas, 50&#10;TI, 25&#10;Enlace, 2</textarea>' +
      '<div id="ncVlsmOut"></div>' +
      '<div class="lab-sub">Puertos comunes</div>' +
      '<input class="cv-key" id="ncPort" style="max-width:260px" placeholder="buscar: 445, smb, ldap…">' +
      '<div id="ncPorts"></div>';

    const kv = (rows) => '<table class="lab-kv mono"><tbody>' +
      rows.map(x => '<tr><th>' + esc(x[0]) + '</th><td>' + esc(x[1]) + '</td></tr>').join('') + '</tbody></table>';

    const inEl = container.querySelector('#ncIn');
    const calcOut = () => {
      const r = calc(inEl.value);
      container.querySelector('#ncOut').innerHTML = r.err ? '<div class="lab-note">' + esc(r.err) + '</div>' : kv(r.rows);
    };
    inEl.oninput = calcOut; calcOut();

    const v6El = container.querySelector('#ncV6');
    const v6Out = () => {
      const r = ipv6Info(v6El.value);
      container.querySelector('#ncV6Out').innerHTML = r.err ? '<div class="lab-note">' + esc(r.err) + '</div>' : kv(r.rows);
    };
    v6El.oninput = v6Out; v6Out();

    const baseEl = container.querySelector('#ncVlsmBase');
    const reqEl = container.querySelector('#ncVlsmReq');
    const vlsmOut = () => {
      const reqs = reqEl.value.split('\n').map(l => {
        const p = l.split(',');
        return { name: (p[0] || '').trim(), size: +(p[1] || '').trim() };
      }).filter(r => r.name && r.size > 0);
      const r = vlsm(baseEl.value, reqs);
      const out = container.querySelector('#ncVlsmOut');
      if (r.err) { out.innerHTML = '<div class="lab-note">' + esc(r.err) + '</div>'; return; }
      out.innerHTML = '<table class="lab-table"><thead><tr><th>Subred</th><th>CIDR</th><th>Máscara</th><th>Rango</th><th>Usables</th></tr></thead><tbody>' +
        r.rows.map(x => x.err
          ? '<tr><td>' + esc(x.name) + '</td><td colspan="4" class="lab-dim">' + esc(x.err) + '</td></tr>'
          : '<tr><td>' + esc(x.name) + '</td><td>' + esc(x.network + '/' + x.prefix) + '</td><td>' + esc(x.mask) +
            '</td><td>' + esc(x.range) + '</td><td>' + x.usable + '</td></tr>').join('') +
        '</tbody></table>' +
        '<div class="lab-dim" style="margin-top:6px">Bloque ' + esc(r.baseNet + '/' + r.baseN) +
        ' · usadas ' + r.used + ' de ' + r.total + ' direcciones · libres ' + r.free + '</div>';
    };
    baseEl.oninput = vlsmOut; reqEl.oninput = vlsmOut; vlsmOut();

    const portEl = container.querySelector('#ncPort');
    const portOut = container.querySelector('#ncPorts');
    const renderPorts = () => {
      const q = portEl.value.toLowerCase().trim();
      const rows = PORTS.filter(p => !q || String(p[0]) === q || String(p[0]).startsWith(q) || p[2].toLowerCase().includes(q));
      portOut.innerHTML = '<table class="lab-table"><thead><tr><th>Puerto</th><th>Proto</th><th>Servicio</th></tr></thead><tbody>' +
        rows.map(p => '<tr><td>' + p[0] + '</td><td>' + p[1] + '</td><td>' + esc(p[2]) + '</td></tr>').join('') +
        '</tbody></table>' + (rows.length ? '' : '<div class="lab-note">Sin coincidencias.</div>');
    };
    portEl.oninput = renderPorts; renderPorts();
  }

  if (typeof window !== 'undefined' && window.LAB) {
    LAB.registerTool({ id: 'netcalc', label: 'Network Calc', icon: '🌐', group: '🧪 LAB / TOOLS', render });
  }
  // Hook de test (no-op en browser): permite probar la lógica desde Node.
  return { calc, ipv6Info, vlsm };
})();
