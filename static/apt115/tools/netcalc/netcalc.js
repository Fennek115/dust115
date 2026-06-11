// APT115 CODEX ARCANUM — Network helpers
// Calculadora de subred/CIDR + referencia de puertos comunes. Todo local.

(function () {
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
      ],
    };
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
      '<span class="sec-cmds-badge">subnet · ports</span></div>' +
      '<div class="lab-intro">Calculadora de subred/CIDR y referencia de puertos — útil para scoping.</div>' +
      '<div class="lab-sub">Subnet / CIDR</div>' +
      '<input class="cv-key" id="ncIn" style="max-width:260px" placeholder="10.10.14.7/24" value="10.10.14.7/24">' +
      '<div id="ncOut"></div>' +
      '<div class="lab-sub">Puertos comunes</div>' +
      '<input class="cv-key" id="ncPort" style="max-width:260px" placeholder="buscar: 445, smb, ldap…">' +
      '<div id="ncPorts"></div>';

    const inEl = container.querySelector('#ncIn');
    const calcOut = () => {
      const r = calc(inEl.value);
      container.querySelector('#ncOut').innerHTML = r.err
        ? '<div class="lab-note">' + esc(r.err) + '</div>'
        : '<table class="lab-kv mono"><tbody>' +
          r.rows.map(x => '<tr><th>' + x[0] + '</th><td>' + esc(x[1]) + '</td></tr>').join('') +
          '</tbody></table>';
    };
    inEl.oninput = calcOut; calcOut();

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

  if (window.LAB) {
    LAB.registerTool({ id: 'netcalc', label: 'Network Calc', icon: '🌐', group: '🧪 LAB / TOOLS', render });
  }
})();
