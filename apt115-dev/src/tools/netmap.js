// APT115 CODEX ARCANUM — Network Map
// Mapa de red desde la salida de nmap, 100% local. Ingiere XML (-oX) o grepable
// (-oG / .gnmap), agrupa hosts por subred /24 y resalta servicios jugosos para
// pentest. Exporta txt/md/json y puede mandar el mapa a una nota markdown
// (puente con el panel de notas, vía window.apt115CreateNote).
//
// El parser XML es por regex en vez de DOMParser: la salida de nmap es máquina-
// generada y muy regular, y así el núcleo se testea en Node sin un DOM falso.

export const netmap = (function () {
  'use strict';

  function esc(s) {
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  // Des-escapa entidades XML básicas de los valores de atributo de nmap.
  function unent(s) {
    return String(s == null ? '' : s)
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'").replace(/&amp;/g, '&');
  }
  const attr = (tag, name) => {
    const m = tag.match(new RegExp('\\b' + name + '="([^"]*)"'));
    return m ? unent(m[1]) : '';
  };

  // Servicios de alto interés para pentest → resalte. Por nombre de servicio
  // (nmap) y por puerto de respaldo.
  const JUICY_SVC = /\b(smb|microsoft-ds|netbios|ldap|globalcat|kerberos|ms-wbt-server|rdp|winrm|wsman|ms-sql|mssql|mysql|postgres|oracle|redis|mongod?|http|https|http-proxy|ftp|telnet|rsync|nfs|rpcbind|vnc|docker|kubernetes|elasticsearch|snmp|ipmi|x11)\b/i;
  const JUICY_PORT = new Set([21, 23, 88, 111, 135, 139, 389, 445, 636, 1433, 1521, 2049,
    3268, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 6443, 9200, 11211, 27017]);
  const isJuicy = (p) => (p.service && JUICY_SVC.test(p.service)) || JUICY_PORT.has(+p.port);

  // ── XML (-oX) ───────────────────────────────────────────────────────────
  function parseNmapXml(xml) {
    const hosts = [];
    const text = String(xml || '');
    const hostRe = /<host\b[\s\S]*?<\/host>/g;
    let hm;
    while ((hm = hostRe.exec(text))) {
      const block = hm[0];
      const statusM = block.match(/<status\b[^>]*>/);
      const state = statusM ? attr(statusM[0], 'state') : '';
      // Dirección IPv4 (preferida) o IPv6.
      let ip = '';
      const addrRe = /<address\b[^>]*\/?>/g;
      let am;
      while ((am = addrRe.exec(block))) {
        const t = attr(am[0], 'addrtype');
        if (t === 'ipv4') { ip = attr(am[0], 'addr'); break; }
        if (t === 'ipv6' && !ip) ip = attr(am[0], 'addr');
      }
      const hnM = block.match(/<hostname\b[^>]*\/?>/);
      const hostname = hnM ? attr(hnM[0], 'name') : '';
      const osM = block.match(/<osmatch\b[^>]*\/?>/);
      const os = osM ? attr(osM[0], 'name') : '';
      const ports = [];
      const portRe = /<port\b[\s\S]*?<\/port>/g;
      let pm;
      while ((pm = portRe.exec(block))) {
        const pb = pm[0];
        const head = pb.match(/<port\b[^>]*>/)[0];
        const stM = pb.match(/<state\b[^>]*\/?>/);
        const svM = pb.match(/<service\b[^>]*\/?>/);
        ports.push({
          port: +attr(head, 'portid'),
          proto: attr(head, 'protocol'),
          state: stM ? attr(stM[0], 'state') : '',
          service: svM ? attr(svM[0], 'name') : '',
          product: svM ? attr(svM[0], 'product') : '',
          version: svM ? attr(svM[0], 'version') : '',
        });
      }
      // Sólo puertos abiertos (incluye open|filtered).
      const open = ports.filter(p => /open/.test(p.state));
      if (ip || open.length) hosts.push({ ip, hostname, state: state || 'up', os, ports: open });
    }
    return hosts;
  }

  // ── Grepable (-oG / .gnmap) ──────────────────────────────────────────────
  function parseGnmap(text) {
    const hosts = [];
    const lines = String(text || '').split('\n');
    for (const line of lines) {
      const hm = line.match(/^Host:\s+(\S+)\s+\(([^)]*)\)/);
      if (!hm) continue;
      const ip = hm[1];
      const hostname = hm[2] || '';
      const statM = line.match(/Status:\s+(\w+)/);
      const state = statM ? statM[1].toLowerCase() : 'up';
      const osM = line.match(/OS:\s+([^\t]+)/);
      const os = osM ? osM[1].trim() : '';
      const ports = [];
      const portsM = line.match(/Ports:\s+([^\t]+)/);
      if (portsM) {
        for (const chunk of portsM[1].split(',')) {
          // portid/state/proto/owner/service/rpc info/version/
          const f = chunk.trim().split('/');
          if (f.length < 3) continue;
          const state2 = f[1];
          if (!/open/.test(state2)) continue;
          ports.push({
            port: +f[0], proto: f[2], state: state2,
            service: (f[4] || '').trim(), product: '', version: (f[6] || '').trim(),
          });
        }
      }
      hosts.push({ ip, hostname, state, os, ports });
    }
    return hosts;
  }

  // Detecta el formato y parsea. Devuelve { hosts, fmt }.
  function parse(text) {
    const t = String(text || '');
    if (/<nmaprun\b|<host\b/.test(t)) return { hosts: parseNmapXml(t), fmt: 'xml' };
    if (/^Host:\s/m.test(t)) return { hosts: parseGnmap(t), fmt: 'gnmap' };
    return { hosts: [], fmt: '' };
  }

  // /24 de una IPv4 ("10.0.0.5" → "10.0.0.0/24"); para IPv6 agrupa por la dir.
  function subnetOf(ip) {
    const m = String(ip).match(/^(\d+)\.(\d+)\.(\d+)\.\d+$/);
    return m ? m[1] + '.' + m[2] + '.' + m[3] + '.0/24' : (ip || 'otros');
  }

  // Agrupa hosts por subred, ordenado.
  function groupBySubnet(hosts) {
    const map = new Map();
    for (const h of hosts) {
      const k = subnetOf(h.ip);
      if (!map.has(k)) map.set(k, []);
      map.get(k).push(h);
    }
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true }));
  }

  // ── Export ───────────────────────────────────────────────────────────────
  function toMarkdown(hosts) {
    const lines = ['# Network map', ''];
    for (const [subnet, hs] of groupBySubnet(hosts)) {
      lines.push('## ' + subnet, '');
      for (const h of hs) {
        lines.push('### ' + h.ip + (h.hostname ? ' (' + h.hostname + ')' : ''));
        if (h.os) lines.push('- OS: ' + h.os);
        for (const p of h.ports) {
          const svc = [p.service, p.product, p.version].filter(Boolean).join(' ');
          lines.push('- `' + p.port + '/' + p.proto + '` ' + (svc || p.state) + (isJuicy(p) ? '  ⭐' : ''));
        }
        lines.push('');
      }
    }
    return lines.join('\n').trim() + '\n';
  }
  function toText(hosts) {
    const out = [];
    for (const [subnet, hs] of groupBySubnet(hosts)) {
      out.push('[' + subnet + ']');
      for (const h of hs) {
        out.push('  ' + h.ip + (h.hostname ? ' (' + h.hostname + ')' : '') + (h.os ? '  — ' + h.os : ''));
        for (const p of h.ports) {
          const svc = [p.service, p.product, p.version].filter(Boolean).join(' ');
          out.push('    ' + (p.port + '/' + p.proto).padEnd(12) + (svc || p.state) + (isJuicy(p) ? ' *' : ''));
        }
      }
    }
    return out.join('\n');
  }
  const toJson = (hosts) => JSON.stringify(hosts, null, 2);

  function render(container) {
    container.innerHTML =
      '<div class="sec-hdr"><div class="sec-title">🗺 Network Map</div>' +
      '<span class="sec-cmds-badge" id="nmBadge">0 hosts</span></div>' +
      '<div class="lab-intro">Pegá la salida de <code>nmap</code> — XML (<code>-oX</code>) o grepable ' +
      '(<code>-oG</code>/<code>.gnmap</code>). Agrupa hosts por subred y resalta servicios jugosos. ' +
      'Todo local — nada sale del navegador.</div>' +
      '<textarea class="cv-io" id="nmIn" style="min-height:130px" ' +
        'placeholder="Pegá acá el XML o grepable de nmap…&#10;Ej (gnmap): Host: 10.0.0.5 (dc01)\tPorts: 445/open/tcp//microsoft-ds//, 3389/open/tcp//ms-wbt-server//"></textarea>' +
      '<div class="ioc-bar">' +
        '<span class="lab-dim" id="nmFmt"></span>' +
        '<button class="cv-btn" id="nmMd">copiar md</button>' +
        '<button class="cv-btn" id="nmTxt">copiar txt</button>' +
        '<button class="cv-btn" id="nmJson">copiar json</button>' +
        '<button class="cv-btn" id="nmNote">→ nota</button>' +
      '</div>' +
      '<div id="nmOut"></div>';

    const inp = container.querySelector('#nmIn');
    let hosts = [];
    let t;
    const run = () => {
      const r = parse(inp.value);
      hosts = r.hosts;
      container.querySelector('#nmBadge').textContent = hosts.length + ' host' + (hosts.length === 1 ? '' : 's');
      container.querySelector('#nmFmt').textContent = inp.value.trim()
        ? (r.fmt ? 'formato: ' + r.fmt : 'formato no reconocido') : '';
      renderMap(container.querySelector('#nmOut'), hosts);
    };
    inp.oninput = () => { clearTimeout(t); t = setTimeout(run, 150); };

    const copy = (s) => { if (s && window.LAB) LAB.copy(s); };
    container.querySelector('#nmMd').onclick = () => copy(hosts.length && toMarkdown(hosts));
    container.querySelector('#nmTxt').onclick = () => copy(hosts.length && toText(hosts));
    container.querySelector('#nmJson').onclick = () => copy(hosts.length && toJson(hosts));
    container.querySelector('#nmNote').onclick = () => {
      if (!hosts.length || typeof window.apt115CreateNote !== 'function') return;
      const title = 'Network map ' + new Date().toLocaleDateString();
      window.apt115CreateNote(title, toMarkdown(hosts));
      if (window.LAB && LAB.toast) LAB.toast('Mapa enviado a notas');
      else if (window.showToast) window.showToast('Mapa enviado a notas');
    };
  }

  function renderMap(out, hosts) {
    if (!hosts.length) { out.innerHTML = ''; return; }
    let html = '';
    for (const [subnet, hs] of groupBySubnet(hosts)) {
      html += '<div class="lab-sub">' + esc(subnet) + ' <span class="lab-dim">(' + hs.length + ')</span></div>';
      for (const h of hs) {
        html += '<div class="nm-host">' +
          '<div class="nm-host-h"><code>' + esc(h.ip) + '</code>' +
          (h.hostname ? ' <span class="lab-dim">' + esc(h.hostname) + '</span>' : '') +
          (h.os ? ' <span class="nm-os">' + esc(h.os) + '</span>' : '') + '</div>';
        if (h.ports.length) {
          html += '<table class="lab-table"><tbody>' + h.ports.map(p => {
            const svc = [p.service, p.product, p.version].filter(Boolean).join(' ');
            return '<tr class="' + (isJuicy(p) ? 'nm-juicy' : '') + '"><td><code>' +
              p.port + '/' + esc(p.proto) + '</code></td><td>' + esc(svc || p.state) +
              (isJuicy(p) ? ' <span class="nm-star">⭐</span>' : '') + '</td></tr>';
          }).join('') + '</tbody></table>';
        } else {
          html += '<div class="lab-dim">sin puertos abiertos</div>';
        }
        html += '</div>';
      }
    }
    out.innerHTML = html;
  }

  if (typeof window !== 'undefined' && window.LAB) {
    LAB.registerTool({ id: 'netmap', label: 'Network Map', icon: '🗺', group: '🧪 LAB / TOOLS', render });
  }
  // Hook de test (no-op en browser).
  return { parseNmapXml, parseGnmap, parse, groupBySubnet, toMarkdown, toText, toJson, isJuicy };
})();
