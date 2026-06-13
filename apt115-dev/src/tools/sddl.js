// APT115 CODEX ARCANUM — SID / SDDL decoder
// quod est superius est sicut quod inferius
//
// Decodifica identificadores de seguridad de Windows/AD:
//  - SID (S-1-5-…): nombre well-known, autoridad, dominio y RID, con la tabla
//    de SIDs y RIDs de dominio conocidos (MS-DTYP, datos públicos).
//  - SDDL (O:…G:…D:…S:…): owner/group + DACL/SACL → cada ACE desglosado
//    (tipo, flags de herencia, derechos de acceso, trustee), resolviendo los
//    alias de SID de 2 letras (BA, SY, WD…). 100% local, sin red.

export const sddl = (function () {
  'use strict';

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // ── SID ────────────────────────────────────────────────────────────────
  const AUTHORITIES = {
    '0': 'Null Authority', '1': 'World Authority', '2': 'Local Authority',
    '3': 'Creator Authority', '4': 'Non-unique Authority', '5': 'NT Authority',
    '15': 'AAD Authority', '16': 'Mandatory Label Authority',
  };
  // SIDs completos well-known.
  const WELL_KNOWN = {
    'S-1-0-0': 'Nobody', 'S-1-1-0': 'Everyone', 'S-1-2-0': 'Local',
    'S-1-2-1': 'Console Logon', 'S-1-3-0': 'Creator Owner', 'S-1-3-1': 'Creator Group',
    'S-1-3-4': 'Owner Rights', 'S-1-5-1': 'Dialup', 'S-1-5-2': 'Network',
    'S-1-5-3': 'Batch', 'S-1-5-4': 'Interactive', 'S-1-5-6': 'Service',
    'S-1-5-7': 'Anonymous', 'S-1-5-9': 'Enterprise Domain Controllers',
    'S-1-5-10': 'Principal Self', 'S-1-5-11': 'Authenticated Users',
    'S-1-5-12': 'Restricted Code', 'S-1-5-13': 'Terminal Server Users',
    'S-1-5-14': 'Remote Interactive Logon', 'S-1-5-15': 'This Organization',
    'S-1-5-17': 'IUSR', 'S-1-5-18': 'Local System (SYSTEM)',
    'S-1-5-19': 'Local Service', 'S-1-5-20': 'Network Service',
    'S-1-5-32-544': 'BUILTIN\\Administrators', 'S-1-5-32-545': 'BUILTIN\\Users',
    'S-1-5-32-546': 'BUILTIN\\Guests', 'S-1-5-32-547': 'BUILTIN\\Power Users',
    'S-1-5-32-548': 'BUILTIN\\Account Operators', 'S-1-5-32-549': 'BUILTIN\\Server Operators',
    'S-1-5-32-550': 'BUILTIN\\Print Operators', 'S-1-5-32-551': 'BUILTIN\\Backup Operators',
    'S-1-5-32-552': 'BUILTIN\\Replicator', 'S-1-5-32-554': 'BUILTIN\\Pre-Windows 2000 Compatible Access',
    'S-1-5-32-555': 'BUILTIN\\Remote Desktop Users', 'S-1-5-32-556': 'BUILTIN\\Network Configuration Operators',
    'S-1-5-32-559': 'BUILTIN\\Performance Log Users', 'S-1-5-32-562': 'BUILTIN\\Distributed COM Users',
    'S-1-5-32-568': 'BUILTIN\\IIS_IUSRS', 'S-1-5-32-569': 'BUILTIN\\Cryptographic Operators',
    'S-1-5-32-573': 'BUILTIN\\Event Log Readers', 'S-1-5-32-578': 'BUILTIN\\Hyper-V Administrators',
    'S-1-5-32-579': 'BUILTIN\\Access Control Assistance Operators', 'S-1-5-32-580': 'BUILTIN\\Remote Management Users',
  };
  // RIDs de dominio (S-1-5-21-<dominio>-<RID>).
  const DOMAIN_RIDS = {
    '500': 'Administrator', '501': 'Guest', '502': 'krbtgt', '512': 'Domain Admins',
    '513': 'Domain Users', '514': 'Domain Guests', '515': 'Domain Computers',
    '516': 'Domain Controllers', '517': 'Cert Publishers', '518': 'Schema Admins',
    '519': 'Enterprise Admins', '520': 'Group Policy Creator Owners', '521': 'Read-only Domain Controllers',
    '522': 'Cloneable Domain Controllers', '525': 'Protected Users', '526': 'Key Admins',
    '527': 'Enterprise Key Admins', '553': 'RAS and IAS Servers', '571': 'Allowed RODC Password Replication Group',
    '572': 'Denied RODC Password Replication Group',
  };

  /** Decodifica un SID textual. @param {string} sidStr */
  function decodeSid(sidStr) {
    const sid = String(sidStr == null ? '' : sidStr).trim();
    const m = /^S-(\d+)-(\d+)((?:-\d+)*)$/i.exec(sid);
    if (!m) return { ok: false, error: 'No es un SID válido (formato S-R-IA-SA…).' };
    const revision = +m[1];
    const authId = m[2];
    const subs = m[3] ? m[3].slice(1).split('-') : [];
    const canon = 'S-' + revision + '-' + authId + (subs.length ? '-' + subs.join('-') : '');
    let name = WELL_KNOWN[canon] || null;
    let kind = name ? 'well-known' : null;
    let rid = subs.length ? subs[subs.length - 1] : null;
    let domain = null;
    // Dominio: S-1-5-21-X-Y-Z-RID
    if (!name && authId === '5' && subs[0] === '21' && subs.length >= 5) {
      domain = 'S-1-5-21-' + subs.slice(1, -1).join('-');
      const rn = DOMAIN_RIDS[rid];
      name = rn ? ('DOMAIN\\' + rn) : ('DOMAIN principal (RID ' + rid + ')');
      kind = rn ? 'domain well-known RID' : 'domain object';
    }
    return {
      ok: true, sid: canon, revision, authority: AUTHORITIES[authId] || ('Authority ' + authId),
      authorityId: authId, subAuthorities: subs, rid, domain,
      name: name || '(SID no reconocido)', category: kind || 'desconocido',
    };
  }

  // ── SDDL ────────────────────────────────────────────────────────────────
  const SID_ALIAS = {
    AO: 'Account Operators', AN: 'Anonymous', AU: 'Authenticated Users', BA: 'BUILTIN\\Administrators',
    BG: 'BUILTIN\\Guests', BO: 'Backup Operators', BU: 'BUILTIN\\Users', CA: 'Cert Publishers',
    CG: 'Creator Group', CO: 'Creator Owner', DA: 'Domain Admins', DC: 'Domain Computers',
    DD: 'Domain Controllers', DG: 'Domain Guests', DU: 'Domain Users', EA: 'Enterprise Admins',
    ED: 'Enterprise Domain Controllers', WD: 'Everyone (World)', PA: 'Group Policy Admins',
    IU: 'Interactive Users', LA: 'Local Administrator', LG: 'Local Guest', LS: 'Local Service',
    SY: 'Local System (SYSTEM)', NU: 'Network', NO: 'Network Config Operators', NS: 'Network Service',
    PO: 'Print Operators', PS: 'Principal Self', PU: 'Power Users', RS: 'RAS Servers',
    RD: 'Remote Desktop Users', RE: 'Replicator', RC: 'Restricted Code', SA: 'Schema Admins',
    SO: 'Server Operators', SU: 'Service', RU: 'Pre-Windows 2000 Compatible Access',
    LW: 'Low Integrity', ME: 'Medium Integrity', HI: 'High Integrity', SI: 'System Integrity',
    AC: 'All Application Packages', RM: 'Remote Management Users',
  };
  const ACE_TYPE = {
    A: 'Access Allowed', D: 'Access Denied', OA: 'Object Access Allowed', OD: 'Object Access Denied',
    AU: 'System Audit', AL: 'System Alarm', OU: 'Object Audit', OL: 'Object Alarm',
    ML: 'Mandatory Label', XA: 'Callback Access Allowed', XD: 'Callback Access Denied',
    ZA: 'Callback Object Access Allowed', SP: 'Scoped Policy ID',
  };
  const ACE_FLAG = {
    CI: 'Container Inherit', OI: 'Object Inherit', NP: 'No Propagate', IO: 'Inherit Only',
    ID: 'Inherited', SA: 'Audit Success', FA: 'Audit Failure', CR: 'Critical',
  };
  const ACL_FLAG = { P: 'Protected', AR: 'Auto-inherit Required', AI: 'Auto-inherited', NO: 'Null ACL' };
  const RIGHTS = {
    GA: 'GENERIC_ALL', GR: 'GENERIC_READ', GW: 'GENERIC_WRITE', GX: 'GENERIC_EXECUTE',
    RC: 'READ_CONTROL', SD: 'DELETE', WD: 'WRITE_DAC', WO: 'WRITE_OWNER',
    FA: 'FILE_ALL_ACCESS', FR: 'FILE_GENERIC_READ', FW: 'FILE_GENERIC_WRITE', FX: 'FILE_GENERIC_EXECUTE',
    KA: 'KEY_ALL_ACCESS', KR: 'KEY_READ', KW: 'KEY_WRITE', KX: 'KEY_EXECUTE',
    CC: 'CREATE_CHILD', DC: 'DELETE_CHILD', LC: 'LIST_CHILDREN', SW: 'SELF_WRITE',
    RP: 'READ_PROPERTY', WP: 'WRITE_PROPERTY', DT: 'DELETE_TREE', LO: 'LIST_OBJECT', CR: 'CONTROL_ACCESS',
  };

  function tok2(s) { const o = []; for (let i = 0; i + 1 < (s || '').length + 1; i += 2) { const t = (s || '').substr(i, 2); if (t.length === 2) o.push(t); } return o; }

  function aclFlags(s) {
    const out = []; let i = 0; s = s || '';
    while (i < s.length) {
      const two = s.substr(i, 2);
      if (ACL_FLAG[two]) { out.push(ACL_FLAG[two]); i += 2; }
      else if (ACL_FLAG[s[i]]) { out.push(ACL_FLAG[s[i]]); i += 1; }
      else i += 1;
    }
    return out;
  }

  function decodeSddlSid(tok) {
    const t = String(tok || '').trim();
    if (!t) return { raw: '', name: '(vacío)' };
    if (SID_ALIAS[t]) return { raw: t, alias: t, name: SID_ALIAS[t] };
    if (/^S-/i.test(t)) { const d = decodeSid(t); return { raw: t, name: d.ok ? d.name : t, sid: d.ok ? d.sid : t }; }
    return { raw: t, name: t };
  }

  function parseRights(s) {
    s = String(s || '').trim();
    if (!s) return { raw: '', names: [] };
    if (/^0x/i.test(s)) return { raw: s, hex: s, names: ['máscara ' + s] };
    return { raw: s, names: tok2(s).map(t => RIGHTS[t] || ('?' + t)) };
  }

  function parseAce(body) {
    const p = String(body).split(';');
    return {
      raw: body,
      typeRaw: p[0] || '', type: ACE_TYPE[p[0]] || p[0] || '',
      flags: tok2(p[1] || '').map(f => ACE_FLAG[f] || f),
      rights: parseRights(p[2] || ''),
      objectGuid: p[3] || '', inheritGuid: p[4] || '',
      trustee: decodeSddlSid(p[5] || ''),
      condition: p.slice(6).join(';') || '',
    };
  }

  function parseAcl(str) {
    if (str == null) return null;
    const fm = /^([A-Za-z]*)/.exec(str);
    const flagsRaw = fm ? fm[1] : '';
    const aces = [];
    const re = /\(([^)]*)\)/g; let m;
    while ((m = re.exec(str))) aces.push(parseAce(m[1]));
    return { flagsRaw, flags: aclFlags(flagsRaw), aces };
  }

  // Separa O:/G:/D:/S: respetando los paréntesis de las ACEs.
  function splitSections(s) {
    const marks = []; let depth = 0;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === '(') depth++;
      else if (c === ')') depth = Math.max(0, depth - 1);
      else if (depth === 0 && 'OGDS'.indexOf(c) >= 0 && s[i + 1] === ':') marks.push(i);
    }
    const out = {};
    for (let k = 0; k < marks.length; k++) {
      const start = marks[k], end = k + 1 < marks.length ? marks[k + 1] : s.length;
      out[s[start]] = s.slice(start + 2, end);
    }
    return out;
  }

  /** Parsea un descriptor SDDL. @param {string} str */
  function parseSddl(str) {
    const s = String(str == null ? '' : str).trim();
    if (!/[OGDS]:/.test(s)) return { ok: false, error: 'No parece SDDL (falta O:/G:/D:/S:).' };
    const sec = splitSections(s);
    return {
      ok: true,
      owner: sec.O != null ? decodeSddlSid(sec.O) : null,
      group: sec.G != null ? decodeSddlSid(sec.G) : null,
      dacl: sec.D != null ? parseAcl(sec.D) : null,
      sacl: sec.S != null ? parseAcl(sec.S) : null,
    };
  }

  /** Autodetecta SID vs SDDL y decodifica. @param {string} input */
  function decode(input) {
    const s = String(input == null ? '' : input).trim();
    if (!s) return { ok: false, error: 'Pegá un SID o un descriptor SDDL.' };
    if (/[OGDS]:/.test(s) && !/^S-1-/i.test(s)) return { kind: 'sddl', ...parseSddl(s) };
    return { kind: 'sid', ...decodeSid(s) };
  }

  // ── Render ────────────────────────────────────────────────────────────
  function render(container) {
    container.innerHTML =
      '<div class="lab-sec">' +
      '<div class="lab-intro"><b>SID / SDDL decoder.</b> Pegá un <b>SID</b> (<code>S-1-5-32-544</code>) ' +
      'o un descriptor <b>SDDL</b> (<code>O:BAG:DUD:(A;;FA;;;SY)</code>) y lo desarmo: nombre well-known, ' +
      'dominio/RID, y cada ACE (tipo, herencia, derechos, trustee). Todo local.</div>' +
      '<textarea id="sdIn" class="cv-io" spellcheck="false" style="min-height:70px" ' +
      'placeholder="S-1-5-21-3623811015-3361044348-30300820-1013   ó   O:BAG:DUD:(A;;FA;;;SY)(A;OICI;FA;;;BA)"></textarea>' +
      '<div class="x5-actions"><button id="sdGo" class="cv-btn">Decodificar</button></div>' +
      '<div id="sdOut"></div></div>';
    const out = container.querySelector('#sdOut');
    container.querySelector('#sdGo').onclick = () => renderOut(out, decode(container.querySelector('#sdIn').value));
  }

  function sidRow(label, d) {
    if (!d) return '';
    return '<tr><th>' + esc(label) + '</th><td>' + esc(d.name) + (d.alias ? ' <span class="x5-tag">' + esc(d.alias) + '</span>' : '') + '</td></tr>';
  }

  function aclHtml(title, acl) {
    if (!acl) return '';
    let html = '<div class="lab-panel"><div class="lab-panel-h" onclick="this.parentElement.classList.toggle(\'collapsed\')">' +
      '<span>' + esc(title) + ' (' + acl.aces.length + ' ACE' + (acl.aces.length === 1 ? '' : 's') + ')</span>' +
      '<span class="lab-panel-x">▾</span></div><div class="lab-panel-b">';
    if (acl.flags.length) html += '<div class="lab-note">Flags: ' + acl.flags.map(esc).join(', ') + '</div>';
    html += '<table class="lab-table"><thead><tr><th>Tipo</th><th>Herencia</th><th>Derechos</th><th>Trustee</th></tr></thead><tbody>' +
      acl.aces.map(a => '<tr><td>' + esc(a.type) + '</td>' +
        '<td>' + (a.flags.length ? esc(a.flags.join(', ')) : '—') + '</td>' +
        '<td>' + esc(a.rights.names.join(', ') || '—') + '</td>' +
        '<td>' + esc(a.trustee.name) + (a.trustee.alias ? ' <span class="x5-tag">' + esc(a.trustee.alias) + '</span>' : '') + '</td></tr>').join('') +
      '</tbody></table></div></div>';
    return html;
  }

  function renderOut(out, res) {
    if (res.ok === false) { out.innerHTML = '<div class="lab-note">' + esc(res.error) + '</div>'; return; }
    if (res.kind === 'sid') {
      out.innerHTML = '<div class="lab-panel"><div class="lab-panel-h">' +
        '<span>🪪 SID — ' + esc(res.name) + '</span></div><div class="lab-panel-b"><table class="lab-kv"><tbody>' +
        '<tr><th>SID</th><td><code>' + esc(res.sid) + '</code></td></tr>' +
        '<tr><th>Nombre</th><td>' + esc(res.name) + '</td></tr>' +
        '<tr><th>Clase</th><td>' + esc(res.category) + '</td></tr>' +
        '<tr><th>Autoridad</th><td>' + esc(res.authority) + '</td></tr>' +
        (res.domain ? '<tr><th>Dominio</th><td><code>' + esc(res.domain) + '</code></td></tr>' : '') +
        (res.rid ? '<tr><th>RID</th><td>' + esc(res.rid) + '</td></tr>' : '') +
        '</tbody></table></div></div>';
      return;
    }
    let html = '<div class="lab-panel"><div class="lab-panel-h"><span>🛡 Descriptor SDDL</span></div>' +
      '<div class="lab-panel-b"><table class="lab-kv"><tbody>' +
      sidRow('Owner', res.owner) + sidRow('Group', res.group) + '</tbody></table></div></div>';
    html += aclHtml('🔐 DACL', res.dacl);
    html += aclHtml('📝 SACL', res.sacl);
    out.innerHTML = html;
  }

  if (typeof window !== 'undefined' && window.LAB) {
    window.LAB.registerTool({ id: 'sddl', label: 'SID / SDDL', icon: '🪪', group: '🧪 LAB / TOOLS', render });
  }
  return { decodeSid, parseSddl, decodeSddlSid, decode };
})();
