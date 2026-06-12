// APT115 CODEX ARCANUM — Triage analyzer: capa (capabilities, estilo Mandiant capa)
// solve et coagula
//
// "capa-lite": mapea CAPACIDADES del binario (qué puede hacer: inyección, persistencia,
// anti-análisis, C2, ransomware, robo de credenciales…) con tags ATT&CK/MBC. Inspirado en
// Mandiant capa (Apache-2.0), pero LIVIANO: matchea sólo sobre los **nombres de API
// importados** y los **strings** que el triage YA extrae — NO desensambla ni usa features
// de basic-block como el motor capa completo. Por eso es una HEURÍSTICA de orientación, no
// una identificación definitiva: cubre el grueso de las reglas que dependen de API+string,
// se queda corto en las que necesitan análisis de flujo. Cero data vendorizada, offline.
//
// Cada capacidad: { ns, name, attack?, mbc?, all:[clausula...] } donde una clausula es
//   { api:[base...] }  → matchea si alguno está entre los imports (A/W normalizados)
//   { str:[substr...] } → matchea si alguno aparece (case-insensitive) en los strings
// La capacidad matchea si TODAS sus clausulas matchean (AND de ORs).

if (typeof window !== 'undefined') window.Triage = window.Triage || {};

(function () {
  'use strict';

  function U() { return window.Triage.util; }
  function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

  // ── Base de capacidades (curada, estilo capa) ───────────────────────────────
  const CAPS = [
    // Anti-análisis
    { ns: 'anti-analysis/anti-debugging', name: 'check for debugger (API)', attack: 'T1622', mbc: 'B0001',
      all: [{ api: ['isdebuggerpresent', 'checkremotedebuggerpresent', 'ntqueryinformationprocess', 'outputdebugstring', 'ntsetinformationthread'] }] },
    { ns: 'anti-analysis/anti-debugging', name: 'debugger detection via ptrace (Linux)', attack: 'T1622',
      all: [{ api: ['ptrace'] }] },
    { ns: 'anti-analysis/anti-vm', name: 'reference VM/sandbox artifacts', attack: 'T1497',
      all: [{ str: ['vmware', 'virtualbox', 'vbox', 'qemu', 'vmtoolsd', 'sbiedll', 'sandboxie', 'wine_get_unix', 'xen'] }] },
    { ns: 'anti-analysis/anti-vm', name: 'query CPUID / hypervisor', attack: 'T1497.001',
      all: [{ str: ['hypervisor', 'cpuid', 'systembiosversion', 'vbox', 'virtual'] }, { api: ['regopenkeyex', 'reggetvalue', 'regqueryvalueex'] }] },
    { ns: 'anti-analysis/timing', name: 'timing check (tick count / perf counter)', attack: 'T1497.003',
      // Sleep solo es demasiado común → exige contadores de timing específicos.
      all: [{ api: ['gettickcount', 'queryperformancecounter', 'ntdelayexecution', 'rdtsc'] }] },

    // Inyección de código
    { ns: 'host-interaction/process/inject', name: 'remote thread injection', attack: 'T1055.002', mbc: 'E1055.m01',
      all: [{ api: ['virtualallocex', 'ntallocatevirtualmemory'] }, { api: ['writeprocessmemory'] }, { api: ['createremotethread', 'ntcreatethreadex', 'rtlcreateuserthread'] }] },
    { ns: 'host-interaction/process/inject', name: 'APC injection', attack: 'T1055.004', mbc: 'E1055.m04',
      all: [{ api: ['queueuserapc', 'ntqueueapcthread'] }] },
    { ns: 'host-interaction/process/inject', name: 'process hollowing', attack: 'T1055.012', mbc: 'E1055.m07',
      all: [{ api: ['ntunmapviewofsection', 'zwunmapviewofsection'] }, { api: ['setthreadcontext', 'getthreadcontext', 'resumethread'] }] },
    { ns: 'host-interaction/process/inject', name: 'section mapping injection', attack: 'T1055',
      all: [{ api: ['ntmapviewofsection', 'ntcreatesection'] }, { api: ['writeprocessmemory', 'ntwritevirtualmemory'] }] },
    { ns: 'host-interaction/process/inject', name: 'set windows hook (injection/keylog)', attack: 'T1056.001',
      all: [{ api: ['setwindowshookex'] }] },

    // Persistencia
    { ns: 'persistence/registry', name: 'persist via Run key', attack: 'T1547.001', mbc: 'F0012',
      all: [{ api: ['regsetvalueex', 'regcreatekeyex'] }, { str: ['currentversion\\run', 'currentversion\\\\run', '\\run', 'runonce'] }] },
    { ns: 'persistence/service', name: 'create or modify Windows service', attack: 'T1543.003', mbc: 'F0011',
      all: [{ api: ['createservice', 'openscmanager', 'startservice', 'changeserviceconfig'] }] },
    { ns: 'persistence/scheduled-task', name: 'schedule task', attack: 'T1053.005',
      all: [{ str: ['schtasks', '\\tasks\\', 'taskschd', 'itaskscheduler', 'itasksettings'] }] },
    { ns: 'persistence/startup-folder', name: 'persist via startup folder', attack: 'T1547.001',
      all: [{ str: ['\\start menu\\programs\\startup', 'startup\\'] }] },
    { ns: 'persistence/cron', name: 'persist via cron / init (Linux)', attack: 'T1053.003',
      // Strings específicos de escritura de persistencia (evitar .bashrc/systemctl genéricos).
      all: [{ str: ['crontab -', '/etc/cron.d', '/var/spool/cron', '/etc/init.d/', 'update-rc.d', '/etc/rc.local'] }] },

    // Evasión de defensas
    { ns: 'defense-evasion/amsi-etw', name: 'tamper with AMSI / ETW', attack: 'T1562.001',
      all: [{ str: ['amsi.dll', 'amsiscanbuffer', 'etweventwrite', 'amsiopensession'] }] },
    { ns: 'defense-evasion/inhibit-recovery', name: 'delete volume shadow copies', attack: 'T1490', mbc: 'F0014',
      all: [{ str: ['vssadmin', 'wbadmin', 'bcdedit', 'wmic shadowcopy', 'delete shadows'] }] },
    { ns: 'defense-evasion/clear-logs', name: 'clear event logs', attack: 'T1070.001',
      all: [{ api: ['cleareventlog', 'openeventlog'] }] },
    { ns: 'defense-evasion/disable-tools', name: 'disable security tools / firewall', attack: 'T1562.004',
      all: [{ str: ['netsh advfirewall', 'netsh firewall', 'defender', 'set-mppreference', 'disablerealtimemonitoring'] }] },

    // Acceso a credenciales
    { ns: 'collection/credential-access', name: 'access LSASS memory', attack: 'T1003.001', mbc: 'E1003',
      all: [{ api: ['readprocessmemory', 'minidumpwritedump'] }, { str: ['lsass'] }] },
    { ns: 'collection/credential-access', name: 'dump credentials (MiniDump)', attack: 'T1003',
      all: [{ api: ['minidumpwritedump'] }] },
    { ns: 'collection/credential-access', name: 'access SAM / registry hives', attack: 'T1003.002',
      all: [{ str: ['\\sam', 'reg save', 'system32\\config', 'hklm\\sam'] }] },
    { ns: 'collection/credential-access', name: 'enumerate stored credentials', attack: 'T1555',
      all: [{ api: ['credenumerate', 'credread', 'cryptunprotectdata'] }] },
    { ns: 'collection/credential-access', name: 'browser credential paths', attack: 'T1555.003',
      all: [{ str: ['login data', '\\google\\chrome\\', 'cookies.sqlite', 'logins.json', 'key4.db', 'signons'] }] },

    // Descubrimiento
    { ns: 'discovery/system-info', name: 'gather system information', attack: 'T1082',
      all: [{ api: ['getcomputername', 'getsysteminfo', 'getversionex', 'getnativesysteminfo', 'gethostname', 'uname'] }] },
    { ns: 'discovery/user', name: 'get current user', attack: 'T1033',
      all: [{ api: ['getusername', 'lookupaccountname', 'getuserprofiledirectory', 'getpwuid', 'getlogin'] }] },
    { ns: 'discovery/recon-commands', name: 'run reconnaissance commands', attack: 'T1059',
      all: [{ str: ['whoami', 'systeminfo', 'ipconfig', 'net view', 'net user', 'tasklist', 'arp -a', 'nltest'] }] },
    { ns: 'discovery/security-products', name: 'enumerate processes', attack: 'T1057',
      all: [{ api: ['createtoolhelp32snapshot', 'process32first', 'process32next', 'enumprocesses'] }] },

    // Red / C2
    { ns: 'communication/http', name: 'HTTP communication (WinINet/WinHTTP)', attack: 'T1071.001', mbc: 'C0002',
      all: [{ api: ['internetopen', 'internetopenurl', 'httpopenrequest', 'httpsendrequest', 'winhttpopen', 'winhttpconnect', 'winhttpsendrequest', 'urldownloadtofile'] }] },
    { ns: 'communication/socket', name: 'TCP/IP socket communication', attack: 'T1095', mbc: 'C0001',
      all: [{ api: ['socket', 'connect', 'send', 'recv', 'wsastartup', 'wsasocket'] }] },
    { ns: 'communication/dns', name: 'resolve DNS', attack: 'T1071.004',
      all: [{ api: ['dnsquery', 'getaddrinfo', 'gethostbyname'] }] },
    { ns: 'communication/c2-url', name: 'embedded URL + network capability', attack: 'T1071',
      // Una URL sola es ruido (URLs de licencia). Atarla a una API de red real.
      all: [{ str: ['http://', 'https://', 'user-agent:', 'mozilla/'] },
        { api: ['socket', 'connect', 'internetopen', 'winhttpopen', 'wsastartup', 'urldownloadtofile', 'send'] }] },
    { ns: 'communication/download', name: 'download and execute', attack: 'T1105', mbc: 'C0040',
      all: [{ api: ['urldownloadtofile', 'internetreadfile', 'winhttpreaddata'] }, { api: ['winexec', 'createprocess', 'shellexecute'] }] },

    // Ejecución
    { ns: 'execution/command', name: 'execute via command shell', attack: 'T1059.003',
      all: [{ api: ['winexec', 'createprocess', 'shellexecute', 'system', 'popen', 'execve', 'execl'] }] },
    { ns: 'execution/wmi', name: 'execute via WMI', attack: 'T1047',
      all: [{ str: ['root\\cimv2', 'win32_process', 'wbemscripting', 'iwbemservices'] }] },
    { ns: 'execution/powershell', name: 'invoke PowerShell', attack: 'T1059.001',
      all: [{ str: ['powershell', '-encodedcommand', '-nop ', 'invoke-expression', 'iex(', 'frombase64string'] }] },
    { ns: 'execution/com', name: 'create COM object', attack: 'T1559.001',
      all: [{ api: ['cocreateinstance', 'coinitialize', 'cogetclassobject'] }] },

    // Captura / colección
    { ns: 'collection/keylog', name: 'log keystrokes', attack: 'T1056.001', mbc: 'E1056',
      all: [{ api: ['getasynckeystate', 'getkeystate', 'getkeyboardstate', 'registerrawinputdevices'] }] },
    { ns: 'collection/screenshot', name: 'capture screenshot', attack: 'T1113', mbc: 'E1113',
      all: [{ api: ['bitblt', 'getdc', 'createcompatiblebitmap', 'getdesktopwindow'] }] },
    { ns: 'collection/clipboard', name: 'access clipboard data', attack: 'T1115',
      all: [{ api: ['getclipboarddata', 'openclipboard', 'setclipboarddata'] }] },
    { ns: 'collection/audio', name: 'capture audio', attack: 'T1123',
      all: [{ api: ['waveinopen', 'waveinstart', 'mcisendstring'] }] },

    // Cripto / ransomware / impacto
    { ns: 'data-manipulation/encryption', name: 'encrypt data (CryptoAPI)', attack: 'T1486', mbc: 'C0027',
      all: [{ api: ['cryptencrypt', 'cryptgenkey', 'cryptderivekey', 'bcryptencrypt', 'cryptacquirecontext'] }] },
    { ns: 'impact/ransomware', name: 'ransomware behavior (encrypt + enum files)', attack: 'T1486',
      all: [{ api: ['findfirstfile', 'findnextfile'] }, { api: ['cryptencrypt', 'bcryptencrypt', 'cryptgenkey'] }] },
    { ns: 'impact/ransom-note', name: 'reference ransom note / payment', attack: 'T1486',
      all: [{ str: ['your files have been encrypted', 'bitcoin', 'decrypt', 'ransom', 'tor browser', '.onion'] }] },

    // Privilegios
    { ns: 'privilege-escalation/token', name: 'adjust token privileges', attack: 'T1134',
      all: [{ api: ['adjusttokenprivileges', 'openprocesstoken', 'lookupprivilegevalue'] }] },
    { ns: 'privilege-escalation/uac', name: 'bypass UAC', attack: 'T1548.002',
      all: [{ str: ['eventvwr', 'fodhelper', 'computerdefaults', 'sdclt', 'ms-settings\\shell\\open'] }] },

    // Resolución dinámica de APIs (evasión común en packers/loaders)
    { ns: 'anti-analysis/api-resolution', name: 'dynamically resolve APIs', attack: 'T1027.007', mbc: 'B0032',
      all: [{ api: ['loadlibrary', 'getprocaddress', 'ldrgetprocedureaddress', 'dlopen', 'dlsym'] }] },

    // Loader: cambia permisos de memoria + resuelve APIs en runtime (patrón de
    // shellcode/packer). VirtualAlloc solo es ubicuo, así que se exige la combinación.
    { ns: 'host-interaction/process/memory', name: 'change memory protection for execution', attack: 'T1055',
      all: [{ api: ['virtualprotect', 'ntprotectvirtualmemory', 'mprotect'] }, { api: ['loadlibrary', 'getprocaddress', 'dlopen', 'dlsym'] }] },
  ];

  // ── Recolección de features ─────────────────────────────────────────────────
  function normApi(name) {
    // base + variante sin sufijo A/W (CreateFileA → createfile)
    const lo = String(name).toLowerCase();
    const out = [lo];
    if (lo.length > 4 && (lo.endsWith('a') || lo.endsWith('w'))) out.push(lo.slice(0, -1));
    if (lo.startsWith('nt') || lo.startsWith('zw')) out.push('nt' + lo.slice(2), 'zw' + lo.slice(2)); // Nt/Zw alias
    return out;
  }

  function gatherApis(ctx) {
    const set = new Set();
    const add = (n) => { if (n) normApi(n).forEach(x => set.add(x)); };
    if (ctx.pe && ctx.pe.imports) for (const imp of ctx.pe.imports) for (const f of imp.funcs) add(f.name);
    if (ctx.elf && ctx.elf.imports) for (const n of ctx.elf.imports) add(n);
    if (ctx.elf && ctx.elf.exports) for (const n of ctx.elf.exports) add(n);
    return set;
  }

  function gatherStrings(ctx) {
    const res = U().extractStrings(ctx.bytes, 4, 20000);
    let blob = '';
    for (const s of res.strings) blob += s.s + '\n';
    return blob.toLowerCase();
  }

  // ── Evaluación ──────────────────────────────────────────────────────────────
  function evalClause(cl, apis, strBlob) {
    if (cl.api) { const hit = cl.api.filter(a => apis.has(a)); return hit.length ? { ok: true, ev: hit, kind: 'api' } : { ok: false }; }
    if (cl.str) { const hit = cl.str.filter(s => strBlob.indexOf(s) >= 0); return hit.length ? { ok: true, ev: hit, kind: 'str' } : { ok: false }; }
    return { ok: false };
  }

  function run(ctx) {
    const apis = gatherApis(ctx);
    const strBlob = gatherStrings(ctx);
    if (!apis.size && !strBlob) return '<div class="lab-note">Sin imports ni strings para evaluar capacidades.</div>';

    const matched = [];
    for (const cap of CAPS) {
      const evid = [];
      let all = true;
      for (const cl of cap.all) {
        const r = evalClause(cl, apis, strBlob);
        if (!r.ok) { all = false; break; }
        evid.push(r);
      }
      if (all) matched.push({ cap, evid });
    }

    let html = '<div class="lab-row1">Capacidades inferidas estilo <b>capa</b> sobre ' +
      apis.size + ' APIs + strings. <span class="lab-dim">Heurística liviana (imports+strings, sin desensamblado) — ' +
      'orienta, no confirma. Inspirado en Mandiant capa.</span></div>';

    if (!matched.length) return html + '<div class="lab-note">Ninguna capacidad de la base matcheó. ' +
      'Ausencia de evidencia ≠ inocuidad (un binario packed expone pocos imports/strings).</div>';

    // Resumen ATT&CK
    const attacks = [...new Set(matched.map(m => m.cap.attack).filter(Boolean))].sort();
    html += '<div class="lab-sub">ATT&CK (' + attacks.length + ')</div><div class="lab-badges">' +
      attacks.map(a => '<span class="lab-mit off" style="cursor:default">' + esc(a) + '</span>').join('') + '</div>';

    // Agrupar por namespace top-level
    const groups = {};
    for (const m of matched) { const top = m.cap.ns.split('/')[0]; (groups[top] = groups[top] || []).push(m); }
    for (const g of Object.keys(groups).sort()) {
      html += '<div class="lab-sub">' + esc(g) + ' (' + groups[g].length + ')</div>';
      for (const m of groups[g]) {
        const tags = [m.cap.attack && ('ATT&CK ' + m.cap.attack), m.cap.mbc && ('MBC ' + m.cap.mbc)].filter(Boolean).join(' · ');
        const ev = m.evid.map(e => e.ev.slice(0, 4).map(x => '<span class="lab-imp' + (e.kind === 'str' ? '' : ' ') + '">' + esc(x) + '</span>').join('')).join('');
        html += '<div class="lab-str" style="flex-direction:column;align-items:flex-start;gap:3px">' +
          '<div><b>' + esc(m.cap.name) + '</b> <span class="lab-dim">' + esc(m.cap.ns) + (tags ? ' · ' + esc(tags) : '') + '</span></div>' +
          '<div class="lab-imps" style="margin:0">' + ev + '</div></div>';
      }
    }
    return html;
  }

  const Tri = (typeof window !== 'undefined' && window.Triage) || null;
  if (Tri && Tri.analyzers) {
    Tri.analyzers.register({
      id: 'capa', title: 'Capabilities (capa-lite)', icon: '🧠',
      applies(ctx) { return !!(ctx.pe || ctx.elf); },
      run(ctx) { return run(ctx); },
    });
  }

  if (typeof module !== 'undefined' && module.exports) module.exports = { CAPS, normApi, evalClause, run, gatherApis, gatherStrings };
})();
