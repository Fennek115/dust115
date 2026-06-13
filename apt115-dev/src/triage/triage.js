// APT115 CODEX ARCANUM — Static Malware Triage Lab
// quod est superius est sicut quod inferius
//
// Triage estático 100% client-side: el archivo se lee con FileReader y se
// procesa en el navegador. NADA se sube a ningún servidor. Orquesta los
// analyzers de analyzers.js y muestra cada uno en su panel.

if (typeof window !== 'undefined') window.Triage = window.Triage || {};

// Helper de copia compartido (lo usa el render de hashes)
Triage.copy = function (text) {
  try { navigator.clipboard.writeText(text); } catch (e) {}
  if (typeof showToast === 'function') showToast('✓ Copiado');
};

export const triage = (function () {
  'use strict';
  const U = Triage.util;
  const BIG = 64 * 1024 * 1024; // aviso por encima de 64 MB

  function render(container) {
    container.innerHTML =
      '<div class="sec-hdr"><div class="sec-title">🧪 Malware Triage</div>' +
      '<span class="sec-cmds-badge">static · local</span></div>' +
      '<div class="lab-intro">Análisis estático en el navegador. El archivo se procesa ' +
      '<b>100% local</b> — nada se sube ni se ejecuta. Ideal para triage rápido de un binario ' +
      'sospechoso sin tocar un sandbox.</div>' +
      '<div class="lab-drop" id="triageDrop" tabindex="0">' +
      '<div class="lab-drop-ic">⬡</div>' +
      '<div class="lab-drop-t">Arrastrá un archivo acá o hacé click para elegir</div>' +
      '<div class="lab-drop-s">PE/EXE/DLL, ELF, documentos, cualquier binario</div>' +
      '</div>' +
      '<input type="file" id="triageFile" style="display:none">' +
      '<div id="triageResults"></div>';

    const drop = container.querySelector('#triageDrop');
    const input = container.querySelector('#triageFile');

    drop.onclick = () => input.click();
    drop.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } };
    input.onchange = () => { if (input.files[0]) handleFile(input.files[0], container); };

    drop.ondragover = (e) => { e.preventDefault(); drop.classList.add('over'); };
    drop.ondragleave = () => drop.classList.remove('over');
    drop.ondrop = (e) => {
      e.preventDefault(); drop.classList.remove('over');
      const f = e.dataTransfer.files[0];
      if (f) handleFile(f, container);
    };
  }

  function handleFile(file, container) {
    const results = container.querySelector('#triageResults');
    // Soltar el archivo anterior ANTES de alocar el nuevo: los analyzers con
    // estado perezoso retienen ctx.bytes para sus botones, y sin esto un
    // archivo grande viejo queda vivo toda la sesión.
    Triage.analyzers.releaseAll();
    results.innerHTML = '<div class="lab-loading">⬡ Leyendo ' + U.esc(file.name) + ' …</div>';

    if (file.size > BIG) {
      results.innerHTML = '<div class="lab-note">⚠ Archivo grande (' + U.formatBytes(file.size) +
        '). El análisis puede tardar; algunos límites (strings) están acotados.</div>' +
        '<div class="lab-loading">⬡ Procesando …</div>';
    }

    const reader = new FileReader();
    reader.onerror = () => { results.innerHTML = '<div class="lab-err">No se pudo leer el archivo.</div>'; };
    reader.onload = (e) => {
      const bytes = new Uint8Array(e.target.result);
      analyze(file, bytes, results).catch(err => {
        console.error('[triage]', err);
        results.insertAdjacentHTML('beforeend', '<div class="lab-err">Error en el análisis: ' + U.esc(String(err)) + '</div>');
      });
    };
    reader.readAsArrayBuffer(file);
  }

  async function analyze(file, bytes, results) {
    const ctx = {
      bytes,
      dv: new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength),
      file: { name: file.name, size: file.size },
      pe: null,
      elf: null,
      macho: null,
      dotnet: null,
    };
    try { ctx.pe = Triage.pe.parse(bytes); }
    catch (e) { console.error('[triage] PE parse', e); }
    try { if (ctx.pe && Triage.dotnet) ctx.dotnet = Triage.dotnet.parse(ctx.pe, bytes); }
    catch (e) { console.error('[triage] .NET parse', e); }
    try { if (!ctx.pe && Triage.elf) ctx.elf = Triage.elf.parse(bytes); }
    catch (e) { console.error('[triage] ELF parse', e); }
    try { if (!ctx.pe && !ctx.elf && Triage.macho) ctx.macho = Triage.macho.parse(bytes); }
    catch (e) { console.error('[triage] Mach-O parse', e); }

    results.innerHTML = '';
    const analyzers = Triage.analyzers.all().filter(a => !a.applies || a.applies(ctx));

    for (const a of analyzers) {
      const panel = document.createElement('div');
      panel.className = 'lab-panel';
      panel.innerHTML =
        '<div class="lab-panel-h">' + (a.icon || '') + ' ' + U.esc(a.title) +
        '<span class="lab-panel-x">▾</span></div>' +
        '<div class="lab-panel-b"><span class="lab-dim">…</span></div>';
      results.appendChild(panel);

      const head = panel.querySelector('.lab-panel-h');
      const body = panel.querySelector('.lab-panel-b');
      head.onclick = () => panel.classList.toggle('collapsed');

      try {
        const out = await Promise.resolve(a.run(ctx));
        body.innerHTML = out;
      } catch (e) {
        console.error('[triage] analyzer', a.id, e);
        body.innerHTML = '<div class="lab-err">Falló el analyzer "' + U.esc(a.id) + '": ' + U.esc(String(e)) + '</div>';
      }
    }
  }

  // Registro en el LAB
  if (window.LAB) {
    LAB.registerTool({
      id: 'triage', label: 'Malware Triage', icon: '🧪', group: '🧪 LAB / TOOLS', render,
    });
  }
})();
