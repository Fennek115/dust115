// APT115 CODEX ARCANUM — Triage analyzer: epdisasm (desensamblado del entry point)
// solve et coagula
//
// Desensambla las primeras instrucciones desde el ENTRY POINT del binario (PE/ELF)
// reusando el servicio compartido LAB.capstone. Se ubica después de `peid`: si PEiD
// matcheó un packer/compilador, acá se lee el código real del EP.
//
// LÍMITE HONESTO: es barrido lineal estático. Frente a anti-desensamblado (bytes
// basura tras un salto, instrucciones solapadas) o packing/cifrado, el EP no es
// representativo. El analyzer NO desempaca (restricción dura: nada se ejecuta) —
// detecta y deriva:
//   · guardia de entropía  → EP en región de alta entropía: probablemente packed.
//   · desincronización      → se frena en bytes inválidos muy temprano: anti-disasm.
//   · re-sync manual (±N)   → contra el truco del byte basura: corré el arranque.
//   · seguir el primer salto → jmp/call resoluble (p.ej. el jmp a la OEP de UPX).
//
// El motor (~1.8 MB) se carga PEREZOSAMENTE recién al apretar "desensamblar", no en
// cada triage. Interactividad: igual que el analyzer YARA — el run() devuelve HTML
// con botones inline que entran por window.Triage.epdisasm y ubican el panel con
// closest('.lab-panel-b'); el ctx vive en lastCtx.

if (typeof window !== 'undefined') window.Triage = window.Triage || {};

export const epdisasm = (function () {
  'use strict';

  const WINDOW_BYTES = 4096; // tope de bytes que tomamos desde el EP
  const DEFAULT_COUNT = 40;  // instrucciones a mostrar por default
  const HI_ENTROPY = 7.0;    // umbral de "región probablemente packed/cifrada"
  const DESYNC_EARLY = 8;    // bytes: frenar antes de esto ⇒ sospecha de anti-disasm

  // Capstone es opcional en build-time (el <script> del core viene antes en
  // index.html); lo resolvemos perezoso por si el orden cambia.
  function CS() { return (window.LAB && window.LAB.capstone) || null; }

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
  function hx(n) { return '0x' + (n >>> 0 === n ? n : Number(n)).toString(16); }

  // Entropía de Shannon (0..8 bits/byte) sobre una vista de bytes.
  function shannon(view) {
    if (!view.length) return 0;
    const freq = new Uint32Array(256);
    for (let i = 0; i < view.length; i++) freq[view[i]]++;
    let h = 0;
    for (let i = 0; i < 256; i++) {
      if (!freq[i]) continue;
      const p = freq[i] / view.length;
      h -= p * Math.log2(p);
    }
    return h;
  }

  // vaddr → offset de archivo, reconstruido desde lo que YA exponen los parsers
  // (no toca pe.js/elf.js). PE: vía secciones + imageBase. ELF: vía segmentos LOAD.
  function vaddrToOffset(ctx, va) {
    if (ctx.pe) {
      const base = (ctx.pe.optional && ctx.pe.optional.imageBase) || 0;
      const rva = va - base;
      for (const s of ctx.pe.sections) {
        const span = Math.max(s.vsize || 0, s.rawsize || 0);
        if (rva >= s.vaddr && rva < s.vaddr + span) return s.rawptr + (rva - s.vaddr);
      }
      return -1;
    }
    if (ctx.elf) {
      for (const s of ctx.elf.segments) {
        if (s.type === 1 && va >= s.vaddr && va < s.vaddr + s.filesz) return s.offset + (va - s.vaddr);
      }
      return -1;
    }
    if (ctx.macho) {
      const slices = ctx.macho.fat ? ctx.macho.slices.map(x => x.macho).filter(Boolean) : [ctx.macho];
      for (const m of slices) {
        for (const s of m.segments) {
          if (s.filesize && va >= s.vmaddr && va < s.vmaddr + s.filesize) return m.sliceOffset + s.fileoff + (va - s.vmaddr);
        }
      }
      return -1;
    }
    return -1;
  }

  // Mapa máquina → arch de Capstone. Devuelve el id del mapa LAB.capstone.ARCHES
  // (string) o null si Capstone no soporta esa arquitectura.
  function archForPe(machine) {
    switch (machine) {
      case 0x8664: return 'x64';   // AMD64
      case 0x014c: return 'x32';   // i386
      case 0xaa64: return 'arm64'; // ARM64
      case 0x01c0: case 0x01c4: return 'thumb'; // ARM/ARMNT (Thumb-2 en PE)
      default: return null;
    }
  }
  function archForElf(elf) {
    switch (elf.machine) {
      case 0x3e: return 'x64';
      case 0x03: return 'x32';
      case 0xb7: return 'arm64';
      case 0x28: return (elf.entry & 1) ? 'thumb' : 'arm'; // bit 0 del entry ⇒ Thumb
      case 0x08: return elf.is64 ? 'mips64' : 'mips32';
      default: return null; // RISC-V, etc.: sin soporte en el Capstone vendorizado
    }
  }
  function archForMacho(cpuType) {
    switch (cpuType >>> 0) {
      case 0x01000007: return 'x64';   // x86_64
      case 0x00000007: return 'x32';   // i386
      case 0x0100000C: return 'arm64'; // ARM64
      case 0x0000000C: return 'arm';   // ARM (32-bit)
      default: return null;
    }
  }

  // Normaliza el ctx a lo que necesita el desensamblado del EP. null si no aplica
  // (sin PE/ELF, o el EP no cae en ningún segmento mapeable).
  function epContext(ctx) {
    if (ctx.pe && ctx.pe.optional && ctx.pe.epOffset >= 0) {
      const opt = ctx.pe.optional;
      const archId = archForPe(ctx.pe.machine);
      return {
        kind: 'PE', fileOffset: ctx.pe.epOffset,
        displayBase: (opt.imageBase || 0) + opt.entryPoint,
        entryVaddr: (opt.imageBase || 0) + opt.entryPoint,
        archId, machineName: ctx.pe.machineName, le: true,
      };
    }
    if (ctx.elf && ctx.elf.entryOffset >= 0) {
      const archId = archForElf(ctx.elf);
      // En Thumb el código vive en (entry & ~1); corregimos base y offset.
      const thumb = archId === 'thumb';
      return {
        kind: 'ELF',
        fileOffset: ctx.elf.entryOffset - (thumb ? 1 : 0),
        displayBase: ctx.elf.entry - (thumb ? 1 : 0),
        entryVaddr: ctx.elf.entry,
        archId, machineName: ctx.elf.machineName, le: ctx.elf.le,
      };
    }
    if (ctx.macho) {
      // fat: usamos la primera slice con entry resuelto
      const slices = ctx.macho.fat ? ctx.macho.slices.map(x => x.macho).filter(Boolean) : [ctx.macho];
      const m = slices.find(s => s && s.entryOffset >= 0);
      if (m) {
        return {
          kind: 'Mach-O', fileOffset: m.entryOffset, displayBase: m.entry,
          entryVaddr: m.entry, archId: archForMacho(m.cpuType), machineName: m.cpuName, le: m.le,
        };
      }
    }
    return null;
  }

  // Construye el arch a pasar a CS.run: id del mapa, o un objeto {a,m} cuando hay
  // que forzar big-endian (MIPS BE) que el id little-endian no cubre.
  function buildArch(archId, le) {
    if (!le && (archId === 'mips32' || archId === 'mips64')) {
      return { a: 'CS_ARCH_MIPS', m: [archId === 'mips64' ? 'CS_MODE_64' : 'CS_MODE_32', 'CS_MODE_BIG_ENDIAN'] };
    }
    return archId;
  }

  function archOptions(selected) {
    const cs = CS();
    const arches = (cs && cs.ARCHES) || [];
    return arches.map(a =>
      '<option value="' + a.id + '"' + (a.id === selected ? ' selected' : '') + '>' + esc(a.label) + '</option>'
    ).join('');
  }

  // ── Estado para los handlers inline (un solo panel de triage a la vez) ──
  let lastCtx = null, lastEp = null, lastText = '', lastBranch = null;

  // ── UI (devuelta por el analyzer; se inyecta vía innerHTML) ──
  function analyze(ctx) {
    lastCtx = ctx; lastEp = epContext(ctx); lastText = ''; lastBranch = null;
    const ep = lastEp;
    if (!ep) {
      return '<div class="lab-note">No se pudo resolver el entry point a un offset de ' +
        'archivo (¿EP fuera de los segmentos mapeados, o formato no PE/ELF?).</div>';
    }
    const cs = CS();
    if (!cs) return '<div class="lab-err">El servicio Capstone no está disponible.</div>';

    const archNote = ep.archId
      ? ('arch inferida <b>' + esc((cs.ARCHES.find(a => a.id === ep.archId) || {}).label || ep.archId) + '</b>')
      : '<span class="ds-warn">arch ' + esc(ep.machineName) + ' sin soporte en Capstone — elegí una manualmente</span>';

    return '' +
      '<div class="lab-row1">' + ep.kind + ' · EP en ' + hx(ep.entryVaddr) +
      ' <span class="lab-dim">(offset ' + hx(ep.fileOffset) + ')</span> · ' + archNote +
      ' <span class="lab-dim">— el motor (~1.8 MB) se carga al primer uso; nada sale del navegador.</span></div>' +
      '<div class="ds-bar">' +
        '<button class="yr-run" onclick="Triage.epdisasm.run(this)">▶ Desensamblar EP</button>' +
        '<select class="lr-cat ep-arch">' + archOptions(ep.archId || 'x64') + '</select>' +
        '<label class="ioc-chk">instr <input class="cv-key ep-count" value="' + DEFAULT_COUNT + '" style="max-width:64px"></label>' +
        '<label class="ioc-chk">desfase <input class="cv-key ep-skew" value="0" title="re-sincronizar: corre el arranque ±N bytes" style="max-width:64px"></label>' +
        '<button class="cv-btn" onclick="Triage.epdisasm.copy()">copiar</button>' +
        '<span class="yr-status lab-dim ep-status"></span>' +
      '</div>' +
      '<div class="ep-out"></div>';
  }

  async function run(btn) {
    const panel = btn.closest('.lab-panel-b');
    const out = panel.querySelector('.ep-out');
    const ctx = lastCtx, ep = lastEp, cs = CS();
    if (!ctx || !ep || !cs) { out.innerHTML = '<div class="lab-err">No hay binario cargado.</div>'; return; }

    const archId = panel.querySelector('.ep-arch').value;
    let count = parseInt(panel.querySelector('.ep-count').value, 10);
    if (!(count > 0)) count = DEFAULT_COUNT;
    const skew = parseInt(panel.querySelector('.ep-skew').value, 10) || 0;

    const start = ep.fileOffset + skew;
    const base = ep.displayBase + skew;
    if (start < 0 || start >= ctx.bytes.length) {
      out.innerHTML = '<div class="lab-err">El desfase deja el arranque fuera del archivo.</div>'; return;
    }
    const slice = ctx.bytes.subarray(start, Math.min(start + WINDOW_BYTES, ctx.bytes.length));

    btn.disabled = true;
    const firstLoad = !cs.loaded();
    out.innerHTML = '<div class="lab-loading">⬡ ' + (firstLoad ? 'Cargando el motor Capstone…' : 'Desensamblando…') + '</div>';
    try {
      const insns = await cs.run(slice, { arch: buildArch(archId, ep.le), address: base });
      const res = cs.renderTable(insns, slice, base, { cap: count });
      lastText = res.text;
      out.innerHTML = banners(slice, res, base) + res.html + branchFollow(insns, ctx);
    } catch (e) {
      console.error('[triage] epdisasm', e);
      out.innerHTML = '<div class="lab-err">Error del desensamblador: ' + esc(e && e.message || e) + '</div>';
    } finally {
      btn.disabled = false;
    }
  }

  // Avisos anti-ruido por encima de la tabla (guardia de entropía + desync).
  function banners(slice, res, base) {
    let h = '';
    const ent = shannon(slice.subarray(0, Math.min(256, slice.length)));
    if (ent >= HI_ENTROPY) {
      h += '<div class="lab-note">⚠ Región del EP con entropía alta (' + ent.toFixed(2) +
        ' bits/byte) → probablemente <b>packed/cifrada</b>. El desensamblado no será ' +
        'representativo; el próximo paso es un unpacker/sandbox/debugger (dinámico).</div>';
    }
    const decodedSpan = res.stoppedAt - base;
    if (res.decoded < slice.length && decodedSpan <= DESYNC_EARLY) {
      h += '<div class="lab-note">⚠ Se frenó en un byte inválido casi al instante (' +
        decodedSpan + ' bytes) → posible <b>anti-desensamblado</b> (bytes basura / ' +
        'instrucciones solapadas). Probá el desfase ±1 para re-sincronizar.</div>';
    }
    return h;
  }

  // Si la primera instrucción es un salto/llamada con destino inmediato resoluble,
  // ofrece saltar ahí (cubre el clásico "jmp OEP" de los stubs de packer).
  function branchFollow(insns, ctx) {
    lastBranch = null;
    if (!insns.length) return '';
    const first = insns[0];
    if (!/^(jmp|call|b|bl)$/.test(first.mnemonic)) return '';
    const m = /^(?:0x)?([0-9a-fA-F]+)$/.exec((first.opStr || '').trim());
    if (!m) return ''; // destino indirecto (registro/memoria): no resoluble estático
    const targetVa = parseInt(m[1], 16);
    const off = vaddrToOffset(ctx, targetVa);
    if (off < 0) return '';
    lastBranch = { offset: off, vaddr: targetVa };
    return '<div class="lab-row1" style="margin-top:6px">El EP salta a ' + hx(targetVa) +
      '. <button class="cv-btn" onclick="Triage.epdisasm.follow(this)">▶ seguir a ' + hx(targetVa) + '</button></div>';
  }

  async function follow(btn) {
    const panel = btn.closest('.lab-panel-b');
    const out = panel.querySelector('.ep-out');
    const ctx = lastCtx, ep = lastEp, cs = CS(), br = lastBranch;
    if (!ctx || !ep || !cs || !br) return;
    const archId = panel.querySelector('.ep-arch').value;
    let count = parseInt(panel.querySelector('.ep-count').value, 10);
    if (!(count > 0)) count = DEFAULT_COUNT;
    const slice = ctx.bytes.subarray(br.offset, Math.min(br.offset + WINDOW_BYTES, ctx.bytes.length));
    btn.disabled = true;
    out.innerHTML = '<div class="lab-loading">⬡ Desensamblando desde ' + hx(br.vaddr) + '…</div>';
    try {
      const insns = await cs.run(slice, { arch: buildArch(archId, ep.le), address: br.vaddr });
      const res = cs.renderTable(insns, slice, br.vaddr, { cap: count });
      lastText = res.text;
      out.innerHTML = '<div class="lab-row1">Desde el destino del salto · ' + hx(br.vaddr) + '</div>' +
        banners(slice, res, br.vaddr) + res.html + branchFollow(insns, ctx);
    } catch (e) {
      out.innerHTML = '<div class="lab-err">Error del desensamblador: ' + esc(e && e.message || e) + '</div>';
    } finally {
      btn.disabled = false;
    }
  }

  function copy() { if (lastText && window.LAB) LAB.copy(lastText); }

  const Tri = (typeof window !== 'undefined' && window.Triage) || null;
  if (Tri) Tri.epdisasm = { run, follow, copy, epContext, vaddrToOffset, archForElf, archForPe };

  // Registro del analyzer (después de peid en la cadena → ver index.html).
  if (Tri && Tri.analyzers) {
    Tri.analyzers.register({
      id: 'epdisasm', title: 'Entry Point (disasm)', icon: '⚙',
      applies(ctx) { return !!epContext(ctx); },
      run(ctx) { return analyze(ctx); },
    });
  }

  return { epContext, vaddrToOffset, archForElf, archForPe, shannon, buildArch };
})();
