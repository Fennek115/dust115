/* Vulpine Marrow — lightbox con zoom (rueda) + pan (arrastrar).
   Clickea imágenes, SVG y diagramas mermaid en los posts para verlos a pantalla.
   Sin dependencias. Usa delegación de eventos sobre .post-content, así que
   funciona aunque mermaid renderice su <svg> de forma asíncrona. */
(function () {
  const content = document.querySelector(".post--single .post-content");
  if (!content) return;

  let overlay, stage, capEl;
  let scale = 1, tx = 0, ty = 0;                 // transform actual del stage
  let dragging = false, sx = 0, sy = 0, ox = 0, oy = 0;
  let lastFocus = null;
  const MIN = 0.2, MAX = 8, STEP = 1.25;

  function center() {
    return { x: window.innerWidth / 2, y: window.innerHeight / 2 };
  }

  function apply() {
    stage.style.transform = `translate(${tx}px, ${ty}px) scale(${scale})`;
  }

  // zoom manteniendo fijo el punto bajo `pivot` (coords de viewport)
  function zoomBy(factor, pivot) {
    const next = Math.min(MAX, Math.max(MIN, scale * factor));
    const k = next / scale;
    tx = pivot.x - k * (pivot.x - tx);
    ty = pivot.y - k * (pivot.y - ty);
    scale = next;
    apply();
  }

  // encuadra el contenido a tamaño natural, centrado en el viewport
  function fit() {
    scale = 1; tx = 0; ty = 0; apply();
    const r = stage.getBoundingClientRect();
    tx = (window.innerWidth - r.width) / 2;
    ty = (window.innerHeight - r.height) / 2;
    apply();
  }

  function build() {
    overlay = document.createElement("div");
    overlay.className = "vm-lightbox";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.hidden = true;

    const bar = document.createElement("div");
    bar.className = "vm-lightbox__bar";
    bar.innerHTML =
      '<button type="button" data-act="out" aria-label="Alejar">−</button>' +
      '<button type="button" data-act="reset" aria-label="Restablecer">⤢</button>' +
      '<button type="button" data-act="in" aria-label="Acercar">+</button>' +
      '<button type="button" data-act="close" aria-label="Cerrar">✕</button>';

    stage = document.createElement("div");
    stage.className = "vm-lightbox__stage";

    capEl = document.createElement("div");
    capEl.className = "vm-lightbox__cap";

    overlay.append(bar, stage, capEl);
    document.body.appendChild(overlay);

    bar.addEventListener("click", (e) => {
      const btn = e.target.closest("button");
      if (!btn) return;
      const act = btn.dataset.act;
      if (act === "in") zoomBy(STEP, center());
      else if (act === "out") zoomBy(1 / STEP, center());
      else if (act === "reset") fit();
      else if (act === "close") close();
    });

    // click en el fondo (no en stage/barra/caption) → cerrar
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) close();
    });

    overlay.addEventListener("wheel", (e) => {
      e.preventDefault();
      const factor = e.deltaY < 0 ? STEP : 1 / STEP;
      zoomBy(factor, { x: e.clientX, y: e.clientY });
    }, { passive: false });

    // pan
    stage.addEventListener("pointerdown", (e) => {
      dragging = true;
      sx = e.clientX; sy = e.clientY; ox = tx; oy = ty;
      try { stage.setPointerCapture(e.pointerId); } catch (_) {}
      stage.classList.add("is-grabbing");
    });
    stage.addEventListener("pointermove", (e) => {
      if (!dragging) return;
      tx = ox + (e.clientX - sx);
      ty = oy + (e.clientY - sy);
      apply();
    });
    const endDrag = (e) => {
      if (!dragging) return;
      dragging = false;
      stage.classList.remove("is-grabbing");
      try { stage.releasePointerCapture(e.pointerId); } catch (_) {}
    };
    stage.addEventListener("pointerup", endDrag);
    stage.addEventListener("pointercancel", endDrag);

    document.addEventListener("keydown", (e) => {
      if (overlay.hidden) return;
      if (e.key === "Escape") close();
      else if (e.key === "+" || e.key === "=") zoomBy(STEP, center());
      else if (e.key === "-" || e.key === "_") zoomBy(1 / STEP, center());
      else if (e.key === "0") fit();
    });
  }

  function open(node, caption) {
    if (!overlay) build();
    stage.innerHTML = "";
    stage.appendChild(node);
    capEl.textContent = caption || "";
    capEl.style.display = caption ? "" : "none";
    lastFocus = document.activeElement;
    document.documentElement.classList.add("vm-lightbox-open");
    overlay.hidden = false;
    fit();
    overlay.querySelector('[data-act="close"]').focus();
  }

  function close() {
    if (!overlay || overlay.hidden) return;
    overlay.hidden = true;
    document.documentElement.classList.remove("vm-lightbox-open");
    stage.innerHTML = "";
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }

  function svgAspect(svg) {
    const vb = svg.getAttribute("viewBox");
    if (vb) {
      const p = vb.split(/[\s,]+/).map(Number);
      if (p.length === 4 && p[2] && p[3]) return [p[2], p[3]];
    }
    const w = parseFloat(svg.getAttribute("width"));
    const h = parseFloat(svg.getAttribute("height"));
    if (w && h) return [w, h];
    return [800, 600];
  }

  // construye el nodo que va al stage (desacoplado del DOM vivo)
  function nodeFor(el) {
    if (el.tagName === "IMG") {
      const img = new Image();
      img.src = el.currentSrc || el.src;
      img.alt = el.alt || "";
      return img;
    }
    // svg (mermaid u otro): clonar por outerHTML y dimensionar por aspecto
    const wrap = document.createElement("div");
    wrap.innerHTML = el.outerHTML;
    const svg = wrap.firstElementChild;
    svg.removeAttribute("id");
    const [w, h] = svgAspect(svg);
    const maxW = window.innerWidth * 0.9;
    const maxH = window.innerHeight * 0.86;
    const k = Math.min(maxW / w, maxH / h);
    svg.removeAttribute("width");
    svg.removeAttribute("height");
    svg.style.maxWidth = "none";
    svg.style.width = (w * k) + "px";
    svg.style.height = (h * k) + "px";
    svg.setAttribute("preserveAspectRatio", "xMidYMid meet");
    return svg;
  }

  // resuelve el elemento disparador a partir del target del click
  function triggerFrom(target) {
    const pre = target.closest("pre.mermaid, .mermaid");
    if (pre) return pre.querySelector("svg");
    const svg = target.closest("svg");
    if (svg) return svg;
    return target.closest("img");
  }

  function captionFor(el) {
    const fig = el.closest("figure, .vm-figure");
    if (!fig) return "";
    const cap = fig.querySelector("figcaption");
    return cap ? cap.textContent.trim().replace(/\s+/g, " ") : "";
  }

  content.addEventListener("click", (e) => {
    if (e.target.closest("a")) return;          // no robar clicks de enlaces
    const el = triggerFrom(e.target);
    if (!el) return;
    e.preventDefault();
    open(nodeFor(el), captionFor(el));
  });
})();
