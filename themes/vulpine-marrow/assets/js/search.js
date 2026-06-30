// Buscador full-text client-side de Vulpine Marrow.
// Sin dependencias ni CDN: carga el índice generado en build (/index.json) y
// filtra/rankea en el navegador. Sólo actúa si la página tiene el contenedor
// .vm-search (la página /buscar/), así que entra en el bundle global sin coste
// en el resto del sitio.
(function () {
  'use strict';

  var root = document.querySelector('.vm-search');
  if (!root) return;

  var input = document.getElementById('vm-search-input');
  var results = document.getElementById('vm-search-results');
  var status = document.getElementById('vm-search-status');
  var indexUrl = root.getAttribute('data-index') || '/index.json';

  var docs = null;     // índice cargado
  var loading = false;
  var pending = null;  // query en espera mientras carga el índice

  // ── Utilidades ─────────────────────────────────────────────────────────
  function tokenize(q) {
    return (q || '')
      .toLowerCase()
      .normalize('NFD').replace(/[̀-ͯ]/g, '') // sin diacríticos
      .split(/[^a-z0-9]+/)
      .filter(function (t) { return t.length > 1; });
  }

  function norm(s) {
    return (s || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '');
  }

  function setStatus(msg) { if (status) status.textContent = msg; }

  // Resalta los tokens dentro de un texto, devolviendo un fragmento DOM seguro.
  function highlight(text, tokens) {
    var frag = document.createDocumentFragment();
    if (!text) return frag;
    var hay = norm(text);
    // posiciones a marcar
    var marks = [];
    tokens.forEach(function (tok) {
      var from = 0, i;
      while ((i = hay.indexOf(tok, from)) !== -1) {
        marks.push([i, i + tok.length]);
        from = i + tok.length;
      }
    });
    if (!marks.length) { frag.appendChild(document.createTextNode(text)); return frag; }
    marks.sort(function (a, b) { return a[0] - b[0]; });
    // fusionar solapados
    var merged = [marks[0]];
    for (var k = 1; k < marks.length; k++) {
      var last = merged[merged.length - 1];
      if (marks[k][0] <= last[1]) last[1] = Math.max(last[1], marks[k][1]);
      else merged.push(marks[k]);
    }
    var pos = 0;
    merged.forEach(function (m) {
      if (m[0] > pos) frag.appendChild(document.createTextNode(text.slice(pos, m[0])));
      var mark = document.createElement('mark');
      mark.textContent = text.slice(m[0], m[1]);
      frag.appendChild(mark);
      pos = m[1];
    });
    if (pos < text.length) frag.appendChild(document.createTextNode(text.slice(pos)));
    return frag;
  }

  // Extrae un fragmento de contexto alrededor del primer match en el cuerpo.
  function snippet(content, tokens) {
    if (!content) return '';
    var hay = norm(content);
    var first = -1;
    tokens.forEach(function (tok) {
      var i = hay.indexOf(tok);
      if (i !== -1 && (first === -1 || i < first)) first = i;
    });
    if (first === -1) return content.slice(0, 200);
    var start = Math.max(0, first - 90);
    var end = Math.min(content.length, first + 130);
    var s = content.slice(start, end).trim();
    return (start > 0 ? '…' : '') + s + (end < content.length ? '…' : '');
  }

  // ── Scoring ────────────────────────────────────────────────────────────
  function score(doc, tokens) {
    var title = norm(doc.title);
    var summary = norm(doc.summary);
    var content = norm(doc.content);
    var tags = (doc.tags || []).map(norm);
    var s = 0;
    for (var i = 0; i < tokens.length; i++) {
      var tok = tokens[i];
      var hit = false;
      if (title.indexOf(tok) !== -1) { s += 8; hit = true; }
      for (var t = 0; t < tags.length; t++) {
        if (tags[t] === tok) { s += 6; hit = true; }
        else if (tags[t].indexOf(tok) !== -1) { s += 3; hit = true; }
      }
      if (summary.indexOf(tok) !== -1) { s += 3; hit = true; }
      if (content.indexOf(tok) !== -1) { s += 1; hit = true; }
      if (!hit) return 0; // AND: todos los tokens deben aparecer
    }
    return s;
  }

  // ── Render ─────────────────────────────────────────────────────────────
  function render(matches, tokens) {
    results.textContent = '';
    matches.forEach(function (doc) {
      var art = document.createElement('article');
      art.className = 'post-item';

      var label = doc.series || (doc.section ? doc.section : '');
      if (label) {
        var lab = document.createElement('div');
        lab.className = 'post-item__series';
        lab.textContent = '⟐ ' + label;
        art.appendChild(lab);
      }

      var h = document.createElement('h2');
      h.className = 'post-item__title';
      var a = document.createElement('a');
      a.href = doc.url;
      a.appendChild(highlight(doc.title, tokens));
      h.appendChild(a);
      art.appendChild(h);

      if (doc.date) {
        var meta = document.createElement('div');
        meta.className = 'post-item__meta';
        meta.textContent = doc.date;
        art.appendChild(meta);
      }

      var p = document.createElement('p');
      p.className = 'post-item__summary';
      // si el match está en el cuerpo y no en el summary, mostrar contexto del cuerpo
      var body = doc.summary || '';
      var inSummary = tokens.some(function (t) { return norm(body).indexOf(t) !== -1; });
      if (!inSummary && doc.content) body = snippet(doc.content, tokens);
      p.appendChild(highlight(body, tokens));
      art.appendChild(p);

      if (doc.tags && doc.tags.length) {
        var tg = document.createElement('div');
        tg.className = 'post-item__tags';
        doc.tags.slice(0, 5).forEach(function (tag) {
          var ta = document.createElement('span');
          ta.className = 'post-item__tag';
          ta.textContent = tag;
          tg.appendChild(ta);
        });
        art.appendChild(tg);
      }

      results.appendChild(art);
    });
  }

  // ── Búsqueda ───────────────────────────────────────────────────────────
  function run(q) {
    var tokens = tokenize(q);
    if (!tokens.length) {
      results.textContent = '';
      setStatus(q ? 'Escribí al menos dos caracteres.' : '');
      return;
    }
    if (!docs) { pending = q; ensureIndex(); setStatus('Cargando índice…'); return; }

    var scored = [];
    for (var i = 0; i < docs.length; i++) {
      var sc = score(docs[i], tokens);
      if (sc > 0) scored.push({ doc: docs[i], sc: sc });
    }
    scored.sort(function (a, b) {
      if (b.sc !== a.sc) return b.sc - a.sc;
      return (b.doc.date || '').localeCompare(a.doc.date || '');
    });
    render(scored.map(function (x) { return x.doc; }), tokens);
    setStatus(scored.length
      ? scored.length + (scored.length === 1 ? ' resultado' : ' resultados')
      : 'Sin resultados para «' + q + '».');
  }

  function ensureIndex() {
    if (docs || loading) return;
    loading = true;
    fetch(indexUrl, { credentials: 'same-origin' })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        docs = Array.isArray(data) ? data : [];
        loading = false;
        if (pending != null) { var q = pending; pending = null; run(q); }
      })
      .catch(function () {
        loading = false;
        setStatus('No se pudo cargar el índice de búsqueda.');
      });
  }

  // ── Wiring ─────────────────────────────────────────────────────────────
  var timer = null;
  input.addEventListener('input', function () {
    clearTimeout(timer);
    var q = input.value;
    timer = setTimeout(function () { run(q); }, 120);
  });

  // Prefill desde ?q= y precarga del índice al enfocar.
  input.addEventListener('focus', ensureIndex, { once: true });
  var params = new URLSearchParams(window.location.search);
  var q0 = params.get('q');
  if (q0) { input.value = q0; run(q0); }
  input.focus();
})();
