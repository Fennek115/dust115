// Botón "subir al inicio" — aparece tras desplazarse hacia abajo (útil en posts
// largos del blog / capítulos del Códice). El botón #vm-top vive en el footer.
(function () {
  var btn = document.getElementById("vm-top");
  if (!btn) return;

  var SHOW_AT = 500; // px de scroll antes de mostrarlo
  var ticking = false;

  function update() {
    var y = window.pageYOffset || document.documentElement.scrollTop || 0;
    btn.classList.toggle("is-visible", y > SHOW_AT);
    ticking = false;
  }

  window.addEventListener(
    "scroll",
    function () {
      if (!ticking) {
        window.requestAnimationFrame(update);
        ticking = true;
      }
    },
    { passive: true }
  );

  btn.addEventListener("click", function () {
    var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    window.scrollTo({ top: 0, behavior: reduce ? "auto" : "smooth" });
  });

  update();
})();
