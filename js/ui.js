/**
 * Wiring for the pages' buttons.
 *
 * The pages used to call their handlers from inline `onclick` attributes. The
 * gateway serves a Content-Security-Policy without `'unsafe-inline'`, and an
 * inline event handler is inline script: the browser refuses to run it and
 * logs a violation, so every button on every page did nothing at all when the
 * site was served by its own gateway. Nothing in the page looks broken, which
 * is why it survived — the only symptom is a click with no effect.
 *
 * So handlers are named in `data-action` and dispatched from here. One
 * delegated listener also means it does not matter that the handlers live in
 * ES modules, which are deferred and so are not defined at the moment the
 * markup is parsed.
 *
 * Loaded as a classic script (not a module) because it must also serve pages
 * that load no modules at all.
 */
(function () {
  "use strict";

  /** Handlers are published on window by js/App.js and js/chunked-app.js. */
  function run(name, event) {
    var handler = window[name];
    if (typeof handler !== "function") {
      console.error("[OREOCHAIN] no handler named " + name);
      return;
    }
    var result = handler(event);
    // Upload and retrieval are async and report their own failures in the
    // page; this stops an unhandled rejection from reaching the console.
    if (result && typeof result.catch === "function") result.catch(function () {});
  }

  function dispatch(event) {
    var target = event.target.closest("[data-action]");
    if (!target) return;
    if (target.tagName === "BUTTON" && target.disabled) return;
    run(target.getAttribute("data-action"), event);
  }

  document.addEventListener("click", dispatch);
  document.addEventListener("change", dispatch);

  window.addEventListener("load", function () {
    // index.html has no module to do this, and a loader that never clears
    // covers the whole page.
    var loader = document.querySelector(".loader-wraper");
    if (loader) loader.style.display = "none";

    // admin.html: typing a new address clears the last result and re-enables
    // the buttons a previous action disabled.
    var address = document.getElementById("Exporter-address");
    if (!address) return;
    address.addEventListener("input", function () {
      var note = document.getElementById("note");
      if (note) note.innerHTML = "";
      ["ExporterBtn", "edit", "delete"].forEach(function (id) {
        var button = document.getElementById(id);
        if (button) button.disabled = false;
      });
    });
  });
})();
