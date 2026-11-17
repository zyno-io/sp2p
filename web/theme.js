// SPDX-License-Identifier: MIT

// Theme preference: "system" (default), "light", or "dark".
// Loaded synchronously in <head> so an explicit choice applies before first
// paint (the CSP forbids inline scripts). "system" leaves data-theme unset,
// so the prefers-color-scheme rules in style.css decide.
(function () {
  var KEY = "sp2p-theme";
  var ORDER = ["system", "light", "dark"];
  var LABELS = { system: "System", light: "Light", dark: "Dark" };
  var root = document.documentElement;

  function read() {
    try {
      var v = localStorage.getItem(KEY);
      return ORDER.indexOf(v) >= 0 ? v : "system";
    } catch (e) {
      return "system";
    }
  }

  function apply(pref) {
    root.setAttribute("data-theme-pref", pref);
    if (pref === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", pref);
    var buttons = document.querySelectorAll(".theme-toggle");
    for (var i = 0; i < buttons.length; i++) {
      var next = ORDER[(ORDER.indexOf(pref) + 1) % ORDER.length];
      var label = "Theme: " + LABELS[pref] + " (switch to " + LABELS[next] + ")";
      buttons[i].setAttribute("aria-label", label);
      buttons[i].setAttribute("title", label);
    }
  }

  apply(read());

  document.addEventListener("DOMContentLoaded", function () {
    apply(read());
    var buttons = document.querySelectorAll(".theme-toggle");
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].addEventListener("click", function () {
        var current = root.getAttribute("data-theme-pref") || "system";
        var next = ORDER[(ORDER.indexOf(current) + 1) % ORDER.length];
        try {
          if (next === "system") localStorage.removeItem(KEY);
          else localStorage.setItem(KEY, next);
        } catch (e) {
          // Storage unavailable: the choice lasts for this page view only.
        }
        apply(next);
      });
    }
  });
})();
