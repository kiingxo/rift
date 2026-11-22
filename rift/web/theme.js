/* Light and dark theme. Loaded in <head> so the page is painted in the right
 * colours from the first frame. The choice is "system", "light" or "dark";
 * "system" follows the operating system and is the default. */
(function () {
  "use strict";
  var KEY = "rift-theme";
  var root = document.documentElement;
  var media = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

  function saved() {
    try {
      var value = window.localStorage.getItem(KEY);
      return value === "light" || value === "dark" ? value : "system";
    } catch (error) {
      return "system";
    }
  }

  function apply(choice) {
    root.setAttribute("data-theme", choice === "system" ? (media && media.matches ? "dark" : "light") : choice);
    var buttons = document.querySelectorAll("[data-theme-choice]");
    for (var index = 0; index < buttons.length; index += 1) {
      buttons[index].setAttribute("aria-pressed", buttons[index].getAttribute("data-theme-choice") === choice ? "true" : "false");
    }
  }

  function choose(choice) {
    try {
      if (choice === "system") window.localStorage.removeItem(KEY);
      else window.localStorage.setItem(KEY, choice);
    } catch (error) {
      /* Private windows can refuse storage. The theme still applies for this visit. */
    }
    apply(choice);
  }

  var current = saved();
  apply(current);
  if (media) {
    var onSystemChange = function () { if (saved() === "system") apply("system"); };
    if (media.addEventListener) media.addEventListener("change", onSystemChange);
    else if (media.addListener) media.addListener(onSystemChange);
  }
  document.addEventListener("DOMContentLoaded", function () {
    var buttons = document.querySelectorAll("[data-theme-choice]");
    for (var index = 0; index < buttons.length; index += 1) {
      buttons[index].addEventListener("click", function (event) {
        current = event.currentTarget.getAttribute("data-theme-choice");
        choose(current);
      });
    }
    apply(current);
  });
})();
