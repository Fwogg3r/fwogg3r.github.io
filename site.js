// Top-left site menu, shared by every page on fwogg3r.com.
(function () {
  var PAGES = [
    ["Home", "index.html"],
    ["About Me", "about.html"],
    ["Portfolio", "portfolio.html"],
    ["Contact", "contact.html"],
  ];

  function mount() {
    var here = window.location.pathname.split("/").pop() || "index.html";

    var nav = document.createElement("nav");
    nav.id = "site-nav";
    nav.setAttribute("aria-label", "Site");

    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "site-nav-button";
    btn.setAttribute("aria-haspopup", "true");
    btn.setAttribute("aria-expanded", "false");
    btn.setAttribute("aria-controls", "site-nav-list");
    btn.textContent = "[ MENU ▾ ]";

    var list = document.createElement("div");
    list.id = "site-nav-list";
    list.className = "site-nav-list";
    list.hidden = true;

    PAGES.forEach(function (p) {
      var a = document.createElement("a");
      a.href = p[1];
      a.textContent = p[0];
      if (p[1] === here) a.setAttribute("aria-current", "page");
      list.appendChild(a);
    });

    function setOpen(open) {
      list.hidden = !open;
      btn.setAttribute("aria-expanded", String(open));
    }

    btn.addEventListener("click", function (e) {
      e.stopPropagation();
      setOpen(list.hidden);
      if (!list.hidden) list.querySelector("a").focus();
    });
    document.addEventListener("click", function (e) {
      if (!nav.contains(e.target)) setOpen(false);
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && !list.hidden) {
        setOpen(false);
        btn.focus();
      }
    });

    nav.appendChild(btn);
    nav.appendChild(list);
    document.body.appendChild(nav);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mount);
  } else {
    mount();
  }
})();
