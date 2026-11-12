/* Boot diagnostic. Deliberately a classic script, not a module: it has to keep
   working in exactly the situation it exists for, where the module graph never
   loads. Nothing here is needed when the page starts normally.

   The symptom it addresses: jb15.html keeps showing the placeholder
   "RAM: checking..." with the spinner turning forever. That text is static
   HTML. If the module had run even one line it would have been replaced by
   "JS heap: ... | core: ...". So the spinner means "the module never started",
   which is a loading problem, not a memory problem. */
(function () {
  var MODULES = ["jb.js", "core.js", "mem.js", "int64.js", "ps4_offsets.js"];
  var started = false;
  var problems = [];
  var probe = {};

  window.__JB_ERRORS = problems;

  function note(msg) {
    problems.push(msg);
    try {
      if (window.console && console.error) console.error("[boot] " + msg);
    } catch (e) {}
  }

  window.addEventListener("error", function (e) {
    var t = e && e.target;
    if (t && (t.src || t.href)) {
      note("failed to load " + (t.src || t.href) + " (" + (t.tagName || "?") + ")");
    } else if (e && e.message) {
      note("script error: " + e.message + (e.filename ? " @ " + e.filename + ":" + e.lineno : ""));
    } else {
      note("script error");
    }
  }, true);

  window.addEventListener("unhandledrejection", function (e) {
    var r = e && e.reason;
    note("unhandled rejection: " + (r && r.message ? r.message : String(r)));
  });

  function head(url, cb) {
    var done = false;
    function fin(v) { if (!done) { done = true; cb(v); } }
    try {
      var x = new XMLHttpRequest();
      x.open("HEAD", url + "?bootcheck=" + Date.now(), true);
      x.onreadystatechange = function () {
        if (x.readyState !== 4) return;
        fin({ status: x.status, type: x.getResponseHeader("Content-Type") || "" });
      };
      x.onerror = function () { fin({ status: 0, type: "" }); };
      x.send(null);
      setTimeout(function () { fin({ status: -1, type: "timeout" }); }, 4000);
    } catch (e) {
      fin({ status: -2, type: String(e && e.message) });
    }
  }

  function isModuleType(t) {
    /* A module script is refused unless the type is a JavaScript MIME type.
       text/plain and application/octet-stream both fail, and the console shows
       a WebKit error that is invisible on a television. */
    var s = String(t || "").split(";")[0].trim().toLowerCase();
    return s === "text/javascript" || s === "application/javascript" ||
           s === "application/x-javascript" || s === "text/ecmascript" ||
           s === "application/ecmascript" || s === "module";
  }

  /* Booted either because jb.js set the flag, or -- if an older jb.js without
     the flag is in use -- because the page shows the traces the module leaves:
     the RAM box no longer holds its placeholder, the log panel is on, or the log
     has lines in it. Without this fallback the diagnostic would fire on a page
     that is working perfectly. */
  function looksBooted() {
    if (window.__JB_BOOTED) return true;
    try {
      if (document.body && document.body.className === "log") return true;
      var b = document.getElementById("ramBox");
      if (b && b.textContent.indexOf("RAM: checking") < 0 &&
          b.textContent.indexOf("BOOT DIAGNOSTIC") < 0) return true;
      var o = document.getElementById("out");
      if (o && o.textContent.length > 0 &&
          o.textContent.indexOf("MODULE NEVER STARTED") < 0) return true;
    } catch (e) {}
    return false;
  }

  function report() {
    if (started || looksBooted() || window.__REPORTED__) return;
    window.__REPORTED__ = true;

    var lines = [];
    lines.push("MODULE NEVER STARTED - this is not a RAM error.");
    lines.push("");
    for (var i = 0; i < MODULES.length; i++) {
      var m = MODULES[i];
      var p = probe[m];
      if (!p) { lines.push("  " + m + ": not probed"); continue; }
      var verdict;
      if (p.status === 404) verdict = "MISSING (404) - file is not in the served folder";
      else if (p.status === 0) verdict = "NO RESPONSE - server not answering";
      else if (p.status === -1) verdict = "TIMEOUT";
      else if (p.status === -2) verdict = "request failed: " + p.type;
      else if (p.status !== 200) verdict = "HTTP " + p.status;
      else if (!isModuleType(p.type)) verdict = "WRONG TYPE '" + p.type + "' - browser refuses it as a module";
      else verdict = "ok";
      lines.push("  " + m + ": " + verdict);
    }
    if (problems.length) {
      lines.push("");
      lines.push("errors:");
      for (var j = 0; j < problems.length && j < 8; j++) lines.push("  " + problems[j]);
    }
    /* Every file present, correct type, still not started: the modules are
       being refused for a reason the probes cannot see, most often no module
       support in the browser at all. Say so instead of guessing. */
    var allOk = true;
    for (var k = 0; k < MODULES.length; k++) {
      var q = probe[MODULES[k]];
      if (!q || q.status !== 200 || !isModuleType(q.type)) allOk = false;
    }
    if (allOk) {
      lines.push("");
      lines.push("All five modules are present and served as JavaScript, so this");
      lines.push("browser is refusing ES modules outright (no module support).");
      lines.push("Tell me and I will ship a single-file, non-module build.");
    }

    lines.push("");
    lines.push("Fix: serve the folder with  python3 serve.py 8001  and open");
    lines.push("     http://<pc-ip>:8001/jb15.html?... again. serve.py sends");
    lines.push("     text/javascript for .js and no-store for everything;");
    lines.push("     python -m http.server on Windows can send text/plain,");
    lines.push("     which the browser refuses for modules.");

    var text = lines.join("\n");

    try {
      var box = document.getElementById("ramBox");
      if (box) {
        box.textContent = "BOOT DIAGNOSTIC - module not started";
        box.style.color = "#c45c4a";
        box.style.whiteSpace = "normal";
        box.style.overflow = "visible";
      }
      var out = document.getElementById("out");
      if (out) {
        out.textContent = text;
        out.style.borderColor = "#c45c4a";
        out.style.color = "#f0c8c0";
      }
      if (document.body) document.body.className = "log";
      var spin = document.getElementById("spin");
      if (spin) spin.style.borderTopColor = "#c45c4a";
      var st = document.getElementById("state");
      if (st) { st.textContent = "not started"; st.style.color = "#c45c4a"; }
    } catch (e) {}

    try {
      note("diagnostic shown");
    } catch (e) {}
  }

  function probeAll(cb) {
    var left = MODULES.length;
    if (!left) return cb();
    for (var i = 0; i < MODULES.length; i++) {
      (function (m) {
        head(m, function (v) {
          probe[m] = v;
          if (--left === 0) cb();
        });
      })(MODULES[i]);
    }
  }

  var t = setInterval(function () {
    if (looksBooted()) {
      started = true;
      clearInterval(t);
    }
  }, 200);

  setTimeout(function () {
    if (looksBooted()) return;
    probeAll(report);
  }, 2500);

  setTimeout(function () {
    if (looksBooted()) return;
    if (!document.getElementById("out") ||
        document.getElementById("out").textContent.indexOf("MODULE NEVER STARTED") < 0) {
      report();
    }
  }, 9000);
})();
