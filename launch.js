/* The landing page: pick a payload, then start the run.
 *
 * Leaving this page has to be a real navigation from it -- the referrer guard
 * in jb.js arms the chain only when the run page was reached from here. */

var TARGET = {
  nova: "log=1&afterglow=run&payload=nova.bin",
  goldhen: "log=1&afterglow=run&mode=goldhen",
};

/* Diagnostic switches ride through from this page's own query string, so a
 * run page can be reached with a real referrer from here instead of being
 * typed into the address bar -- a typed URL sends none, and jb.js arms
 * nothing without one.
 *
 * `afterglow` is deliberately not on the list: TARGET already sets it, and a
 * second copy in the same query would be read as the first, silently turning
 * a probe into a full run or the other way round. */
var PASSTHROUGH = ["stop", "attempts", "mem", "log"];

function passthrough() {
  var q = location.search.replace(/^\?/, "");
  if (!q) return "";
  var keep = [];
  var parts = q.split("&");
  for (var i = 0; i < parts.length; i++) {
    if (!parts[i]) continue;
    var k = decodeURIComponent(parts[i].split("=")[0]);
    if (PASSTHROUGH.indexOf(k) >= 0) keep.push(parts[i]);
  }
  return keep.length ? "&" + keep.join("&") : "";
}

var AUTOSTART_SECONDS = 5;
var STORE_KEY = "afterglow.choice";

var form = document.getElementById("pick");
var autoBox = document.getElementById("auto");
var countEl = document.getElementById("count");
var cacheEl = document.getElementById("cache");
var ticker = null;
var waitingForCache = false;

/* The offline cache, and the one state that must not be run through.
 *
 * While the manifest is being checked or fetched, some modules are the ones
 * the page loaded with and some are not yet on disk -- starting there can mix
 * two builds. Every other state is fine to start from: IDLE is cached and
 * current, UNCACHED means no cache at all (which works as long as the server
 * answers), and a browser with no Application Cache at all -- every desktop
 * browser since Chrome 95 -- must obviously still be able to start.
 *
 * So this blocks on CHECKING and DOWNLOADING and nothing else. The inverse,
 * passing only on IDLE, leaves the button dead wherever the cache is absent.
 *
 * The idea is titotryh-ux's, from Fewi-PS4 911e08a. */
var appCache = (function () {
  try { return window.applicationCache || null; } catch (e) { return null; }
})();

function cacheBusy() {
  if (!appCache) return false;
  try {
    return appCache.status === appCache.CHECKING
        || appCache.status === appCache.DOWNLOADING;
  } catch (e) {
    return false;
  }
}

function cacheNote() {
  if (!cacheEl) return;
  if (!appCache) { cacheEl.textContent = ""; return; }
  var text = "";
  try {
    if (appCache.status === appCache.CHECKING) text = "checking for updates";
    else if (appCache.status === appCache.DOWNLOADING) text = "loading files - hold on";
    else if (appCache.status === appCache.UPDATEREADY) text = "a newer version is cached - reopen this page to use it";
    else if (appCache.status === appCache.OBSOLETE) text = "the cache was dropped - the server answers directly";
  } catch (e) {}
  cacheEl.textContent = text;
}

function cacheChanged() {
  cacheNote();
  /* Someone pressed start while the files were still coming down. Go now
     that they are here, rather than making them press again. */
  if (waitingForCache && !cacheBusy()) {
    waitingForCache = false;
    start();
  }
}

if (appCache) {
  var events = ["checking", "downloading", "progress", "cached", "noupdate",
                "updateready", "error", "obsolete"];
  for (var e = 0; e < events.length; e++) {
    try { appCache.addEventListener(events[e], cacheChanged, false); } catch (err) {}
  }
}

/* Autostart is remembered; the payload is not. Every load starts on Nova,
   whatever was picked last time. Both accessors are guarded, because storage
   can be unavailable or throw outright, and the page works either way. */
function remember() {
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify({ autostart: autoBox.checked }));
  } catch (e) {}
}

function restore() {
  var saved = null;
  try {
    saved = JSON.parse(localStorage.getItem(STORE_KEY) || "null");
  } catch (e) {}
  if (!saved) return;

  if (typeof saved.autostart === "boolean") autoBox.checked = saved.autostart;
}

function picked() {
  var radio = form.querySelector('input[name="payload"]:checked');
  return radio ? radio.value : "nova";
}

function start() {
  stopClock();
  /* Not a refusal -- a wait. The run begins by itself once the files are in. */
  if (cacheBusy()) {
    waitingForCache = true;
    countEl.textContent = "waiting for the cache";
    cacheNote();
    return;
  }
  /* A radio whose value is not a TARGET key used to build "jb.html?undefined":
     the run page then had no payload step and the log said nothing about it,
     because nothing had failed yet. Fall back to the first entry instead of
     navigating with a query that means nothing. */
  var target = TARGET[picked()] || TARGET.nova;
  location.href = "jb.html?" + target + passthrough();
}

function stopClock() {
  if (ticker !== null) {
    clearInterval(ticker);
    ticker = null;
  }
  countEl.textContent = "";
}

function startClock() {
  var left = AUTOSTART_SECONDS;
  countEl.textContent = "starting in " + left + "s";
  ticker = setInterval(function () {
    left -= 1;
    if (left <= 0) {
      start();
      return;
    }
    countEl.textContent = "starting in " + left + "s";
  }, 1000);
}

form.addEventListener("submit", function (ev) {
  ev.preventDefault();
  start();
});

form.addEventListener("change", function (ev) {
  remember();
  if (ev.target === autoBox) {
    if (autoBox.checked) startClock();
    else stopClock();
    return;
  }
  /* Switching payload while the clock runs restarts it, so what is counting
     down is always what is actually selected. */
  if (ev.target.name === "payload" && autoBox.checked) {
    stopClock();
    startClock();
  }
});

restore();
cacheNote();
/* A landing page opened for a diagnostic must not autostart a full run five
 * seconds later -- the run page is a tap away and the clock would replace it
 * with the thing that gets refused on an unknown firmware. */
var DIAGNOSTIC = /(^|[?&])stop=/.test(location.search);
if (autoBox.checked && !DIAGNOSTIC) startClock();
