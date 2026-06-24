(function () {
  var wrapper = document.getElementById('log-wrapper');
  var feed = document.getElementById('log-feed');
  var isHistory = wrapper && wrapper.dataset.history === 'true';
  var paused = false;

  function togglePause() {
    paused = !paused;
    var label = document.getElementById('pause-label');
    if (label) label.textContent = paused ? 'Resume' : 'Pause';
    var icon = document.getElementById('pause-icon');
    if (icon) {
      icon.className = paused
        ? 'hgi hgi-stroke hgi-rounded hgi-play'
        : 'hgi hgi-stroke hgi-rounded hgi-pause';
    }
    var btn = document.getElementById('pause-btn');
    if (btn) btn.style.color = paused ? '#5DBB7B' : '#64748B';
  }

  var pauseBtn = document.getElementById('pause-btn');
  if (pauseBtn) pauseBtn.addEventListener('click', togglePause);

  if (feed && !isHistory) {
    var obs = new MutationObserver(function () {
      var empty = document.getElementById('empty-state');
      if (empty) empty.remove();
      if (!paused) wrapper.scrollTop = 0;
    });
    obs.observe(feed, { childList: true });
  }

  // The server stores/filters everything in UTC. datetime-local inputs are
  // always in the browser's local time, so convert in both directions: show
  // the server's UTC filter value as local time on load, and convert back
  // to UTC right before the form submits.
  function pad(n) { return String(n).padStart(2, '0'); }
  function utcToLocalInput(utcStr) {
    if (!utcStr) return '';
    var d = new Date(utcStr + ':00Z');
    if (isNaN(d.getTime())) return '';
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
      'T' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  }
  function localInputToUTC(localStr) {
    if (!localStr) return '';
    var d = new Date(localStr);
    return d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()) +
      'T' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes());
  }

  var fromEl = document.getElementById('filter-from');
  var toEl = document.getElementById('filter-to');
  if (fromEl) fromEl.value = utcToLocalInput(fromEl.dataset.utc);
  if (toEl) toEl.value = utcToLocalInput(toEl.dataset.utc);

  var filterForm = document.getElementById('logs-filter-form');
  if (filterForm) {
    filterForm.addEventListener('submit', function () {
      if (fromEl.value) fromEl.value = localInputToUTC(fromEl.value);
      if (toEl.value) toEl.value = localInputToUTC(toEl.value);
    });
  }
})();
