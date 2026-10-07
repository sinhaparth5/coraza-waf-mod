// Logs page: the live table (SSE), the Table/Stats toggle, and the request
// detail modal. Filter controls live in pickers.js; the Stats view in
// logstats.js, which this file feeds through window.czLogStats.
(function () {
  var adminPath = document.body.dataset.adminPath || '';
  var csrf = document.body.dataset.csrf || '';
  var wrapper = document.getElementById('log-wrapper');
  var feed = document.getElementById('log-feed');
  var notice = document.getElementById('logs-notice');
  var live = !!(wrapper && feed && wrapper.dataset.history === 'false');

  // Short-lived message in the status bar's aria-live region.
  var noticeTimer;
  function say(msg) {
    if (!notice) return;
    notice.textContent = msg;
    clearTimeout(noticeTimer);
    noticeTimer = setTimeout(function () { notice.textContent = ''; }, 4000);
  }

  // ── Live table ────────────────────────────────────────────────────────────
  // Rows arrive as server-rendered HTML. They are queued and inserted in one
  // batch every flushDelay ms, so a burst of traffic costs one layout instead
  // of one per request (a timer rather than requestAnimationFrame, which
  // stops in background tabs and would leave one huge insert for the return), and the table keeps only the newest maxRows so a page
  // left open all day stays fast. While paused, or while the user has
  // scrolled down to read, new rows wait in the queue instead of shifting
  // the rows being read; a pill shows how many are waiting.
  var maxRows = 500;
  var flushDelay = 50;
  var followThreshold = 48; // px from the top that still counts as "at the top"
  var queue = [];
  var frame = 0;
  var paused = false;
  var stream = null;

  var pauseBtn = document.getElementById('pause-btn');
  var pauseLabel = document.getElementById('pause-label');
  var pauseIcon = document.getElementById('pause-icon');
  var pill = document.getElementById('new-rows-pill');
  var pillCount = document.getElementById('new-rows-count');
  var statusDot = document.getElementById('live-dot');
  var statusPing = document.getElementById('live-ping');
  var statusText = document.getElementById('live-text');
  var stats = window.czLogStats;

  function atTop() { return wrapper.scrollTop <= followThreshold; }

  function flush() {
    frame = 0;
    if (!queue.length || paused || !atTop()) return updatePill();
    var empty = document.getElementById('empty-state');
    if (empty) empty.remove();
    // queue is oldest-first; the table is newest-first.
    feed.insertAdjacentHTML('afterbegin', queue.reverse().join(''));
    queue = [];
    while (feed.childElementCount > maxRows) feed.lastElementChild.remove();
    wrapper.scrollTop = 0;
    updatePill();
  }

  function scheduleFlush() {
    if (live && !frame) frame = setTimeout(flush, flushDelay);
  }

  function updatePill() {
    if (!pill) return;
    var n = queue.length;
    pill.classList.toggle('hidden', n === 0);
    if (pillCount) pillCount.textContent = n >= maxRows ? maxRows + '+' : String(n);
  }

  function setStatus(state) {
    if (!statusText) return;
    statusText.textContent = { live: 'Live', paused: 'Paused', reconnecting: 'Reconnecting…' }[state];
    statusText.className = state === 'live' ? 'text-green-700' : state === 'paused' ? 'text-slate-600' : 'text-amber-700';
    var color = state === 'live' ? 'bg-brand' : state === 'paused' ? 'bg-slate-400' : 'bg-amber-500';
    [statusDot, statusPing].forEach(function (el) {
      if (!el) return;
      el.classList.remove('bg-brand', 'bg-slate-400', 'bg-amber-500');
      el.classList.add(color);
    });
    if (statusPing) statusPing.classList.toggle('hidden', state !== 'live');
  }

  function setPaused(p) {
    paused = p;
    if (pauseLabel) pauseLabel.textContent = p ? 'Resume' : 'Pause';
    if (pauseIcon) {
      pauseIcon.classList.toggle('hgi-pause', !p);
      pauseIcon.classList.toggle('hgi-play', p);
    }
    if (pauseBtn) {
      pauseBtn.setAttribute('aria-pressed', String(p));
      pauseBtn.classList.toggle('text-brand-dark', p);
      pauseBtn.classList.toggle('text-slate-500', !p);
    }
    if (stats) stats.setPaused(p);
    setStatus(p ? 'paused' : stream && stream.readyState === 1 ? 'live' : 'reconnecting');
    if (!p) {
      wrapper.scrollTop = 0;
      scheduleFlush();
    }
  }

  function openStream() {
    if (stream || !window.EventSource) return;
    stream = new EventSource(adminPath + '/logs/stream');
    stream.onopen = function () { if (!paused) setStatus('live'); };
    // EventSource reconnects on its own; this only reflects it in the UI.
    stream.onerror = function () { if (!paused) setStatus('reconnecting'); };
    stream.onmessage = function (e) {
      queue.push(e.data);
      // Bound the backlog too: past maxRows the oldest waiting rows could
      // never be shown anyway.
      if (queue.length > maxRows) queue.splice(0, queue.length - maxRows);
      scheduleFlush();
    };
    stream.addEventListener('stat', function (e) {
      if (!stats) return;
      try { stats.add(JSON.parse(e.data)); } catch (_) { /* malformed event: skip */ }
    });
  }

  if (live) {
    if (pauseBtn) pauseBtn.addEventListener('click', function () { setPaused(!paused); });
    if (pill) pill.addEventListener('click', function () {
      wrapper.scrollTop = 0;
      if (paused) setPaused(false);
      else scheduleFlush();
    });
    // Scrolling back to the top shows whatever queued up meanwhile.
    wrapper.addEventListener('scroll', function () { if (queue.length && atTop()) scheduleFlush(); }, { passive: true });
    openStream();
    window.addEventListener('pagehide', function () { if (stream) stream.close(); });
  }

  // ── Table / Stats toggle ──────────────────────────────────────────────────
  var tableBtn = document.getElementById('view-table-btn');
  var statsBtn = document.getElementById('view-stats-btn');
  var logCard = document.getElementById('log-card');
  var tableHint = document.getElementById('table-format-hint');
  var statsView = document.getElementById('stats-view');

  function setTabActive(btn, on) {
    btn.classList.toggle('bg-white', on);
    btn.classList.toggle('shadow-xs', on);
    btn.classList.toggle('text-slate-800', on);
    btn.classList.toggle('text-slate-500', !on);
    btn.setAttribute('aria-selected', String(on));
    btn.tabIndex = on ? 0 : -1;
  }

  function setView(view) {
    var isTable = view === 'table';
    if (logCard) logCard.classList.toggle('hidden', !isTable);
    if (tableHint) tableHint.classList.toggle('hidden', !isTable);
    if (statsView) statsView.classList.toggle('hidden', isTable);
    setTabActive(tableBtn, isTable);
    setTabActive(statsBtn, !isTable);
    if (isTable) scheduleFlush();
    else if (stats) stats.show();
    try { sessionStorage.setItem('cz-logs-view', view); } catch (_) { /* storage blocked */ }
  }

  if (tableBtn && statsBtn) {
    tableBtn.addEventListener('click', function () { setView('table'); });
    statsBtn.addEventListener('click', function () { setView('stats'); });
    // Arrow keys switch tabs, per the WAI-ARIA tabs pattern.
    [tableBtn, statsBtn].forEach(function (b) {
      b.addEventListener('keydown', function (e) {
        if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
        var next = b === tableBtn ? statsBtn : tableBtn;
        next.focus();
        next.click();
      });
    });
    var saved = null;
    try { saved = sessionStorage.getItem('cz-logs-view'); } catch (_) { /* storage blocked */ }
    if (saved === 'stats') setView('stats');
  }

  // ── Request detail modal ──────────────────────────────────────────────────
  var backdrop = document.getElementById('log-detail-backdrop');
  var modal = document.getElementById('log-detail-modal');
  var closeBtn = document.getElementById('log-detail-close');
  var feedbackRow = document.getElementById('ld-feedback-row');
  var feedbackStatus = document.getElementById('ld-feedback-status');
  var currentLogID = null;
  var returnFocus = null;
  var loadingID = null;

  function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function statusColor(code) {
    if (code >= 500) return 'text-red-600';
    if (code >= 400) return 'text-amber-600';
    if (code >= 300) return 'text-blue-600';
    return 'text-brand-dark';
  }

  function setText(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val || '—';
  }

  function show(id, on) {
    var el = document.getElementById(id);
    if (el) el.classList.toggle('hidden', !on);
  }

  function populateModal(d) {
    setText('ld-method', d.method);
    var fullPath = (d.host || '') + d.path + (d.query ? '?' + d.query : '');
    setText('ld-path', fullPath);
    var pathEl = document.getElementById('ld-path');
    if (pathEl) pathEl.title = fullPath; // the header truncates long paths
    var statusEl = document.getElementById('ld-status');
    if (statusEl) {
      statusEl.textContent = d.status;
      statusEl.className = 'font-bold text-[15px] shrink-0 tabular-nums ' + statusColor(d.status);
    }
    setText('ld-ts', d.timestamp ? new Date(d.timestamp).toUTCString() : '');
    setText('ld-dur', d.duration_ms + 'ms' + (d.cache_status ? ' · cache ' + d.cache_status : ''));
    setText('ld-app', d.app_name);
    setText('ld-host', d.host);
    setText('ld-ua', d.user_agent);
    setText('ld-query', d.query || '(none)');
    setText('ld-reqid', d.request_id);

    var countryEl = document.getElementById('ld-country');
    if (countryEl) {
      if (d.country) {
        countryEl.innerHTML =
          '<span class="fi fi-' + esc(d.country.toLowerCase()) +
          ' w-4 h-3 bg-cover inline-block rounded-[1px] shrink-0"></span>' +
          '<span>' + esc(d.country) + '</span>';
      } else {
        countryEl.textContent = '—';
      }
    }

    setText('ld-real-ip', d.real_ip);
    setText('ld-proxy-ip', d.proxy_ip);
    setText('ld-asn', d.asn ? 'AS' + d.asn : '');
    setText('ld-org', d.org);
    setText('ld-proto', d.proto);

    setText('ld-tls', d.tls_version
      ? d.tls_version + (d.tls_cipher ? ' · ' + d.tls_cipher : '')
      : 'Plaintext / terminated upstream');
    setText('ld-sni', d.tls_sni);
    show('ld-sni-row', !!d.tls_version);

    var hasBot = !!(d.bot_score || d.ja3_hash || d.ja4 || d.visitor_id);
    show('ld-bot-section', hasBot);
    if (hasBot) {
      setText('ld-bot-score', String(d.bot_score || 0));
      setText('ld-ja4', d.ja4);
      setText('ld-ja3', d.ja3_hash);
      setText('ld-visitor', d.visitor_id);
    }

    show('ld-threat-section', !!d.has_threat_score);
    if (d.has_threat_score) {
      setText('ld-threat-score', d.threat_score + ' / 100');
      setText('ld-threat-breakdown',
        'autoban ' + d.threat_autoban + ' · bot ' + d.threat_bot + ' · asn ' + d.threat_asn +
        ' · geo ' + d.threat_geo + ' · ja4 ' + d.threat_ja4);
    }

    show('ld-security', !!d.blocked);
    if (d.blocked) setText('ld-block-reason', (d.rule_id ? 'Rule #' + d.rule_id + ' · ' : '') + (d.action || 'blocked'));

    if (feedbackStatus) feedbackStatus.textContent = '';
    if (feedbackRow) feedbackRow.classList.toggle('hidden', !(d.blocked && d.rule_id));

    var hdrsEl = document.getElementById('ld-headers');
    if (hdrsEl) {
      var h = d.headers || {};
      var keys = Object.keys(h).sort();
      // Header names and values are client-controlled: escaped before use.
      hdrsEl.innerHTML = keys.length ? keys.map(function (k, i) {
        var border = i < keys.length - 1 ? ' border-b border-line' : '';
        return '<div class="flex flex-col gap-1 px-4 py-[9px] sm:flex-row sm:items-start sm:gap-3' + border + '">' +
          '<span class="font-mono text-slate-500 shrink-0 sm:w-[190px] pt-[1px] break-all">' + esc(k) + '</span>' +
          '<span class="font-mono text-slate-700 flex-1 break-all">' + esc(h[k]) + '</span>' +
          '</div>';
      }).join('') : '<p class="text-slate-500 p-4">No headers captured.</p>';
    }
  }

  function openDetail(row) {
    var id = row.dataset.logId;
    if (!backdrop || loadingID === id) return; // ignore a double click while loading
    loadingID = id;
    row.setAttribute('aria-busy', 'true');
    fetch(adminPath + '/logs/' + id, { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (d) {
        currentLogID = id;
        returnFocus = row;
        populateModal(d);
        backdrop.classList.remove('hidden');
        document.body.classList.add('overflow-hidden');
        var body = modal && modal.querySelector('[data-modal-body]');
        if (body) body.scrollTop = 0;
        if (closeBtn) closeBtn.focus();
      })
      .catch(function () { say('Could not load that request. It may have been pruned; try again.'); })
      .finally(function () {
        loadingID = null;
        row.removeAttribute('aria-busy');
      });
  }

  function closeDetail() {
    if (!backdrop || backdrop.classList.contains('hidden')) return;
    backdrop.classList.add('hidden');
    document.body.classList.remove('overflow-hidden');
    if (returnFocus && document.contains(returnFocus)) returnFocus.focus();
    returnFocus = null;
  }

  function post(url, body) {
    return fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': csrf },
      body: body || ''
    });
  }

  function busy(btn, on) {
    btn.disabled = on;
    btn.classList.toggle('opacity-50', on);
  }

  function feedbackText(msg) {
    if (feedbackStatus) feedbackStatus.textContent = msg;
  }

  function sendFeedback(btn, falsePositive) {
    if (!currentLogID) return;
    busy(btn, true);
    feedbackText('Saving…');
    post(adminPath + '/logs/feedback/' + currentLogID, 'false_positive=' + (falsePositive ? '1' : '0'))
      .then(function (r) { if (!r.ok) throw r.status; })
      .then(function () { feedbackText('Marked ' + (falsePositive ? 'false positive' : 'correct') + '.'); })
      .catch(function () { feedbackText('Failed to save. Try again.'); })
      .finally(function () { busy(btn, false); });
  }

  // Issue #7: disable the blocking rule for this entry's service only.
  function createException(btn) {
    if (!currentLogID || !confirm('Disable this rule for this service? The WAF reloads immediately.')) return;
    busy(btn, true);
    feedbackText('Saving…');
    post(adminPath + '/logs/exception/' + currentLogID)
      .then(function (r) { return r.json().then(function (j) { if (!r.ok) throw j.error; return j; }); })
      .then(function (j) { feedbackText('Rule disabled for ' + j.service + '.'); })
      .catch(function (e) { feedbackText(typeof e === 'string' ? e : 'Failed to save. Try again.'); })
      .finally(function () { busy(btn, false); });
  }

  [['ld-feedback-fp', function (b) { sendFeedback(b, true); }],
   ['ld-feedback-tp', function (b) { sendFeedback(b, false); }],
   ['ld-exception', createException]].forEach(function (pair) {
    var b = document.getElementById(pair[0]);
    if (b) b.addEventListener('click', function () { pair[1](b); });
  });

  if (backdrop) {
    backdrop.addEventListener('click', function (e) { if (e.target === backdrop) closeDetail(); });
    // Keep Tab inside the dialog while it is open.
    backdrop.addEventListener('keydown', function (e) {
      if (e.key !== 'Tab') return;
      var vis = Array.prototype.filter.call(
        modal.querySelectorAll('button:not([disabled]), [href], [tabindex="0"]'),
        function (el) { return el.offsetParent !== null; });
      if (!vis.length) return;
      var first = vis[0], last = vis[vis.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    });
  }
  if (closeBtn) closeBtn.addEventListener('click', closeDetail);
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeDetail(); });

  if (feed) {
    feed.addEventListener('click', function (e) {
      var row = e.target.closest('[data-log-id]');
      if (row) openDetail(row);
    });
    feed.addEventListener('keydown', function (e) {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      var row = e.target.closest('[data-log-id]');
      if (!row) return;
      e.preventDefault();
      openDetail(row);
    });
  }
})();
