(function () {
  var wrapper = document.getElementById('log-wrapper');
  var feed = document.getElementById('log-feed');
  var isHistory = wrapper && wrapper.dataset.history === 'true';
  var adminPath = document.body.dataset.adminPath || '';
  var paused = false;
  var stream;

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
    if (btn) {
      btn.classList.toggle('text-brand', paused);
      btn.classList.toggle('text-slate-500', !paused);
    }
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

    if (window.EventSource) {
      stream = new EventSource(adminPath + '/logs/stream');
      stream.onmessage = function (e) {
        feed.insertAdjacentHTML('afterbegin', e.data);
      };
    }
  }

  function closeStream() {
    if (!stream) return;
    stream.close();
    stream = null;
  }

  window.addEventListener('pagehide', closeStream);
  window.addEventListener('beforeunload', closeStream);

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

  // ── Request Detail Modal ──────────────────────────────────────────────────
  var backdrop  = document.getElementById('log-detail-backdrop');
  var closeBtn  = document.getElementById('log-detail-close');

  function esc(s) {
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function statusColor(code) {
    if (code >= 500) return 'text-red-500';
    if (code >= 400) return 'text-amber-500';
    if (code >= 300) return 'text-blue-500';
    return 'text-brand';
  }

  function setText(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val || '—';
  }

  function populateModal(d) {
    // ── Header bar ──────────────────────────────────────────────────
    setText('ld-method', d.method);
    var fullPath = (d.host || '') + d.path + (d.query ? '?' + d.query : '');
    setText('ld-path', fullPath);
    var statusEl = document.getElementById('ld-status');
    if (statusEl) {
      statusEl.textContent = d.status;
      statusEl.className = 'font-bold text-[15px] shrink-0 tabular-nums ' + statusColor(d.status);
    }

    // ── Overview ────────────────────────────────────────────────────
    setText('ld-ts',    d.timestamp ? new Date(d.timestamp).toUTCString() : '—');
    setText('ld-dur',   d.duration_ms + 'ms');
    setText('ld-app',   d.app_name  || '—');
    setText('ld-host',  d.host      || '—');
    setText('ld-ua',    d.user_agent || '—');
    setText('ld-query', d.query     || '(none)');
    setText('ld-reqid', d.request_id || '—');

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

    // ── IPs ─────────────────────────────────────────────────────────
    setText('ld-real-ip',  d.real_ip  || '—');
    setText('ld-proxy-ip', d.proxy_ip || '—');

    // ── Network (ASN / Org) ─────────────────────────────────────────
    setText('ld-asn', d.asn ? 'AS' + d.asn : '—');
    setText('ld-org', d.org || '—');

    // ── Connection (proto / TLS) ────────────────────────────────────
    setText('ld-proto', d.proto || '—');

    var tlsRow = document.getElementById('ld-tls-row');
    var sniRow = document.getElementById('ld-sni-row');
    if (d.tls_version) {
      var tlsText = d.tls_version;
      if (d.tls_cipher) tlsText += ' · ' + d.tls_cipher;
      setText('ld-tls', tlsText);
      if (tlsRow) tlsRow.classList.remove('hidden');
      setText('ld-sni', d.tls_sni || '—');
      if (sniRow) sniRow.classList.remove('hidden');
    } else {
      setText('ld-tls', 'Plaintext / terminated upstream');
      if (tlsRow) tlsRow.classList.remove('hidden');
      if (sniRow) sniRow.classList.add('hidden');
    }

    // ── Bot Analysis ────────────────────────────────────────────────
    var botSection = document.getElementById('ld-bot-section');
    if (botSection) {
      if (d.bot_score || d.ja3_hash) {
        botSection.classList.remove('hidden');
        setText('ld-bot-score', d.bot_score != null ? String(d.bot_score) : '0');
        setText('ld-ja3', d.ja3_hash || '—');
      } else {
        botSection.classList.add('hidden');
      }
    }

    // ── Security ────────────────────────────────────────────────────
    var secEl = document.getElementById('ld-security');
    if (secEl) {
      if (d.blocked) {
        secEl.classList.remove('hidden');
        var reason = d.rule_id ? 'Rule #' + d.rule_id + ' · ' : '';
        reason += d.action || 'blocked';
        setText('ld-block-reason', reason);
      } else {
        secEl.classList.add('hidden');
      }
    }

    // ── Request Headers ─────────────────────────────────────────────
    var hdrsEl = document.getElementById('ld-headers');
    if (hdrsEl) {
      var h = d.headers;
      if (h && Object.keys(h).length) {
        var keys = Object.keys(h).sort();
        hdrsEl.innerHTML = keys.map(function (k, i) {
          var border = i < keys.length - 1 ? ' border-b border-line' : '';
          return '<div class="flex items-start gap-3 px-4 py-[9px]' + border + '">' +
            '<span class="mono text-slate-500 shrink-0 w-[190px] pt-[1px] break-all">' + esc(k) + '</span>' +
            '<span class="mono text-slate-700 flex-1 break-all">' + esc(h[k]) + '</span>' +
            '</div>';
        }).join('');
      } else {
        hdrsEl.innerHTML = '<p class="text-slate-400 p-4">No headers captured.</p>';
      }
    }
  }

  function openDetail(id) {
    fetch(adminPath + '/logs/' + id)
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (d) {
        populateModal(d);
        if (backdrop) backdrop.classList.remove('hidden');
      })
      .catch(function () { /* silently ignore fetch errors */ });
  }

  function closeDetail() {
    if (backdrop) backdrop.classList.add('hidden');
  }

  if (backdrop) {
    backdrop.addEventListener('click', function (e) {
      if (e.target === backdrop) closeDetail();
    });
  }
  if (closeBtn) closeBtn.addEventListener('click', closeDetail);
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeDetail();
  });

  // Event delegation — works for both static rows and SSE-prepended rows.
  if (feed) {
    feed.addEventListener('click', function (e) {
      var row = e.target.closest('[data-log-id]');
      if (row) openDetail(row.dataset.logId);
    });
  }
})();
