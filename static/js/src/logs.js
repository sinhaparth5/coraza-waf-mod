(function () {
  // ── Shared utilities ─────────────────────────────────────────────────────
  function dpPad(n) { return String(n).padStart(2, '0'); }

  function parseDateStr(s) {
    if (!s) return null;
    var m = s.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/);
    if (!m) return null;
    return { y: +m[1], mo: +m[2] - 1, d: +m[3], h: +m[4], mi: +m[5] };
  }

  function buildDateStr(sel) {
    if (!sel) return '';
    return sel.y + '-' + dpPad(sel.mo + 1) + '-' + dpPad(sel.d) + 'T' + dpPad(sel.h) + ':' + dpPad(sel.mi);
  }

  var MONTH_NAMES = ['January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December'];
  var MONTH_SHORT = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
    'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

  // ── DatePicker ─────────────────────────────────────────────────────────────
  // All values are UTC — log timestamps are UTC so filtering in UTC is natural.
  function DatePicker(hiddenEl, btnEl, displayEl) {
    var self = this;
    self.hidden = hiddenEl;
    self.btn = btnEl;
    self.display = displayEl;
    self.sel = parseDateStr(hiddenEl.value);

    var now = new Date();
    self.viewY = self.sel ? self.sel.y : now.getUTCFullYear();
    self.viewMo = self.sel ? self.sel.mo : now.getUTCMonth();
    self.viewMode = 'days';
    self.yearBase = Math.floor(self.viewY / 12) * 12;
    self.isOpen = false;

    self.pop = document.createElement('div');
    self.pop.className = 'fixed z-[250] bg-white border border-line rounded-[18px] select-none overflow-hidden';
    self.pop.style.cssText = 'display:none;box-shadow:0 8px 40px rgba(0,0,0,.15);width:272px;';
    self.pop.__dp = self;
    document.body.appendChild(self.pop);

    // Stop popover clicks bubbling to the document close handler
    self.pop.addEventListener('click', function (e) { e.stopPropagation(); });

    self.updateDisplay();

    btnEl.addEventListener('click', function (e) {
      e.stopPropagation();
      if (self.isOpen) { self.close(); return; }
      closeAll();
      self.open();
    });
  }

  DatePicker.prototype.open = function () {
    this.isOpen = true;
    this.viewMode = 'days';
    this.render();
    this.pop.style.display = 'block';
    this.pop.classList.add('__dpop');
    this.reposition();
  };

  DatePicker.prototype.close = function () {
    this.isOpen = false;
    this.pop.classList.remove('__dpop');
    this.pop.style.display = 'none';
  };

  DatePicker.prototype.reposition = function () {
    var r = this.btn.getBoundingClientRect();
    var top = r.bottom + 6;
    var left = r.left;
    if (left + 272 > window.innerWidth - 8) left = window.innerWidth - 272 - 8;
    this.pop.style.top = top + 'px';
    this.pop.style.left = left + 'px';
  };

  DatePicker.prototype.updateDisplay = function () {
    if (this.sel) {
      this.display.textContent = MONTH_SHORT[this.sel.mo] + ' ' + this.sel.d + ', ' + this.sel.y +
        ' ' + dpPad(this.sel.h) + ':' + dpPad(this.sel.mi) + ' UTC';
      this.display.classList.remove('text-slate-400');
      this.display.classList.add('text-slate-700');
    } else {
      this.display.textContent = 'Any date';
      this.display.classList.remove('text-slate-700');
      this.display.classList.add('text-slate-400');
    }
  };

  DatePicker.prototype.render = function () {
    if (this.viewMode === 'days') this.renderDays();
    else if (this.viewMode === 'months') this.renderMonths();
    else this.renderYears();
  };

  DatePicker.prototype.renderDays = function () {
    var self = this;
    var y = self.viewY, m = self.viewMo;
    var now = new Date();
    var todY = now.getUTCFullYear(), todMo = now.getUTCMonth(), todD = now.getUTCDate();
    var firstDOW = new Date(Date.UTC(y, m, 1)).getUTCDay();
    var startOff = (firstDOW + 6) % 7;   // Mon=0 … Sun=6
    var dim = new Date(Date.UTC(y, m + 1, 0)).getUTCDate();
    var prevLast = new Date(Date.UTC(y, m, 0)).getUTCDate();
    var selH = self.sel ? dpPad(self.sel.h) : '00';
    var selMi = self.sel ? dpPad(self.sel.mi) : '00';

    var html = '<div class="p-3">';
    // ── Header ──
    html += '<div class="flex items-center justify-between mb-2">';
    html += btn('dp-prev', '<i class="hgi hgi-stroke hgi-rounded hgi-arrow-left-01 text-[11px]"></i>',
      'w-7 h-7 flex items-center justify-center rounded-lg hover:bg-surface text-slate-400');
    html += '<button type="button" class="dp-head text-[13px] font-semibold text-slate-700 hover:text-brand rounded-lg px-2 py-1 cursor-pointer">' +
      MONTH_NAMES[m] + ' ' + y + '</button>';
    html += btn('dp-next', '<i class="hgi hgi-stroke hgi-rounded hgi-arrow-right-01 text-[11px]"></i>',
      'w-7 h-7 flex items-center justify-center rounded-lg hover:bg-surface text-slate-400');
    html += '</div>';
    // ── Weekday headers ──
    html += '<div class="grid grid-cols-7 mb-[3px]">';
    ['Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa', 'Su'].forEach(function (d, i) {
      html += '<div class="h-6 flex items-center justify-center text-[10px] font-semibold ' +
        (i >= 5 ? 'text-red-400' : 'text-slate-400') + '">' + d + '</div>';
    });
    html += '</div>';
    // ── Day grid ──
    html += '<div class="grid grid-cols-7 gap-y-px">';
    // Prev-month trailing days
    for (var i = startOff - 1; i >= 0; i--) {
      var pd = prevLast - i;
      var pm = m === 0 ? 11 : m - 1;
      var py = m === 0 ? y - 1 : y;
      html += dayBtn(py, pm, pd, pd, 'text-slate-300 hover:bg-surface');
    }
    // Current-month days
    for (var d = 1; d <= dim; d++) {
      var isSel = self.sel && self.sel.y === y && self.sel.mo === m && self.sel.d === d;
      var isToday = y === todY && m === todMo && d === todD;
      var dow = (new Date(Date.UTC(y, m, d)).getUTCDay() + 6) % 7;
      var cls = isSel
        ? 'bg-brand text-white font-semibold'
        : (dow >= 5 ? 'text-red-500' : 'text-slate-700') + ' hover:bg-surface';
      html += '<button type="button" class="dp-day h-7 text-[12px] rounded-lg relative cursor-pointer ' + cls + '" ' +
        'data-y="' + y + '" data-m="' + m + '" data-d="' + d + '">' + d;
      if (isToday && !isSel) html += '<span class="absolute bottom-[1px] left-1/2 -translate-x-1/2 w-[3px] h-[3px] rounded-full bg-brand block"></span>';
      html += '</button>';
    }
    // Next-month leading days
    var rem = (7 - ((startOff + dim) % 7)) % 7;
    for (var nd = 1; nd <= rem; nd++) {
      var nm = m === 11 ? 0 : m + 1;
      var ny = m === 11 ? y + 1 : y;
      html += dayBtn(ny, nm, nd, nd, 'text-slate-300 hover:bg-surface');
    }
    html += '</div>';
    // ── Time ──
    html += '<div class="flex items-center gap-2 mt-3 pt-3 border-t border-line">';
    html += '<i class="hgi hgi-stroke hgi-rounded hgi-clock-01 text-slate-400 text-[13px] shrink-0"></i>';
    html += '<input class="dp-hour border border-line rounded-[8px] w-11 text-center text-[13px] py-[5px] outline-none text-slate-700 tabular-nums focus:border-brand" type="number" min="0" max="23" value="' + selH + '">';
    html += '<span class="text-slate-400 text-[14px] font-semibold select-none">:</span>';
    html += '<input class="dp-min border border-line rounded-[8px] w-11 text-center text-[13px] py-[5px] outline-none text-slate-700 tabular-nums focus:border-brand" type="number" min="0" max="59" value="' + selMi + '">';
    html += '<span class="text-[10px] text-slate-400 font-semibold uppercase tracking-wider ml-1 select-none">UTC</span>';
    html += '</div>';
    // ── Actions ──
    html += '<div class="flex items-center justify-between mt-3">';
    html += '<button type="button" class="dp-clear text-[12px] text-slate-400 hover:text-slate-600 cursor-pointer py-1">Clear</button>';
    html += '<button type="button" class="dp-apply text-[13px] font-semibold text-white bg-brand px-4 py-[7px] rounded-[9px] cursor-pointer">Apply</button>';
    html += '</div></div>';

    self.pop.innerHTML = html;

    // Navigation
    self.pop.querySelector('.dp-prev').addEventListener('click', function () {
      if (self.viewMo === 0) { self.viewY--; self.viewMo = 11; } else { self.viewMo--; }
      self.render();
    });
    self.pop.querySelector('.dp-next').addEventListener('click', function () {
      if (self.viewMo === 11) { self.viewY++; self.viewMo = 0; } else { self.viewMo++; }
      self.render();
    });
    self.pop.querySelector('.dp-head').addEventListener('click', function () {
      self.yearBase = Math.floor(self.viewY / 12) * 12;
      self.viewMode = 'years';
      self.render();
    });

    function timeInputs() {
      return {
        h: Math.min(23, Math.max(0, parseInt(self.pop.querySelector('.dp-hour').value) || 0)),
        mi: Math.min(59, Math.max(0, parseInt(self.pop.querySelector('.dp-min').value) || 0))
      };
    }

    self.pop.querySelectorAll('.dp-day').forEach(function (b) {
      b.addEventListener('click', function () {
        var t = timeInputs();
        self.sel = { y: +b.dataset.y, mo: +b.dataset.m, d: +b.dataset.d, h: t.h, mi: t.mi };
        self.viewY = self.sel.y; self.viewMo = self.sel.mo;
        self.render();
      });
    });
    self.pop.querySelector('.dp-clear').addEventListener('click', function () {
      self.sel = null; self.hidden.value = ''; self.updateDisplay(); self.close();
    });
    self.pop.querySelector('.dp-apply').addEventListener('click', function () {
      if (self.sel) {
        var t = timeInputs();
        self.sel = { y: self.sel.y, mo: self.sel.mo, d: self.sel.d, h: t.h, mi: t.mi };
      }
      self.hidden.value = buildDateStr(self.sel);
      self.updateDisplay();
      self.close();
    });
  };

  DatePicker.prototype.renderMonths = function () {
    var self = this;
    var y = self.viewY;

    var html = '<div class="p-3">';
    html += '<div class="flex items-center justify-between mb-3">';
    html += btn('dp-prev-y', '<i class="hgi hgi-stroke hgi-rounded hgi-arrow-left-01 text-[11px]"></i>',
      'w-7 h-7 flex items-center justify-center rounded-lg hover:bg-surface text-slate-400');
    html += '<button type="button" class="dp-to-yrs text-[13px] font-semibold text-slate-700 hover:text-brand px-2 py-1 rounded-lg cursor-pointer">' + y + '</button>';
    html += btn('dp-next-y', '<i class="hgi hgi-stroke hgi-rounded hgi-arrow-right-01 text-[11px]"></i>',
      'w-7 h-7 flex items-center justify-center rounded-lg hover:bg-surface text-slate-400');
    html += '</div><div class="grid grid-cols-3 gap-1">';
    MONTH_SHORT.forEach(function (mn, i) {
      var isSel = self.sel && self.sel.y === y && self.sel.mo === i;
      html += '<button type="button" class="dp-month h-9 text-[12px] font-medium rounded-lg cursor-pointer ' +
        (isSel ? 'bg-brand text-white' : 'text-slate-700 hover:bg-surface') +
        '" data-m="' + i + '">' + mn + '</button>';
    });
    html += '</div></div>';
    self.pop.innerHTML = html;

    self.pop.querySelector('.dp-prev-y').addEventListener('click', function () { self.viewY--; self.render(); });
    self.pop.querySelector('.dp-next-y').addEventListener('click', function () { self.viewY++; self.render(); });
    self.pop.querySelector('.dp-to-yrs').addEventListener('click', function () {
      self.yearBase = Math.floor(self.viewY / 12) * 12; self.viewMode = 'years'; self.render();
    });
    self.pop.querySelectorAll('.dp-month').forEach(function (b) {
      b.addEventListener('click', function () { self.viewMo = +b.dataset.m; self.viewMode = 'days'; self.render(); });
    });
  };

  DatePicker.prototype.renderYears = function () {
    var self = this;
    var base = self.yearBase;

    var html = '<div class="p-3">';
    html += '<div class="flex items-center justify-between mb-3">';
    html += btn('dp-prev-yr', '<i class="hgi hgi-stroke hgi-rounded hgi-arrow-left-01 text-[11px]"></i>',
      'w-7 h-7 flex items-center justify-center rounded-lg hover:bg-surface text-slate-400');
    html += '<span class="text-[12px] font-semibold text-slate-500 select-none">' + base + ' – ' + (base + 11) + '</span>';
    html += btn('dp-next-yr', '<i class="hgi hgi-stroke hgi-rounded hgi-arrow-right-01 text-[11px]"></i>',
      'w-7 h-7 flex items-center justify-center rounded-lg hover:bg-surface text-slate-400');
    html += '</div><div class="grid grid-cols-3 gap-1">';
    for (var yr = base; yr < base + 12; yr++) {
      var isSel = self.sel && self.sel.y === yr;
      html += '<button type="button" class="dp-year h-9 text-[12px] font-medium rounded-lg cursor-pointer ' +
        (isSel ? 'bg-brand text-white' : 'text-slate-700 hover:bg-surface') +
        '" data-y="' + yr + '">' + yr + '</button>';
    }
    html += '</div></div>';
    self.pop.innerHTML = html;

    self.pop.querySelector('.dp-prev-yr').addEventListener('click', function () { self.yearBase -= 12; self.render(); });
    self.pop.querySelector('.dp-next-yr').addEventListener('click', function () { self.yearBase += 12; self.render(); });
    self.pop.querySelectorAll('.dp-year').forEach(function (b) {
      b.addEventListener('click', function () { self.viewY = +b.dataset.y; self.viewMode = 'months'; self.render(); });
    });
  };

  // HTML helpers
  function btn(cls, inner, extra) {
    return '<button type="button" class="' + cls + ' ' + (extra || '') + ' cursor-pointer">' + inner + '</button>';
  }
  function dayBtn(y, m, d, label, extra) {
    return '<button type="button" class="dp-day h-7 text-[12px] rounded-lg cursor-pointer ' + extra + '" ' +
      'data-y="' + y + '" data-m="' + m + '" data-d="' + d + '">' + label + '</button>';
  }

  // ── CustomSelect ───────────────────────────────────────────────────────────
  function CustomSelect(hiddenEl, btnEl, displayEl, dropdownEl) {
    var self = this;
    self.hidden = hiddenEl;
    self.btn = btnEl;
    self.display = displayEl;
    self.dropdown = dropdownEl;
    self.isOpen = false;

    // Init display from server-rendered value
    var cur = hiddenEl.value;
    var opts = dropdownEl.querySelectorAll('button[data-value]');
    opts.forEach(function (opt) {
      if (opt.dataset.value === cur) {
        displayEl.textContent = opt.dataset.label;
        opt.classList.add('text-brand', 'font-semibold');
      }
    });

    dropdownEl.addEventListener('click', function (e) { e.stopPropagation(); });

    btnEl.addEventListener('click', function (e) {
      e.stopPropagation();
      if (self.isOpen) { self.close(); return; }
      closeAll();
      self.open();
    });

    opts.forEach(function (opt) {
      opt.addEventListener('click', function () {
        self.hidden.value = opt.dataset.value;
        displayEl.textContent = opt.dataset.label;
        opts.forEach(function (o) {
          o.classList.toggle('text-brand', o === opt);
          o.classList.toggle('font-semibold', o === opt);
        });
        self.close();
      });
    });
  }

  CustomSelect.prototype.open = function () {
    this.isOpen = true;
    this.dropdown.classList.remove('hidden');
    this.dropdown.classList.add('__csel');
  };

  CustomSelect.prototype.close = function () {
    this.isOpen = false;
    this.dropdown.classList.add('hidden');
    this.dropdown.classList.remove('__csel');
  };

  // ── Close-all helper ───────────────────────────────────────────────────────
  function closeAll() {
    document.querySelectorAll('.__dpop').forEach(function (p) { if (p.__dp) p.__dp.close(); });
    document.querySelectorAll('.__csel').forEach(function (d) {
      d.classList.add('hidden'); d.classList.remove('__csel');
    });
  }

  document.addEventListener('click', closeAll);
  window.addEventListener('resize', function () {
    document.querySelectorAll('.__dpop').forEach(function (p) { if (p.__dp) p.__dp.reposition(); });
  });

  // ── Initialize pickers ────────────────────────────────────────────────────
  function initDP(hiddenId, btnId, displayId) {
    var h = document.getElementById(hiddenId);
    var b = document.getElementById(btnId);
    var d = document.getElementById(displayId);
    if (h && b && d) new DatePicker(h, b, d);
  }
  function initCS(hiddenId, btnId, displayId, dropId) {
    var h = document.getElementById(hiddenId);
    var b = document.getElementById(btnId);
    var d = document.getElementById(displayId);
    var dr = document.getElementById(dropId);
    if (h && b && d && dr) new CustomSelect(h, b, d, dr);
  }

  initDP('filter-from', 'filter-from-btn', 'filter-from-display');
  initDP('filter-to', 'filter-to-btn', 'filter-to-display');
  initCS('filter-app', 'filter-app-btn', 'filter-app-display', 'filter-app-dropdown');
  initCS('filter-status', 'filter-status-btn', 'filter-status-display', 'filter-status-dropdown');

  // ── Live stream ───────────────────────────────────────────────────────────
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
    var pb = document.getElementById('pause-btn');
    if (pb) {
      pb.classList.toggle('text-brand', paused);
      pb.classList.toggle('text-slate-500', !paused);
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
    stream.close(); stream = null;
  }
  window.addEventListener('pagehide', closeStream);
  window.addEventListener('beforeunload', closeStream);

  // ── Request Detail Modal ──────────────────────────────────────────────────
  var backdrop = document.getElementById('log-detail-backdrop');
  var closeBtn = document.getElementById('log-detail-close');

  function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
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
    setText('ld-method', d.method);
    var fullPath = (d.host || '') + d.path + (d.query ? '?' + d.query : '');
    setText('ld-path', fullPath);
    var statusEl = document.getElementById('ld-status');
    if (statusEl) {
      statusEl.textContent = d.status;
      statusEl.className = 'font-bold text-[15px] shrink-0 tabular-nums ' + statusColor(d.status);
    }
    setText('ld-ts', d.timestamp ? new Date(d.timestamp).toUTCString() : '—');
    setText('ld-dur', d.duration_ms + 'ms');
    setText('ld-app', d.app_name || '—');
    setText('ld-host', d.host || '—');
    setText('ld-ua', d.user_agent || '—');
    setText('ld-query', d.query || '(none)');
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

    setText('ld-real-ip', d.real_ip || '—');
    setText('ld-proxy-ip', d.proxy_ip || '—');
    setText('ld-asn', d.asn ? 'AS' + d.asn : '—');
    setText('ld-org', d.org || '—');
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
      .catch(function () { });
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

  if (feed) {
    feed.addEventListener('click', function (e) {
      var row = e.target.closest('[data-log-id]');
      if (row) openDetail(row.dataset.logId);
    });
  }
})();
