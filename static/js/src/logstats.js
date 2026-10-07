// Logs page Stats view: a GoAccess-style live summary. logs.js feeds it the
// JSON "stat" events that arrive on the table's SSE connection (add) and
// tells it when the tab is shown (show) or paused (setPaused); the last
// hour is fetched once, the first time the tab opens.
(function () {
  var statsView = document.getElementById('stats-view');
  if (!statsView) return;
  var adminPath = document.body.dataset.adminPath || '';
  var paused = false;

  var regionNames = null;
  try { regionNames = new Intl.DisplayNames(['en'], { type: 'region' }); } catch (_) {}

  var st = {
    total: 0, blocked: 0, nf: 0, err5: 0, msSum: 0,
    ips: new Set(),
    maps: { path: new Map(), ip: new Map(), why: new Map(), nf: new Map(), status: new Map(), cc: new Map(), app: new Map(), br: new Map(), os: new Map() },
    minutes: new Map() // unix minute -> {n, b}
  };
  var statsSeeded = false, statsSeeding = false;
  // Counting starts when the tab is first opened. Earlier requests are in
  // the seed; ones streamed while it loads wait in pending and are counted
  // only if newer than the seed's newest id, so nothing is counted twice.
  var pending = [];
  var seedMaxID = 0;
  var statsDirty = true;
  var statsMaxKeys = 5000;

  function bump(map, key) {
    if (!key) return;
    map.set(key, (map.get(key) || 0) + 1);
    // ponytail: drops the long tail of one-hit keys once a panel tracks too
    // many (scanners hit thousands of unique paths); fine for a top-10 view.
    if (map.size > statsMaxKeys) map.forEach(function (n, k) { if (n <= 1) map.delete(k); });
  }

  function countStat(e) {
    st.total++;
    st.msSum += e.ms || 0;
    st.ips.add(e.ip);
    if (e.blk) st.blocked++;
    if (e.s === 404) { st.nf++; bump(st.maps.nf, e.p); }
    if (e.s >= 500) st.err5++;
    bump(st.maps.path, e.m + ' ' + e.p);
    bump(st.maps.ip, e.ip);
    if (e.blk) bump(st.maps.why, e.why || 'blocked');
    bump(st.maps.status, String(e.s));
    bump(st.maps.cc, e.cc || '??');
    bump(st.maps.app, e.app);
    bump(st.maps.br, e.br);
    bump(st.maps.os, e.os);
    var min = Math.floor(e.t / 60000);
    var bucket = st.minutes.get(min) || { n: 0, b: 0 };
    bucket.n++;
    if (e.blk) bucket.b++;
    st.minutes.set(min, bucket);
    schedule();
  }

  function loadStatsSeed() {
    if (statsSeeded || statsSeeding) return;
    statsSeeding = true;
    fetch(adminPath + '/logs/stats', { credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(function (data) {
        (data.events || []).forEach(function (e) {
          if (e.id > seedMaxID) seedMaxID = e.id;
          countStat(e);
        });
        pending.forEach(function (e) { if (e.id > seedMaxID) countStat(e); });
        pending = [];
        statsSeeded = true;
        var since = new Date(data.since);
        document.getElementById('st-since').textContent = 'Since ' +
          since.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ' · updates live';
        statsDirty = true;
        renderStats();
      })
      .catch(function () {
        statsSeeded = true;
        pending.forEach(countStat);
        pending = [];
        document.getElementById('st-since').textContent = 'Could not load the last hour — counting live requests only.';
      })
      .finally(function () { statsSeeding = false; });
  }

  var svgNS = 'http://www.w3.org/2000/svg';
  function svgEl(tag, attrs) {
    var el = document.createElementNS(svgNS, tag);
    for (var k in attrs) el.setAttribute(k, attrs[k]);
    return el;
  }

  var monoPanels = { path: 1, ip: 1, why: 1, nf: 1, status: 1 };

  function labelFor(id, key) {
    if (id === 'cc') {
      if (key === '??') return 'Unknown';
      var name = regionNames && regionNames.of(key);
      return name && name !== key ? name + ' (' + key + ')' : key;
    }
    return key;
  }

  // Every label here (paths, IPs, user agents) is client-controlled, so
  // rows are built with textContent/setAttribute, never as HTML.
  function renderPanel(id, map) {
    var list = document.getElementById('st-' + id);
    if (!list) return;
    var rows = Array.from(map.entries()).sort(function (a, b) { return b[1] - a[1]; }).slice(0, 10);
    var sum = 0;
    map.forEach(function (n) { sum += n; });
    list.replaceChildren();
    if (!rows.length) {
      var none = document.createElement('li');
      none.className = 'text-[13px] text-slate-400';
      none.textContent = 'No requests yet';
      list.appendChild(none);
      return;
    }
    var top = rows[0][1];
    rows.forEach(function (row) {
      var li = document.createElement('li');
      var line = document.createElement('div');
      line.className = 'flex items-center gap-3 text-[13px]';
      var name = document.createElement('span');
      name.className = 'min-w-0 flex-1 truncate text-slate-700' + (monoPanels[id] ? ' font-mono' : '');
      name.textContent = labelFor(id, row[0]);
      name.title = row[0];
      var count = document.createElement('span');
      count.className = 'tabular-nums font-semibold text-slate-800';
      count.textContent = row[1].toLocaleString();
      var pct = document.createElement('span');
      pct.className = 'w-12 text-right tabular-nums text-[12px] text-slate-400';
      pct.textContent = (row[1] * 100 / sum).toFixed(1) + '%';
      line.append(name, count, pct);
      var bar = svgEl('svg', { 'class': 'mt-1 h-1 w-full', preserveAspectRatio: 'none', viewBox: '0 0 100 1' });
      bar.appendChild(svgEl('rect', { width: 100, height: 1, 'class': 'fill-slate-100' }));
      bar.appendChild(svgEl('rect', { width: Math.max(1, row[1] * 100 / top), height: 1, 'class': id === 'why' ? 'fill-red-500' : 'fill-brand' }));
      li.append(line, bar);
      list.appendChild(li);
    });
  }

  function renderTimeline() {
    var svg = document.getElementById('st-timeline');
    if (!svg) return;
    var now = Math.floor(Date.now() / 60000);
    st.minutes.forEach(function (_, m) { if (m <= now - 60) st.minutes.delete(m); });
    var max = 1;
    st.minutes.forEach(function (v) { if (v.n > max) max = v.n; });
    svg.replaceChildren();
    for (var i = 0; i < 60; i++) {
      var m = now - 59 + i;
      var v = st.minutes.get(m);
      if (!v) continue;
      var h = v.n * 40 / max, hb = v.b * 40 / max;
      var g = svgEl('g', {});
      var tip = svgEl('title', {});
      tip.textContent = new Date(m * 60000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) +
        ' — ' + v.n + ' requests, ' + v.b + ' blocked';
      g.appendChild(tip);
      g.appendChild(svgEl('rect', { x: i + 0.1, y: 40 - h, width: 0.8, height: h, 'class': 'fill-brand' }));
      if (hb > 0) g.appendChild(svgEl('rect', { x: i + 0.1, y: 40 - hb, width: 0.8, height: hb, 'class': 'fill-red-500' }));
      svg.appendChild(g);
    }
  }

  function renderStats() {
    if (!statsView || statsView.classList.contains('hidden') || paused || !statsDirty) return;
    statsDirty = false;
    var tiles = statsView.querySelectorAll('.st-tile');
    var values = [
      st.total.toLocaleString(),
      st.ips.size.toLocaleString(),
      st.blocked.toLocaleString(),
      st.nf.toLocaleString(),
      st.err5.toLocaleString(),
      st.total ? Math.round(st.msSum / st.total) + ' ms' : '—'
    ];
    tiles.forEach(function (t, i) { t.textContent = values[i]; });
    if (st.total && tiles[2]) {
      var share = document.createElement('span');
      share.className = 'ml-1 text-[13px] font-semibold text-slate-500';
      share.textContent = (st.blocked * 100 / st.total).toFixed(1) + '%';
      tiles[2].appendChild(share);
    }
    for (var id in st.maps) renderPanel(id, st.maps[id]);
    renderTimeline();
  }
  // Repaints are coalesced: however many requests arrive, the DOM is rebuilt
  // at most every 400ms, and only while the tab is visible. The timeline
  // also slides on idle minutes, hence the 30s nudge.
  var renderTimer = null;
  function schedule() {
    statsDirty = true;
    if (renderTimer || statsView.classList.contains('hidden')) return;
    renderTimer = setTimeout(function () { renderTimer = null; renderStats(); }, 400);
  }
  setInterval(schedule, 30000);

  function add(ev) {
    if (!statsSeeded) {
      if (statsSeeding) pending.push(ev);
      return;
    }
    if (ev.id > seedMaxID) countStat(ev);
  }

  window.czLogStats = {
    add: add,
    show: function () {
      loadStatsSeed();
      statsDirty = true;
      renderStats();
    },
    setPaused: function (p) {
      paused = p;
      if (!p) schedule();
    }
  };
})();
