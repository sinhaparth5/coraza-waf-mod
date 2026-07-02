(function () {
  var adminPath = document.body.dataset.adminPath || '';
  var panel = document.getElementById('notif-panel');
  var btn = document.getElementById('notif-btn');

  if (!panel || !btn) return;

  function isOpen() {
    return !panel.classList.contains('hidden');
  }

  function closePanel() {
    panel.classList.add('hidden');
  }

  function updateBadge(n) {
    var existing = document.getElementById('notif-badge');
    if (n <= 0) {
      if (existing) existing.remove();
      return;
    }
    var text = n > 9 ? '9+' : String(n);
    if (existing) {
      existing.textContent = text;
      return;
    }
    existing = document.createElement('span');
    existing.id = 'notif-badge';
    existing.className = 'absolute -top-[3px] -right-[3px] bg-red-500 text-white text-[9px] font-bold rounded-full min-w-[16px] h-4 flex items-center justify-center px-[3px] border-2 border-white';
    existing.textContent = text;
    btn.appendChild(existing);
  }

  function markAllRead() {
    fetch(adminPath + '/api/notifications/seen', {
      method: 'POST',
      headers: { 'X-CSRF-Token': document.body.dataset.csrf || '' }
    }).then(function () {
      updateBadge(0);
    });
  }

  var stream;
  if (window.EventSource) {
    stream = new EventSource(adminPath + '/api/notifications/stream');
    stream.addEventListener('count', function (e) {
      updateBadge(parseInt(e.data, 10));
    });
    stream.addEventListener('toast', function (e) {
      try { showToast(JSON.parse(e.data)); } catch (_) {}
    });
  }

  function closeStream() {
    if (!stream) return;
    stream.close();
    stream = null;
  }

  window.addEventListener('pagehide', closeStream);
  window.addEventListener('beforeunload', closeStream);

  function openPanel() {
    panel.classList.remove('hidden');
    fetch(adminPath + '/api/notifications')
      .then(function (res) { return res.text(); })
      .then(function (html) {
        panel.innerHTML = html;
        var markBtn = document.getElementById('notif-mark-read');
        if (markBtn) markBtn.addEventListener('click', markAllRead);
      });
  }

  btn.addEventListener('click', function () {
    if (isOpen()) {
      closePanel();
    } else {
      openPanel();
    }
  });

  document.addEventListener('click', function (e) {
    if (isOpen() && !panel.contains(e.target) && !btn.contains(e.target)) {
      closePanel();
    }
  });
})();

// ── Frosted-glass iOS-style toast notifications ───────────────────────────────
function showToast(data) {
  var container = document.getElementById('toast-container');
  if (!container) return;

  var CONFIGS = {
    waf:  { label: 'WAF BLOCKED',  title: 'Request Blocked',    color: '#007AFF', bg: 'rgba(0,122,255,0.10)',  icon: 'hgi-shield-01' },
    geo:  { label: 'GEO BLOCKED',  title: 'Country Blocked',    color: '#FF9500', bg: 'rgba(255,149,0,0.10)', icon: 'hgi-earth' },
    ip:   { label: 'IP BLOCKED',   title: 'IP Address Blocked', color: '#FF3B30', bg: 'rgba(255,59,48,0.10)', icon: 'hgi-cancel-circle' },
    rate: { label: 'RATE LIMITED', title: 'Too Many Requests',  color: '#FF9500', bg: 'rgba(255,149,0,0.10)', icon: 'hgi-time-04' },
  };

  function getCfg(action) {
    var a = (action || '').toLowerCase();
    if (a === 'rate_limited')    return CONFIGS.rate;
    if (a.indexOf('geo') !== -1) return CONFIGS.geo;
    if (a.indexOf('ip')  !== -1) return CONFIGS.ip;
    return CONFIGS.waf;
  }

  var cfg      = getCfg(data.action);
  var subtitle = (data.ip || '') + (data.country ? ' · ' + data.country : '');
  var body     = (data.method || 'GET') + ' ' + (data.path || '/');

  // Outer card — frosted glass
  var toast = document.createElement('div');
  toast.style.cssText = [
    'position:relative', 'overflow:hidden', 'cursor:pointer', 'pointer-events:auto',
    'display:flex', 'align-items:flex-start', 'gap:10px', 'width:100%', 'padding:14px',
    'border-radius:20px', 'border:1px solid rgba(255,255,255,0.90)',
    'background:rgba(255,255,255,0.80)',
    'backdrop-filter:blur(40px)', '-webkit-backdrop-filter:blur(40px)',
    'box-shadow:0 12px 40px rgba(0,0,0,0.10),0 0 0 1px rgba(0,0,0,0.04)',
    'transform:translateX(110%)', 'opacity:0',
    'transition:transform .35s cubic-bezier(.22,.68,0,1.2),opacity .3s',
  ].join(';');

  // Shimmer decoration (bottom-right)
  var shimmer = document.createElement('div');
  shimmer.style.cssText = [
    'position:absolute', 'right:-24px', 'bottom:-24px',
    'width:120px', 'height:60px', 'border-radius:10px',
    'opacity:.18', 'pointer-events:none',
    'background:conic-gradient(from 196deg at 50% 50%,rgba(66,232,255,0.009) 5deg,rgba(255,126,171,0.50) 185deg,#3083FF 275deg,#7147FF 360deg)',
  ].join(';');
  toast.appendChild(shimmer);

  // Icon box — tinted per action type
  var iconBox = document.createElement('div');
  iconBox.style.cssText = 'width:38px;height:38px;border-radius:10px;flex-shrink:0;margin-top:1px;display:flex;align-items:center;justify-content:center;background:' + cfg.bg + ';';
  iconBox.innerHTML = '<i class="hgi hgi-stroke hgi-rounded ' + cfg.icon + ' text-base" style="color:' + cfg.color + ';"></i>';

  // Content
  var content = document.createElement('div');
  content.style.cssText = 'flex:1;min-width:0;';

  var row = document.createElement('div');
  row.style.cssText = 'display:flex;align-items:flex-start;justify-content:space-between;gap:8px;';

  var left = document.createElement('div');
  left.style.cssText = 'flex:1;min-width:0;';

  var pLabel = document.createElement('p');
  pLabel.style.cssText = 'font-size:11px;font-weight:600;letter-spacing:.06em;line-height:16px;color:' + cfg.color + ';';
  pLabel.textContent = cfg.label;

  var pTitle = document.createElement('p');
  pTitle.style.cssText = 'font-size:15px;font-weight:700;line-height:20px;letter-spacing:-.02em;color:rgba(0,0,0,0.85);';
  pTitle.textContent = cfg.title;

  var pSub = document.createElement('p');
  pSub.style.cssText = 'font-size:15px;font-weight:600;line-height:20px;letter-spacing:-.02em;color:rgba(0,0,0,0.50);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;';
  pSub.textContent = subtitle;

  var pTime = document.createElement('p');
  pTime.style.cssText = 'font-size:12px;color:rgba(0,0,0,0.35);flex-shrink:0;margin-top:1px;white-space:nowrap;';
  pTime.textContent = 'just now';

  var pBody = document.createElement('p');
  pBody.style.cssText = 'font-size:13px;font-family:monospace;color:rgba(0,0,0,0.35);line-height:18px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-top:3px;';
  pBody.textContent = body;

  left.appendChild(pLabel);
  left.appendChild(pTitle);
  left.appendChild(pSub);
  row.appendChild(left);
  row.appendChild(pTime);
  content.appendChild(row);
  content.appendChild(pBody);
  toast.appendChild(iconBox);
  toast.appendChild(content);
  container.prepend(toast);

  // Animate in
  requestAnimationFrame(function () {
    requestAnimationFrame(function () {
      toast.style.transform = 'translateX(0)';
      toast.style.opacity = '1';
    });
  });

  function dismiss() {
    toast.style.transform = 'translateX(110%)';
    toast.style.opacity = '0';
    setTimeout(function () { if (toast.parentNode) toast.remove(); }, 350);
  }

  var timer = setTimeout(dismiss, 5000);
  toast.addEventListener('mouseenter', function () { clearTimeout(timer); });
  toast.addEventListener('mouseleave', function () { timer = setTimeout(dismiss, 2000); });
  toast.addEventListener('click',      function () { clearTimeout(timer); dismiss(); });
}
