// ── Toast notifications ───────────────────────────────────────────────────────
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
    if (a.indexOf('rate_limited') === 0) return CONFIGS.rate; // covers "rate_limited:adaptive"
    if (a.indexOf('geo') !== -1) return CONFIGS.geo;
    if (a.indexOf('ip')  !== -1) return CONFIGS.ip;
    return CONFIGS.waf;
  }

  var cfg      = getCfg(data.action);
  var subtitle = (data.ip || '') + (data.country ? ' · ' + data.country : '');
  var body     = (data.method || 'GET') + ' ' + (data.path || '/');

  var toast = document.createElement('div');
  toast.style.cssText = [
    'position:relative', 'overflow:hidden', 'cursor:pointer', 'pointer-events:auto',
    'display:flex', 'align-items:flex-start', 'gap:10px', 'width:100%', 'padding:14px',
    'border-radius:10px', 'border:1px solid #D8DDE3',
    'background:#fff',
    'box-shadow:0 4px 12px rgba(16,24,40,0.10)',
    'transform:translateX(110%)', 'opacity:0',
    'transition:transform .3s cubic-bezier(.22,.68,0,1.2),opacity .25s',
  ].join(';');

  // Icon box — tinted per action type
  var iconBox = document.createElement('div');
  iconBox.style.cssText = 'width:38px;height:38px;border-radius:8px;flex-shrink:0;margin-top:1px;display:flex;align-items:center;justify-content:center;background:' + cfg.bg + ';';
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
