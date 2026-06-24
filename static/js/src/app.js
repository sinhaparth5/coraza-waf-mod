(function () {
  var adminPath = document.body.dataset.adminPath || '';
  var panel = document.getElementById('notif-panel');
  var btn = document.getElementById('notif-btn');

  if (!panel || !btn) return;

  function isOpen() {
    return panel.style.display === 'block';
  }

  function closePanel() {
    panel.style.display = 'none';
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
    existing.style.cssText = 'position:absolute; top:-3px; right:-3px; background:#EF4444; color:#fff; font-size:9px; font-weight:700; border-radius:999px; min-width:16px; height:16px; display:flex; align-items:center; justify-content:center; padding:0 3px; border:2px solid #fff;';
    existing.textContent = text;
    btn.appendChild(existing);
  }

  function markAllRead() {
    fetch(adminPath + '/api/notifications/seen', { method: 'POST' }).then(function () {
      updateBadge(0);
    });
  }

  if (window.EventSource) {
    var stream = new EventSource(adminPath + '/api/notifications/stream');
    stream.onmessage = function (e) {
      updateBadge(parseInt(e.data, 10));
    };
  }

  function openPanel() {
    panel.style.display = 'block';
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
