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
