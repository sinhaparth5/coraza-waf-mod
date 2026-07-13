// ── Copy-to-clipboard buttons (e.g. the one-time API key reveal) ──────────────
// Delegated on document so it keeps working after an HTMX swap re-renders the
// button (e.g. #api-keys-card), no re-binding needed.
(function () {
  function legacyCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (_) {}
    document.body.removeChild(ta);
    return ok;
  }

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).then(function () { return true; }, function () {
        return legacyCopy(text);
      });
    }
    return Promise.resolve(legacyCopy(text));
  }

  document.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-copy-value]');
    if (!btn) return;

    copyText(btn.getAttribute('data-copy-value') || '').then(function (ok) {
      var icon = btn.querySelector('.copy-btn-icon');
      var label = btn.querySelector('.copy-btn-label');
      if (!icon || !label) return;

      var prevIconClass = icon.className;
      var prevLabel = label.textContent;
      icon.className = 'hgi hgi-stroke hgi-rounded ' + (ok ? 'hgi-checkmark-circle-02' : 'hgi-cancel-circle') + ' text-sm copy-btn-icon';
      label.textContent = ok ? 'Copied' : 'Failed';

      clearTimeout(btn._copyResetTimer);
      btn._copyResetTimer = setTimeout(function () {
        icon.className = prevIconClass;
        label.textContent = prevLabel;
      }, 1500);
    });
  });
})();
