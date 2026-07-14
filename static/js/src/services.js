(function () {
  var wizard = document.getElementById('service-wizard');
  if (!wizard) return;

  var form = document.getElementById('service-form');
  var steps = wizard.querySelectorAll('.wizard-step');
  var dots = wizard.querySelectorAll('.wizard-dot');
  var nextBtn = document.getElementById('wizard-next');
  var backBtn = document.getElementById('wizard-back');
  var submitBtn = document.getElementById('wizard-submit');
  var review = document.getElementById('wizard-review');
  var total = steps.length;
  var current = 1;

  function goToStep(n) {
    current = n;
    steps.forEach(function (step) {
      step.classList.toggle('hidden', Number(step.dataset.step) !== n);
    });
    dots.forEach(function (dot) {
      var active = Number(dot.dataset.dot) <= n;
      dot.classList.toggle('bg-brand', active);
      dot.classList.toggle('bg-line', !active);
    });
    backBtn.classList.toggle('hidden', n <= 1);
    nextBtn.classList.toggle('hidden', n >= total);
    submitBtn.classList.toggle('hidden', n !== total);
  }

  // Manual validation only — native required/checkValidity() is unreliable
  // here because steps 2-4 are display:none until reached, and a hidden
  // invalid control can't be focused for the validation bubble (Chrome logs
  // "is not focusable" and silently swallows the submit).
  function validateCurrentStep() {
    var step = wizard.querySelector('.wizard-step[data-step="' + current + '"]');
    var inputs = step.querySelectorAll('input[type="text"]');
    var ok = true;
    inputs.forEach(function (input) {
      var err = input.parentElement.querySelector('.step-error');
      if (input.value.trim() === '') {
        ok = false;
        if (err) err.classList.remove('hidden');
      } else if (err) {
        err.classList.add('hidden');
      }
    });
    return ok;
  }

  function populateReview() {
    var name = form.querySelector('input[name="name"]').value;
    var matchType = form.querySelector('input[name="match_type"]:checked').value;
    var matchValue = form.querySelector('input[name="match_value"]').value;
    var backend = form.querySelector('input[name="backend"]').value;
    var rps = parseFloat(form.querySelector('input[name="rps"]').value) || 0;
    var burst = parseInt(form.querySelector('input[name="burst"]').value) || 0;

    var pairs = [
      ['Name', name],
      [matchType === 'host' ? 'Host' : 'Path prefix', matchValue],
      ['Backend', backend],
    ];
    if (rps > 0) pairs.push(['Rate limit', rps + '/s' + (burst > 0 ? ', burst ' + burst : ', burst auto')]);

    review.innerHTML = '';
    pairs.forEach(function (pair) {
      var row = document.createElement('div');
      row.className = 'flex justify-between gap-[10px]';
      var label = document.createElement('span');
      label.className = 'text-slate-500';
      label.textContent = pair[0];
      var value = document.createElement('span');
      value.className = 'font-semibold text-slate-800 text-right break-all';
      value.textContent = pair[1];
      row.appendChild(label);
      row.appendChild(value);
      review.appendChild(row);
    });
  }

  function goNext() {
    if (!validateCurrentStep()) return;
    if (current === total - 1) populateReview();
    if (current < total) goToStep(current + 1);
  }

  nextBtn.addEventListener('click', goNext);

  backBtn.addEventListener('click', function () {
    if (current > 1) goToStep(current - 1);
  });

  // Enter key in a text field should advance the wizard, not trigger the
  // browser's implicit form submission (which would run native validation
  // against still-hidden later steps).
  form.addEventListener('keydown', function (e) {
    if (e.key !== 'Enter') return;
    if (current < total) {
      e.preventDefault();
      goNext();
    }
  });

  window.resetServiceWizard = function () {
    goToStep(1);
  };

  goToStep(1);
})();

// Edit-service modal — one popup for every per-service setting (rate limit,
// bot mode, cache, TLS) plus removal. Rows carry labels only + an Edit button.
(function () {
  var overlay = document.getElementById('svc-modal-overlay');
  if (!overlay) return;

  var nameLabel = document.getElementById('svc-modal-service-name');
  var closeBtn = document.getElementById('svc-modal-close');
  var tabBtns = overlay.querySelectorAll('.svc-tab-btn');
  var tabs = overlay.querySelectorAll('.svc-tab');

  var rlIdInput = document.getElementById('rl-service-id');
  var rpsInput = document.getElementById('rl-rps');
  var burstInput = document.getElementById('rl-burst');
  var botForm = document.getElementById('bot-form');
  var botIdInput = document.getElementById('bot-service-id');
  var cacheForm = document.getElementById('svc-cache-form');
  var cacheToggle = document.getElementById('svc-cache-enabled');
  var cacheSessionForm = document.getElementById('svc-cache-session-form');
  var cacheSessionToggle = document.getElementById('svc-cache-session-enabled');
  var cacheSessionCookie = document.getElementById('svc-cache-session-cookie');
  var cacheTuningForm = document.getElementById('svc-cache-tuning-form');
  var ttlFloorInput = document.getElementById('svc-cache-ttl-floor');
  var ttlCeilingInput = document.getElementById('svc-cache-ttl-ceiling');
  var graceInput = document.getElementById('svc-cache-grace');
  var keepInput = document.getElementById('svc-cache-keep');
  var cachePurgeForm = document.getElementById('svc-cache-purge-form');
  var cachePurgeStatus = document.getElementById('svc-cache-purge-status');
  var deleteBtn = document.getElementById('svc-delete-btn');

  function showTab(name) {
    tabs.forEach(function (tab) {
      tab.classList.toggle('hidden', tab.dataset.tab !== name);
    });
    tabBtns.forEach(function (btn) {
      var active = btn.dataset.tab === name;
      btn.classList.toggle('bg-white', active);
      btn.classList.toggle('shadow-sm', active);
      btn.classList.toggle('text-slate-900', active);
      btn.classList.toggle('bg-transparent', !active);
      btn.classList.toggle('text-slate-500', !active);
    });
  }

  tabBtns.forEach(function (btn) {
    btn.addEventListener('click', function () { showTab(btn.dataset.tab); });
  });

  function openModal(d) {
    var adminPath = botForm.dataset.adminPath || '/admin';
    nameLabel.textContent = d.name;

    rlIdInput.value = d.id;
    rpsInput.value = parseFloat(d.rps) > 0 ? d.rps : '';
    burstInput.value = parseInt(d.burst) > 0 ? d.burst : '';

    botIdInput.value = d.id;
    botForm.setAttribute('hx-post', adminPath + '/services/bot/' + d.id);
    htmx.process(botForm);
    var radio = overlay.querySelector('input[name="bot_mode"][value="' + (d.mode || 'inherit') + '"]');
    if (radio) radio.checked = true;

    cacheForm.setAttribute('hx-post', adminPath + '/services/cache/' + d.id);
    htmx.process(cacheForm);
    cacheToggle.checked = d.cache === '1';

    cacheSessionForm.setAttribute('hx-post', adminPath + '/services/cache-session/' + d.id);
    htmx.process(cacheSessionForm);
    cacheSessionToggle.checked = d.sessionCache === '1';
    cacheSessionCookie.value = d.sessionCookie || '';

    cacheTuningForm.setAttribute('hx-post', adminPath + '/services/cache-tuning/' + d.id);
    htmx.process(cacheTuningForm);
    ttlFloorInput.value = parseInt(d.ttlFloor) > 0 ? d.ttlFloor : '';
    ttlCeilingInput.value = parseInt(d.ttlCeiling) > 0 ? d.ttlCeiling : '';
    graceInput.value = parseInt(d.grace) > 0 ? d.grace : '';
    keepInput.value = parseInt(d.keep) > 0 ? d.keep : '';

    cachePurgeForm.setAttribute('hx-post', adminPath + '/services/cache-purge/' + d.id);
    htmx.process(cachePurgeForm);
    cachePurgeStatus.textContent = '';

    document.querySelectorAll('.tls-service-id').forEach(function (input) {
      input.value = d.id;
    });
    // TLS termination resolves certs by SNI, which needs a domain — the tab
    // only applies to host-matched services.
    overlay.querySelector('.svc-tab-btn[data-tab="tls"]').classList.toggle('hidden', d.hasHost !== '1');

    deleteBtn.setAttribute('hx-delete', '/admin/services/' + d.id);
    deleteBtn.setAttribute('hx-confirm', 'Remove service ' + d.name + '?');
    htmx.process(deleteBtn);

    ['tls-error', 'rl-error', 'bot-error', 'svc-cache-error', 'svc-cache-session-error', 'svc-cache-tuning-error'].forEach(function (id) {
      var el = document.getElementById(id);
      if (el) el.textContent = '';
    });

    showTab('ratelimit');
    overlay.classList.remove('hidden');
  }

  function closeModal() {
    overlay.classList.add('hidden');
  }

  document.addEventListener('click', function (e) {
    var btn = e.target.closest('.svc-edit-btn');
    if (btn) openModal(btn.dataset);
  });

  closeBtn.addEventListener('click', closeModal);
  overlay.addEventListener('click', function (e) {
    if (e.target === overlay) closeModal();
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !overlay.classList.contains('hidden')) closeModal();
  });

  // TLS action radios switch between the pool / upload / auto forms.
  var poolForm = document.getElementById('tls-pool-form');
  var uploadForm = document.getElementById('tls-upload-form');
  var autoForm = document.getElementById('tls-auto-form');
  function syncTLSForms() {
    var val = (overlay.querySelector('input[name="tls_action"]:checked') || {}).value;
    if (poolForm) poolForm.classList.toggle('hidden', val !== 'pool');
    uploadForm.classList.toggle('hidden', val !== 'upload');
    autoForm.classList.toggle('hidden', val !== 'auto');
  }
  overlay.querySelectorAll('input[name="tls_action"]').forEach(function (radio) {
    radio.addEventListener('change', syncTLSForms);
  });
  syncTLSForms();

  // Close on success. The TLS and rate-limit handlers signal success with
  // explicit HX-Trigger events — their error paths also return 200,
  // retargeted into the in-modal error boxes, so a bare afterRequest can't
  // be trusted for them. The bot/cache forms and the delete button return
  // real error statuses, so afterRequest.successful is meaningful there.
  document.body.addEventListener('tls-saved', closeModal);
  document.body.addEventListener('rl-saved', closeModal);
  document.body.addEventListener('htmx:afterRequest', function (e) {
    var elt = e.detail.elt;
    if ((elt === botForm || elt === cacheForm || elt === cacheSessionForm || elt === cacheTuningForm || elt === deleteBtn) && e.detail.successful) closeModal();
    // Purge intentionally does not close the modal — its status fragment
    // (success or error) renders inline so the admin sees the outcome.
  });
})();

// ACME email modal — shown when auto-TLS is requested but no email is stored.
(function () {
  var overlay  = document.getElementById('acme-email-modal-overlay');
  if (!overlay) return;

  var closeBtn  = document.getElementById('acme-email-modal-close');
  var idInput   = document.getElementById('acme-email-service-id');
  var emailInput = document.getElementById('acme-email-input');

  function openModal(serviceId) {
    idInput.value = serviceId || '';
    document.getElementById('acme-email-error').textContent = '';
    overlay.classList.remove('hidden');
    emailInput.focus();
  }

  function closeModal() { overlay.classList.add('hidden'); }

  closeBtn.addEventListener('click', closeModal);
  overlay.addEventListener('click', function (e) { if (e.target === overlay) closeModal(); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !overlay.classList.contains('hidden')) closeModal();
  });

  // Server fires this when EnableServiceAutoTLS finds no email in DB.
  document.body.addEventListener('need-acme-email', function (e) {
    openModal(e.detail && e.detail.service_id);
  });

  // Server fires this after SaveAcmeEmail succeeds — close both modals.
  document.body.addEventListener('acme-email-saved', function () {
    closeModal();
    var svcOverlay = document.getElementById('svc-modal-overlay');
    if (svcOverlay) svcOverlay.classList.add('hidden');
  });
})();
