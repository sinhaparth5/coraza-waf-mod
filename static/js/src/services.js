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

// TLS modal — manage upload/auto-issue/clear for a single service row.
// Self-contained so it works even on pages without the add-service wizard.
(function () {
  var overlay = document.getElementById('tls-modal-overlay');
  if (!overlay) return;

  var nameLabel = document.getElementById('tls-modal-service-name');
  var closeBtn = document.getElementById('tls-modal-close');
  var poolForm = document.getElementById('tls-pool-form');
  var uploadForm = document.getElementById('tls-upload-form');
  var autoForm = document.getElementById('tls-auto-form');
  var clearForm = document.getElementById('tls-clear-form');
  var actionRadios = overlay.querySelectorAll('input[name="tls_action"]');
  var error = document.getElementById('tls-error');

  function openModal(id, name) {
    document.querySelectorAll('.tls-service-id').forEach(function (input) {
      input.value = id;
    });
    nameLabel.textContent = name;
    error.textContent = '';
    overlay.classList.remove('hidden');
  }

  function closeModal() {
    overlay.classList.add('hidden');
  }

  document.addEventListener('click', function (e) {
    var btn = e.target.closest('.tls-manage-btn');
    if (btn) openModal(btn.dataset.id, btn.dataset.name);
  });

  closeBtn.addEventListener('click', closeModal);
  overlay.addEventListener('click', function (e) {
    if (e.target === overlay) closeModal();
  });

  function syncTLSForms() {
    var val = (overlay.querySelector('input[name="tls_action"]:checked') || {}).value;
    if (poolForm) poolForm.classList.toggle('hidden', val !== 'pool');
    uploadForm.classList.toggle('hidden', val !== 'upload');
    autoForm.classList.toggle('hidden', val !== 'auto');
  }

  actionRadios.forEach(function (radio) {
    radio.addEventListener('change', syncTLSForms);
  });
  syncTLSForms();

  // Server fires this (via HX-Trigger) after a successful save/clear.
  document.body.addEventListener('tls-saved', closeModal);
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
    var tlsOverlay = document.getElementById('tls-modal-overlay');
    if (tlsOverlay) tlsOverlay.classList.add('hidden');
  });
})();

// Rate Limit modal — set or clear per-service rate limiting.
(function () {
  var overlay = document.getElementById('rl-modal-overlay');
  if (!overlay) return;

  var nameLabel = document.getElementById('rl-modal-service-name');
  var closeBtn  = document.getElementById('rl-modal-close');
  var idInput   = document.getElementById('rl-service-id');
  var rpsInput  = document.getElementById('rl-rps');
  var burstInput = document.getElementById('rl-burst');

  function openModal(id, name, rps, burst) {
    idInput.value    = id;
    nameLabel.textContent = name;
    rpsInput.value   = rps > 0 ? rps : '';
    burstInput.value = burst > 0 ? burst : '';
    overlay.classList.remove('hidden');
    rpsInput.focus();
  }

  function closeModal() { overlay.classList.add('hidden'); }

  document.addEventListener('click', function (e) {
    var btn = e.target.closest('.rl-manage-btn');
    if (btn) openModal(btn.dataset.id, btn.dataset.name,
                       parseFloat(btn.dataset.rps) || 0,
                       parseInt(btn.dataset.burst) || 0);
  });

  closeBtn.addEventListener('click', closeModal);
  overlay.addEventListener('click', function (e) { if (e.target === overlay) closeModal(); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !overlay.classList.contains('hidden')) closeModal();
  });

  document.body.addEventListener('rl-saved', closeModal);
})();

// Bot Protection modal — set per-service bot mode (inherit / always / off).
(function () {
  var overlay   = document.getElementById('bot-modal-overlay');
  if (!overlay) return;

  var nameLabel = document.getElementById('bot-modal-service-name');
  var closeBtn  = document.getElementById('bot-modal-close');
  var form      = document.getElementById('bot-form');
  var idInput   = document.getElementById('bot-service-id');

  function openModal(id, name, mode) {
    idInput.value = id;
    nameLabel.textContent = name;
    var adminPath = form.dataset.adminPath || '/admin';
    form.setAttribute('hx-post', adminPath + '/services/bot/' + id);
    htmx.process(form);
    var radio = overlay.querySelector('input[value="' + (mode || 'inherit') + '"]');
    if (radio) radio.checked = true;
    overlay.classList.remove('hidden');
  }

  function closeModal() { overlay.classList.add('hidden'); }

  document.addEventListener('click', function (e) {
    var btn = e.target.closest('.bot-manage-btn');
    if (btn) openModal(btn.dataset.id, btn.dataset.name, btn.dataset.mode);
  });

  closeBtn.addEventListener('click', closeModal);
  overlay.addEventListener('click', function (e) { if (e.target === overlay) closeModal(); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !overlay.classList.contains('hidden')) closeModal();
  });

  document.body.addEventListener('htmx:afterRequest', function (e) {
    if (e.detail.elt === form && e.detail.successful) closeModal();
  });
})();
