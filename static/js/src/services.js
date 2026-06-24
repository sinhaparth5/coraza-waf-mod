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

    review.innerHTML = '';
    [
      ['Name', name],
      [matchType === 'host' ? 'Host' : 'Path prefix', matchValue],
      ['Backend', backend],
    ].forEach(function (pair) {
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

  actionRadios.forEach(function (radio) {
    radio.addEventListener('change', function () {
      var isUpload = overlay.querySelector('input[name="tls_action"]:checked').value === 'upload';
      uploadForm.classList.toggle('hidden', !isUpload);
      autoForm.classList.toggle('hidden', isUpload);
    });
  });

  // Server fires this (via HX-Trigger) after a successful save/clear.
  document.body.addEventListener('tls-saved', closeModal);
})();
