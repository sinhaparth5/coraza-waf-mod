// WAF Rules page: load a custom rule into the editor for editing (issue #112).
(function () {
  var form = document.getElementById('custom-rule-form');
  if (!form) return;
  var saveLabel = document.querySelector('#custom-rule-save span');
  var cancel = document.getElementById('custom-rule-cancel');
  var error = document.getElementById('custom-rule-error');

  function load(id, rule, service, note) {
    form.elements.id.value = id;
    form.elements.rules.value = rule;
    form.elements.service.value = service;
    form.elements.note.value = note;
    saveLabel.textContent = id ? 'Update rule' : 'Save rule';
    cancel.classList.toggle('hidden', !id);
    error.textContent = '';
  }

  document.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-custom-edit]');
    if (!btn) return;
    load(btn.dataset.id, btn.dataset.rule, btn.dataset.service, btn.dataset.note);
    form.scrollIntoView({ behavior: 'smooth', block: 'start' });
    form.elements.rules.focus();
  });
  cancel.addEventListener('click', function () { load('', '', '', ''); });
  document.body.addEventListener('custom-rule-saved', function () { load('', '', '', ''); });
})();
