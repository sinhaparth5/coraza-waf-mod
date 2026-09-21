// Settings page: register/remove passkeys (issue #78). HTMX can't drive
// this — registering a passkey needs the browser's own WebAuthn ceremony
// (navigator.credentials.create()) between the begin/finish requests, not
// just a form POST — so this talks to the backend with plain fetch.
(function () {
  var card = document.getElementById('passkeys-card');
  if (!card) return;

  var adminPath = document.body.dataset.adminPath || '';
  function csrf() { return document.body.dataset.csrf || ''; }

  function b64urlToBuf(b64url) {
    var pad = '='.repeat((4 - (b64url.length % 4)) % 4);
    var b64 = (b64url + pad).replace(/-/g, '+').replace(/_/g, '/');
    var str = atob(b64);
    var buf = new Uint8Array(str.length);
    for (var i = 0; i < str.length; i++) buf[i] = str.charCodeAt(i);
    return buf.buffer;
  }
  function bufToB64url(buf) {
    var bytes = new Uint8Array(buf);
    var str = '';
    for (var i = 0; i < bytes.byteLength; i++) str += String.fromCharCode(bytes[i]);
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function decodeCreationOptions(opts) {
    opts.challenge = b64urlToBuf(opts.challenge);
    opts.user.id = b64urlToBuf(opts.user.id);
    (opts.excludeCredentials || []).forEach(function (c) { c.id = b64urlToBuf(c.id); });
    return opts;
  }

  function encodeAttestation(cred) {
    return {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        attestationObject: bufToB64url(cred.response.attestationObject),
        clientDataJSON: bufToB64url(cred.response.clientDataJSON)
      }
    };
  }

  function setStatus(msg, isError) {
    var el = document.getElementById('pk-status');
    if (!el) return;
    el.textContent = msg;
    el.className = 'text-[12px] mb-4 ' + (isError ? 'text-red-600' : 'text-green-700');
  }

  function swapCard(html) {
    var wrapper = document.createElement('div');
    wrapper.innerHTML = html;
    var fresh = wrapper.firstElementChild;
    if (!fresh) return;
    card.replaceWith(fresh);
    card = fresh;
    bind();
  }

  function registerPasskey() {
    var nameField = document.getElementById('pk-name');
    var name = nameField ? nameField.value : '';
    setStatus('Registering…', false);
    fetch(adminPath + '/settings/passkeys/begin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() },
      body: JSON.stringify({ name: name })
    })
      .then(function (r) { return r.json(); })
      .then(function (opts) {
        if (opts.error) throw new Error(opts.error);
        return navigator.credentials.create({ publicKey: decodeCreationOptions(opts.publicKey) });
      })
      .then(function (cred) {
        return fetch(adminPath + '/settings/passkeys/finish', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() },
          body: JSON.stringify(encodeAttestation(cred))
        });
      })
      .then(function (r) {
        if (!r.ok) return r.json().then(function (j) { throw new Error(j.error || 'Registration failed.'); });
        return r.text();
      })
      .then(swapCard)
      .catch(function (err) {
        setStatus(err.message || 'Registration failed.', true);
      });
  }

  function deletePasskey(id) {
    fetch(adminPath + '/settings/passkeys/' + id, {
      method: 'DELETE',
      headers: { 'X-CSRF-Token': csrf() }
    })
      .then(function (r) { return r.text(); })
      .then(swapCard);
  }

  function bind() {
    var btn = document.getElementById('pk-register-btn');
    if (btn) btn.addEventListener('click', registerPasskey);
    card.querySelectorAll('.pk-delete-btn').forEach(function (b) {
      b.addEventListener('click', function () { deletePasskey(b.dataset.id); });
    });
  }

  bind();
})();
