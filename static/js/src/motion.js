// ── Page motion: entrance stagger, stat count-up, hidden replay/Easter eggs ────
// Every effect here is decorative-only and disabled under prefers-reduced-motion.
(function () {
  var reduced = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;

  function stagger(items, stepMs, cap) {
    for (var i = 0; i < items.length && i < cap; i++) {
      items[i].style.animationDelay = (i * stepMs) + 'ms';
      items[i].classList.add('anim-in');
    }
  }

  // Cards rise in one after another on page load; any [data-stagger]
  // container does the same for its direct children.
  if (!reduced) {
    stagger(document.querySelectorAll('main .card'), 40, 8);
    document.querySelectorAll('[data-stagger]').forEach(function (box) {
      stagger(box.children, 40, 12);
    });
  }

  // Stat numbers count up to their value (~600ms, ease-out). The target is
  // remembered on the element so it can be replayed (see donut below).
  function countUp(el) {
    var target = parseInt(el.dataset.countupTarget || el.textContent.replace(/[^0-9]/g, ''), 10);
    if (isNaN(target) || target <= 0) return;
    el.dataset.countupTarget = String(target);
    var start = null;
    function tick(ts) {
      if (start === null) start = ts;
      var p = Math.min((ts - start) / 600, 1);
      el.textContent = String(Math.round(target * (1 - Math.pow(1 - p, 3))));
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }
  if (!reduced) document.querySelectorAll('[data-countup]').forEach(countUp);

  // Hidden: click the request-breakdown donut and it redraws itself —
  // arcs sweep in again and the center number recounts.
  var donut = document.getElementById('donut-ring');
  if (donut && !reduced) {
    var donutBox = donut.parentElement;
    donutBox.addEventListener('click', function () {
      donut.querySelectorAll('.donut-arc').forEach(function (arc) {
        arc.classList.remove('donut-arc');
        void arc.getBoundingClientRect();
        arc.classList.add('donut-arc');
      });
      donutBox.querySelectorAll('[data-countup]').forEach(countUp);
    });
  }

  // Hidden: click the sidebar shield 5 times within 2s and the whole nav salutes.
  var logo = document.getElementById('brand-logo');
  if (!logo) return;
  var clicks = [];
  logo.addEventListener('click', function () {
    var now = Date.now();
    clicks = clicks.filter(function (t) { return now - t < 2000; });
    clicks.push(now);
    if (clicks.length < 5 || reduced) return;
    clicks = [];
    logo.classList.remove('guard');
    void logo.offsetWidth; // restart the animation if it's mid-run
    logo.classList.add('guard');
    var icons = document.querySelectorAll('aside nav a i');
    icons.forEach(function (icon, idx) {
      setTimeout(function () {
        icon.classList.add('nudge');
        icon.addEventListener('animationend', function () { icon.classList.remove('nudge'); }, { once: true });
      }, 120 + idx * 60);
    });
  });
})();
