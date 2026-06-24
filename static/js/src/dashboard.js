(function () {
  var adminPath = document.body.dataset.adminPath || '';

  fetch(adminPath + '/api/traffic')
    .then(function (res) { return res.json(); })
    .then(function (traffic) {
      var el = document.getElementById('trafficChart');
      if (!el) return;
      new Chart(el, {
        type: 'line',
        data: {
          labels: traffic.labels,
          datasets: [
            {
              label: 'Allowed',
              data: traffic.allowed,
              borderColor: '#5DBB7B',
              backgroundColor: 'rgba(93,187,123,0.12)',
              fill: true,
              tension: 0.35,
              pointRadius: 0,
              borderWidth: 2,
            },
            {
              label: 'Blocked',
              data: traffic.blocked,
              borderColor: '#2B4870',
              backgroundColor: 'rgba(43,72,112,0.10)',
              fill: true,
              tension: 0.35,
              pointRadius: 0,
              borderWidth: 2,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: { intersect: false, mode: 'index' },
          plugins: { legend: { display: false } },
          scales: {
            x: { display: false },
            y: { display: false, beginAtZero: true },
          },
          elements: { line: { capBezierPoints: true } },
        },
      });
    });

  fetch(adminPath + '/api/threats')
    .then(function (res) { return res.json(); })
    .then(function (threats) {
      var el = document.getElementById('threatsChart');
      if (!el) return;
      new Chart(el, {
        type: 'bar',
        data: {
          labels: threats.labels,
          datasets: [{
            data: threats.counts,
            backgroundColor: '#2B4870',
            borderRadius: 4,
            maxBarThickness: 22,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { display: false }, ticks: { font: { size: 10 }, color: '#64748B' } },
            y: { display: false, beginAtZero: true },
          },
        },
      });
    });
})();
