(function () {
  var adminPath = document.body.dataset.adminPath || '';

  var whiteTooltip = {
    enabled: true,
    backgroundColor: '#FFFFFF',
    titleColor: '#0F172A',
    bodyColor: '#0F172A',
    borderColor: '#E2E5EA',
    borderWidth: 1,
    padding: { top: 8, bottom: 8, left: 12, right: 12 },
    cornerRadius: 14,
    displayColors: false,
    bodyFont: { size: 12, weight: '600' },
    boxShadow: '0 4px 16px rgba(0,0,0,0.08)',
  };

  fetch(adminPath + '/api/traffic')
    .then(function (res) { return res.json(); })
    .then(function (traffic) {
      var el = document.getElementById('trafficChart');
      if (!el) return;

      // A single permanent marker on the Allowed line's peak hour, the
      // rest of the line stays bare until hovered (matches the calm,
      // single-highlight look of the reference design).
      var peakIdx = traffic.allowed.indexOf(Math.max.apply(null, traffic.allowed));
      var allowedPointRadius = traffic.allowed.map(function (_, i) {
        return i === peakIdx ? 4 : 0;
      });

      new Chart(el, {
        type: 'line',
        data: {
          labels: traffic.labels,
          datasets: [
            {
              label: 'Allowed',
              data: traffic.allowed,
              borderColor: '#76C893',
              borderWidth: 2,
              tension: 0.4,
              fill: 'origin',
              backgroundColor: function (context) {
                var chartArea = context.chart.chartArea;
                if (!chartArea) return 'rgba(118,200,147,0)';
                var gradient = context.chart.ctx.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
                gradient.addColorStop(0, 'rgba(118,200,147,0.18)');
                gradient.addColorStop(1, 'rgba(118,200,147,0)');
                return gradient;
              },
              pointRadius: allowedPointRadius,
              pointHoverRadius: 5,
              pointBackgroundColor: '#FFFFFF',
              pointHoverBackgroundColor: '#FFFFFF',
              pointBorderColor: '#76C893',
              pointHoverBorderColor: '#76C893',
              pointBorderWidth: 2,
            },
            {
              label: 'Blocked',
              data: traffic.blocked,
              borderColor: '#2B5C74',
              borderWidth: 2,
              tension: 0.4,
              pointRadius: 0,
              pointHoverRadius: 5,
              pointBackgroundColor: '#FFFFFF',
              pointHoverBackgroundColor: '#FFFFFF',
              pointBorderColor: '#2B5C74',
              pointHoverBorderColor: '#2B5C74',
              pointBorderWidth: 2,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: { intersect: false, mode: 'index' },
          plugins: {
            legend: { display: false },
            tooltip: Object.assign({}, whiteTooltip, {
              callbacks: {
                title: function () { return ''; },
                label: function (ctx) { return ctx.dataset.label + ': ' + ctx.raw + ' requests'; },
              },
            }),
          },
          scales: {
            x: { display: false },
            y: {
              beginAtZero: true,
              border: { display: false },
              grid: { color: '#EDEFF2', drawTicks: false, borderDash: [4, 4] },
              ticks: { font: { size: 10 }, color: '#A6ADB8', padding: 8, maxTicksLimit: 4 },
            },
          },
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
            backgroundColor: '#2B5C74',
            borderRadius: 10,
            maxBarThickness: 18,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: Object.assign({}, whiteTooltip, {
              callbacks: {
                title: function () { return ''; },
                label: function (ctx) { return ctx.raw + ' blocked'; },
              },
            }),
          },
          scales: {
            x: { grid: { display: false }, ticks: { font: { size: 11 }, color: '#64748B' } },
            y: { display: false, beginAtZero: true },
          },
        },
      });
    });
})();
