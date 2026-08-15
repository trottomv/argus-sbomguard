(function () {
    'use strict';

    var ctx = document.getElementById('trendChart');
    if (!ctx || typeof Chart === 'undefined') {
        return;
    }

    var data;
    try {
        data = JSON.parse(ctx.getAttribute('data-chart'));
    } catch (e) {
        return;
    }

    var chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.labels,
            datasets: [
                { label: 'Critical', data: data.critical, borderColor: '#f38ba8', backgroundColor: '#f38ba820', pointBackgroundColor: '#f38ba8', tension: 0.3, fill: true },
                { label: 'High', data: data.high, borderColor: '#fab387', backgroundColor: '#fab38720', pointBackgroundColor: '#fab387', tension: 0.3, fill: true },
                { label: 'Medium', data: data.medium, borderColor: '#f9e2af', backgroundColor: '#f9e2af20', pointBackgroundColor: '#f9e2af', tension: 0.3, fill: true },
                { label: 'Low', data: data.low, borderColor: '#a6e3a1', backgroundColor: '#a6e3a120', pointBackgroundColor: '#a6e3a1', tension: 0.3, fill: true },
                { label: 'Fixed', data: data.fixed, borderColor: '#89b4fa', backgroundColor: '#89b4fa30', pointBackgroundColor: '#89b4fa', tension: 0.3, fill: true, borderDash: [5, 5] }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { intersect: false, mode: 'index' },
            plugins: {
                legend: {
                    position: 'bottom',
                    align: 'start',
                    labels: { color: '#a6adc8', usePointStyle: true, padding: 20 },
                    onClick: function (event, item) {
                        var meta = chart.getDatasetMeta(item.datasetIndex);
                        meta.hidden = !meta.hidden;
                        chart.update();
                    }
                }
            },
            scales: {
                x: { ticks: { color: '#6c7086', maxTicksLimit: 10 }, grid: { color: '#313244' } },
                y: { ticks: { color: '#6c7086', precision: 0 }, grid: { color: '#313244' }, beginAtZero: true }
            }
        }
    });
})();
