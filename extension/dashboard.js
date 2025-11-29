async function loadDashboard() {
    const result = await chrome.storage.local.get(['scanHistory', 'stats']);
    const history = result.scanHistory || [];
    const stats = result.stats || {
        total_scans: 0,
        threats_blocked: 0,
        last_updated: Date.now()
    };

    document.getElementById('totalScans').textContent = stats.total_scans;
    document.getElementById('threatsBlocked').textContent = stats.threats_blocked;

    const safetyScore = stats.total_scans > 0
        ? Math.round((1 - stats.threats_blocked / stats.total_scans) * 100)
        : 100;
    document.getElementById('safetyScore').textContent = safetyScore + '%';

    const historyBody = document.getElementById('historyBody');
    const emptyState = document.getElementById('emptyState');

    if (history.length === 0) {
        document.getElementById('threatTable').style.display = 'none';
        emptyState.style.display = 'block';
        return;
    }

    historyBody.innerHTML = '';
    history.forEach(entry => {
        const row = document.createElement('tr');

        const date = new Date(entry.timestamp * 1000);
        const timeStr = date.toLocaleTimeString() + ' ' + date.toLocaleDateString();

        const url = entry.url.length > 50
            ? entry.url.substring(0, 50) + '...'
            : entry.url;

        row.innerHTML = `
            <td>${timeStr}</td>
            <td title="${entry.url}">${url}</td>
            <td><span class="threat-level-badge ${entry.threat_level.toLowerCase()}">${entry.threat_level}</span></td>
            <td>${entry.score}/100</td>
            <td><span class="action-badge ${entry.action}">${entry.action.toUpperCase()}</span></td>
        `;

        historyBody.appendChild(row);
    });
}

document.getElementById('exportBtn').addEventListener('click', async () => {
    const result = await chrome.storage.local.get(['scanHistory']);
    const history = result.scanHistory || [];

    if (history.length === 0) {
        alert('No scan history to export');
        return;
    }

    let csv = 'Timestamp,URL,Threat Level,Score,Action,Indicators\n';

    history.forEach(entry => {
        const date = new Date(entry.timestamp * 1000);
        const indicators = entry.indicators.join('; ');
        csv += `"${date.toISOString()}","${entry.url}","${entry.threat_level}",${entry.score},"${entry.action}","${indicators}"\n`;
    });

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel_report_${Date.now()}.csv`;
    a.click();
});

const exportJsonBtn = document.createElement('button');
exportJsonBtn.textContent = 'Export Report (JSON)';
exportJsonBtn.className = 'btn-export';
exportJsonBtn.style.marginLeft = '10px';
exportJsonBtn.addEventListener('click', async () => {
    const result = await chrome.storage.local.get(['scanHistory', 'stats']);

    if (!result.scanHistory || result.scanHistory.length === 0) {
        alert('No scan history to export');
        return;
    }

    const exportData = {
        exported_at: new Date().toISOString(),
        stats: result.stats || {},
        scans: result.scanHistory || []
    };

    const json = JSON.stringify(exportData, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel_data_${Date.now()}.json`;
    a.click();
});
document.getElementById('exportBtn').parentElement.appendChild(exportJsonBtn);

document.addEventListener('DOMContentLoaded', loadDashboard);
