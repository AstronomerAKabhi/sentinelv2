async function getThreatData() {
    const urlParams = new URLSearchParams(window.location.search);
    const threatId = urlParams.get('id');

    if (threatId) {
        const result = await chrome.storage.local.get(['currentThreat']);
        return result.currentThreat;
    }

    return {
        target: "https://example-phishing-site.com",
        threat_score: {
            level: "HIGH",
            score: 85,
            confidence: 0.92,
            indicators: [
                "Suspicious domain pattern",
                "No SSL certificate",
                "Known phishing keywords detected",
                "Domain registered recently"
            ]
        },
        isolation_method: "firecracker_microvm",
        timestamp: Date.now() / 1000
    };
}

function displayThreat(data) {
    const level = data.threat_score.level.toLowerCase();
    const score = data.threat_score.score;
    const confidence = data.threat_score.confidence;

    const header = document.getElementById('modalHeader');
    header.className = `modal-header ${level}`;

    const icon = document.getElementById('threatIcon');
    if (level === 'high') {
        icon.textContent = '🛑';
    } else if (level === 'medium') {
        icon.textContent = '⚠️';
    } else {
        icon.textContent = 'ℹ️';
    }

    document.getElementById('headerText').textContent =
        level === 'high' ? 'CRITICAL THREAT DETECTED' :
            level === 'medium' ? 'POTENTIAL THREAT DETECTED' :
                'LOW RISK DETECTED';

    const scoreBar = document.getElementById('scoreBar');
    scoreBar.className = `score-bar ${level}`;
    scoreBar.style.width = `${score}%`;
    scoreBar.textContent = `${score}/100`;

    document.getElementById('confidenceText').textContent =
        `Analysis Confidence: ${(confidence * 100).toFixed(0)}%`;

    document.getElementById('targetUrl').textContent =
        data.target.substring(0, 40) + (data.target.length > 40 ? '...' : '');
    document.getElementById('targetUrl').title = data.target;

    document.getElementById('threatLevel').textContent =
        data.threat_score.level;

    const date = new Date(data.timestamp * 1000);
    document.getElementById('scanTime').textContent =
        date.toLocaleTimeString();

    document.getElementById('isolationMethod').textContent =
        data.isolation_method.replace('_', ' ').toUpperCase();

    const indicatorsList = document.getElementById('indicatorsList');
    indicatorsList.innerHTML = '';
    data.threat_score.indicators.forEach(indicator => {
        const item = document.createElement('div');
        item.className = 'indicator-item';
        item.textContent = indicator;
        indicatorsList.appendChild(item);
    });
}

document.getElementById('blockBtn').addEventListener('click', async () => {
    const data = await getThreatData();

    if (data.downloadId) {
        chrome.downloads.cancel(data.downloadId);
    }

    await saveScanHistory(data, 'blocked');

    window.close();
});

document.getElementById('allowBtn').addEventListener('click', async () => {
    const data = await getThreatData();

    if (data.downloadId) {
        chrome.downloads.resume(data.downloadId);
    } else {
        chrome.tabs.update({ url: data.target });
    }

    await saveScanHistory(data, 'allowed');

    window.close();
});

document.getElementById('detailsBtn').addEventListener('click', () => {
    chrome.tabs.create({ url: 'dashboard.html' });
});

async function saveScanHistory(data, action) {
    const historyEntry = {
        timestamp: data.timestamp,
        url: data.target,
        type: 'url',
        threat_level: data.threat_score.level,
        score: data.threat_score.score,
        indicators: data.threat_score.indicators,
        action: action
    };

    const result = await chrome.storage.local.get(['scanHistory', 'stats']);
    const history = result.scanHistory || [];
    const stats = result.stats || {
        total_scans: 0,
        threats_blocked: 0,
        last_updated: Date.now()
    };

    history.unshift(historyEntry);

    if (history.length > 100) {
        history.pop();
    }

    stats.total_scans++;
    if (action === 'blocked') {
        stats.threats_blocked++;
    }
    stats.last_updated = Date.now();

    await chrome.storage.local.set({
        scanHistory: history,
        stats: stats
    });
}

document.addEventListener('DOMContentLoaded', async () => {
    const data = await getThreatData();
    displayThreat(data);
});
