document.addEventListener('DOMContentLoaded', () => {
  const scanBtn = document.getElementById('scan-btn');
  const scanFileBtn = document.getElementById('scan-file-btn');
  const scanInput = document.getElementById('scan-input');
  const fileInput = document.getElementById('file-input');
  const verdictDisplay = document.getElementById('verdict');
  const statusDot = document.getElementById('status');

  statusDot.classList.add('active');

  const dashboardBtn = document.createElement('button');
  dashboardBtn.textContent = 'View Dashboard';
  dashboardBtn.style.cssText = 'width: 100%; margin-top: 10px; background: #424242; color: white; border: none; padding: 10px; border-radius: 6px; cursor: pointer;';
  dashboardBtn.addEventListener('click', () => {
    chrome.tabs.create({ url: 'dashboard.html' });
  });
  document.getElementById('root').appendChild(dashboardBtn);

  scanBtn.addEventListener('click', () => {
    const target = scanInput.value.trim();
    if (!target) return;

    verdictDisplay.textContent = "Scanning URL...";
    verdictDisplay.style.color = "#ffff00";

    chrome.runtime.sendMessage({
      type: "SCAN_REQUEST",
      payload: { action: "scan", target: target }
    }, (response) => {
      if (chrome.runtime.lastError) {
        verdictDisplay.textContent = "Error: " + chrome.runtime.lastError.message;
        verdictDisplay.style.color = "#ff5252";
      } else if (response && response.status === "error") {
        verdictDisplay.textContent = "Connection Error: " + response.error;
        verdictDisplay.style.color = "#ff5252";
      }
    });
  });

  scanFileBtn.addEventListener('click', () => {
    const filePath = fileInput.value.trim();
    if (!filePath) return;

    verdictDisplay.textContent = "Scanning file...";
    verdictDisplay.style.color = "#ffff00";

    chrome.runtime.sendMessage({
      type: "SCAN_REQUEST",
      payload: { action: "scan", target: filePath }
    }, (response) => {
      if (chrome.runtime.lastError) {
        verdictDisplay.textContent = "Error: " + chrome.runtime.lastError.message;
        verdictDisplay.style.color = "#ff5252";
      } else if (response && response.status === "error") {
        verdictDisplay.textContent = "Connection Error: " + response.error;
        verdictDisplay.style.color = "#ff5252";
      }
    });
  });

  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "SCAN_RESULT") {
      const data = message.data;

      if (data.threat_score) {
        const level = data.threat_score.level;
        const score = data.threat_score.score;

        let levelColor = '#00e676';
        if (level === 'MEDIUM') levelColor = '#ffc107';
        if (level === 'HIGH') levelColor = '#f44336';

        verdictDisplay.innerHTML = `
          <div style="padding: 15px; background: #1e1e1e; border-radius: 8px; margin-top: 10px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
              <span style="font-size: 11px; color: #888; text-transform: uppercase;">Threat Level</span>
              <span style="color: ${levelColor}; font-weight: bold; font-size: 14px;">${level}</span>
            </div>
            
            <div style="background: #2a2a2a; border-radius: 6px; height: 8px; overflow: hidden; margin-bottom: 12px;">
              <div style="background: ${levelColor}; height: 100%; width: ${score}%; transition: width 0.3s;"></div>
            </div>
            
            <div style="display: flex; justify-content: space-between; margin-bottom: 12px;">
              <span style="font-size: 11px; color: #888;">Risk Score</span>
              <span style="color: #fff; font-weight: 500;">${score}/100</span>
            </div>
            
            <div style="display: flex; justify-content: space-between; margin-bottom: 15px;">
              <span style="font-size: 11px; color: #888;">Confidence</span>
              <span style="color: #fff; font-weight: 500;">${(data.threat_score.confidence * 100).toFixed(0)}%</span>
            </div>
            
            <div style="border-top: 1px solid #333; padding-top: 12px;">
              <div style="font-size: 11px; color: #888; margin-bottom: 8px; text-transform: uppercase;">Risk Indicators</div>
              ${data.threat_score.indicators.map(ind =>
          `<div style="font-size: 11px; color: #ddd; margin: 4px 0; padding-left: 12px; position: relative;">
                  <span style="position: absolute; left: 0;">•</span>
                  ${ind}
                </div>`
        ).join('')}
            </div>
          </div>
        `;

        verdictDisplay.style.color = "#e0e0e0";

        saveScanToHistory({
          timestamp: data.timestamp || Date.now() / 1000,
          url: scanInput.value,
          type: 'url',
          threat_level: level,
          score: score,
          indicators: data.threat_score.indicators,
          action: 'scanned',
          status: data.status
        });

        if (level === 'HIGH' || score >= 70) {
          chrome.storage.local.set({
            currentThreat: {
              target: scanInput.value,
              ...data
            }
          }, () => {
            chrome.windows.create({
              url: 'warning.html?id=current',
              type: 'popup',
              width: 500,
              height: 700
            });
          });
        }
      } else {
        if (data.status === 'error') {
          verdictDisplay.innerHTML = `<div style="color: #f44336; padding: 10px;">❌ Error: ${data.details}</div>`;
        } else {
          verdictDisplay.textContent = JSON.stringify(data, null, 2);
        }
      }
    }
  });

  async function saveScanToHistory(entry) {
    const result = await chrome.storage.local.get(['scanHistory', 'stats']);
    const history = result.scanHistory || [];
    const stats = result.stats || {
      total_scans: 0,
      threats_blocked: 0,
      last_updated: Date.now()
    };

    history.unshift(entry);
    if (history.length > 100) history.pop();

    stats.total_scans++;
    if (entry.threat_level === 'HIGH') {
      stats.threats_blocked++;
    }
    stats.last_updated = Date.now();

    await chrome.storage.local.set({ scanHistory: history, stats: stats });
  }
});
