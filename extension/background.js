let port = null;
let threatCount = 0;

function connectToNativeHost() {
  const hostName = "com.sentinel.host";
  console.log(`Connecting to native host: ${hostName}`);
  port = chrome.runtime.connectNative(hostName);

  port.onMessage.addListener((message) => {
    console.log("Received message from native host:", message);

    if (message.threat_score) {
      handleThreatResult(message);
    }

    chrome.runtime.sendMessage({ type: "SCAN_RESULT", data: message }).catch(() => { });
  });

  port.onDisconnect.addListener(() => {
    console.log("Disconnected from native host");
    if (chrome.runtime.lastError) {
      console.error("Error:", chrome.runtime.lastError.message);
    }
    port = null;
  });
}

function handleThreatResult(data) {
  const level = data.threat_score.level;
  const score = data.threat_score.score;

  if (level === 'HIGH') {
    threatCount++;
    chrome.action.setBadgeText({ text: threatCount.toString() });
    chrome.action.setBadgeBackgroundColor({ color: '#f44336' });
  }

  if (level === 'MEDIUM' || level === 'HIGH') {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: chrome.runtime.getURL('popup.html'),
      title: `⚠️ ${level} Threat Detected`,
      message: `Risk Score: ${score}/100\n${data.threat_score.indicators[0] || 'Potential security risk'}`,
      priority: level === 'HIGH' ? 2 : 1,
      requireInteraction: level === 'HIGH'
    });
  }
}

connectToNativeHost();

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SCAN_REQUEST") {
    if (!port) connectToNativeHost();
    if (port) {
      port.postMessage(message.payload);
      sendResponse({ status: "sent" });
    } else {
      sendResponse({ status: "error", error: "Host disconnected" });
    }
  }
  return true;
});

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;

  const url = details.url;

  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) return;

  const suspiciousPatterns = [
    /\.exe\?/,
    /\.scr\?/,
    /phishing/i,
    /verification/i,
    /suspend/i,
    /confirm.*account/i
  ];

  let riskScore = 0;
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(url)) {
      riskScore += 20;
    }
  }

  if (riskScore >= 40) {
    await chrome.storage.local.set({
      currentThreat: {
        target: url,
        status: "SUSPICIOUS",
        isolation_method: "pattern_detection",
        threat_score: {
          level: "MEDIUM",
          score: riskScore,
          confidence: 0.7,
          indicators: ["Suspicious URL pattern detected"]
        },
        timestamp: Date.now() / 1000
      }
    });

    chrome.tabs.update(details.tabId, {
      url: `warning.html?id=current`
    });
  }
});

chrome.downloads.onCreated.addListener(async (downloadItem) => {
  const filename = downloadItem.filename;

  const dangerousExtensions = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.js'];
  const isDangerous = dangerousExtensions.some(ext => filename.toLowerCase().endsWith(ext));

  if (isDangerous) {
    chrome.downloads.pause(downloadItem.id);

    await chrome.storage.local.set({
      currentThreat: {
        target: downloadItem.filename,
        status: "DOWNLOAD_PAUSED",
        isolation_method: "extension_check",
        threat_score: {
          level: "HIGH",
          score: 75,
          confidence: 0.8,
          indicators: [
            "Executable file type",
            "Downloaded file - requires scan"
          ]
        },
        timestamp: Date.now() / 1000,
        downloadId: downloadItem.id
      }
    });

    chrome.notifications.create({
      type: 'basic',
      iconUrl: chrome.runtime.getURL('popup.html'),
      title: '🛑 Suspicious Download Blocked',
      message: `File: ${downloadItem.filename}\nClick to review`,
      priority: 2,
      requireInteraction: true
    }, () => {
      chrome.windows.create({
        url: 'warning.html?id=current&type=download',
        type: 'popup',
        width: 500,
        height: 700
      });
    });
  }
});
