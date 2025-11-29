// background.js - Enhanced with real-time protection
let port = null;
let threatCount = 0;

function connectToNativeHost() {
  const hostName = "com.sentinel.host";
  console.log(`Connecting to native host: ${hostName}`);
  port = chrome.runtime.connectNative(hostName);

  port.onMessage.addListener((message) => {
    console.log("Received message from native host:", message);

    // Process threat score
    if (message.threat_score) {
      handleThreatResult(message);
    }

    // Forward to popup if open
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

  // Update badge
  if (level === 'HIGH') {
    threatCount++;
    chrome.action.setBadgeText({ text: threatCount.toString() });
    chrome.action.setBadgeBackgroundColor({ color: '#f44336' });
  }

  // Show notification for medium/high threats
  if (level === 'MEDIUM' || level === 'HIGH') {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: chrome.runtime.getURL('popup.html'), // Use any existing file as placeholder
      title: `⚠️ ${level} Threat Detected`,
      message: `Risk Score: ${score}/100\n${data.threat_score.indicators[0] || 'Potential security risk'}`,
      priority: level === 'HIGH' ? 2 : 1,
      requireInteraction: level === 'HIGH'
    });
  }
}

connectToNativeHost();

// Listen for scan requests from popup
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

// Real-time URL scanning - intercept before navigation
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only scan main frame navigations
  if (details.frameId !== 0) return;

  const url = details.url;

  // Skip chrome:// and extension:// URLs
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) return;

  // Quick check for suspicious patterns
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

  // If suspicious, show warning (simplified for demo)
  if (riskScore >= 40) {
    // Save to storage
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

    // Cancel navigation
    chrome.tabs.update(details.tabId, {
      url: `warning.html?id=current`
    });
  }
});

// Download scanning
chrome.downloads.onCreated.addListener(async (downloadItem) => {
  const filename = downloadItem.filename;

  // Check file extension
  const dangerousExtensions = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.js'];
  const isDangerous = dangerousExtensions.some(ext => filename.toLowerCase().endsWith(ext));

  if (isDangerous) {
    // Pause download
    chrome.downloads.pause(downloadItem.id);

    // Show warning
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
      // Open warning modal
      chrome.windows.create({
        url: 'warning.html?id=current&type=download',
        type: 'popup',
        width: 500,
        height: 700
      });
    });
  }
});

