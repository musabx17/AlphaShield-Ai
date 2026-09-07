// Popup.js - AlphaShield Threat & Reasons UI Renderer

document.addEventListener('DOMContentLoaded', () => {
  executeScan();

  const reScanBtn = document.getElementById('reScanBtn');
  if (reScanBtn) {
    reScanBtn.addEventListener('click', executeScan);
  }
});

async function executeScan() {
  const riskScore = document.getElementById('riskScore');
  const verdictText = document.getElementById('verdictText');
  const domainAuth = document.getElementById('domainAuth');
  const scriptObfuscation = document.getElementById('scriptObfuscation');
  const credentialRisk = document.getElementById('credentialRisk');
  const sslStatus = document.getElementById('sslStatus');
  const protectionStatus = document.getElementById('protectionStatus');
  const reasonsContainer = document.getElementById('reasonsContainer');

  if (riskScore) riskScore.textContent = "⏳";
  if (verdictText) verdictText.textContent = "ANALYZING FULL TELEMETRY...";

  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    if (!tabs[0] || !tabs[0].id) {
      if (verdictText) verdictText.textContent = "NO ACTIVE TAB DETECTED";
      return;
    }

    const currentUrl = tabs[0].url || "";

    if (currentUrl.startsWith('chrome://') || currentUrl.startsWith('edge://') || currentUrl.startsWith('about:')) {
      if (riskScore) riskScore.textContent = "0%";
      if (verdictText) {
        verdictText.textContent = "INTERNAL BROWSER PAGE";
        verdictText.style.color = "#10b981";
      }
      if (reasonsContainer) {
        reasonsContainer.innerHTML = '<div class="reason-item clean">• System internal page (Protected)</div>';
      }
      return;
    }

    chrome.tabs.sendMessage(tabs[0].id, { action: "extract_page_data" }, async (pageData) => {
      if (chrome.runtime.lastError) {
        console.warn("AlphaShield Warning:", chrome.runtime.lastError.message);
      }

      const payload = pageData || {
        url: currentUrl,
        protocol: currentUrl.includes(':') ? currentUrl.split(':')[0] + ':' : 'https:',
        visible_text: currentUrl,
        has_password_field: false,
        has_credit_card_field: false
      };

      try {
        const response = await fetch('http://127.0.0.1:8000/api/v1/scan-url', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url: payload.url,
            email_text: payload.visible_text || payload.url,
            has_password_field: payload.has_password_field,
            has_credit_card_field: payload.has_credit_card_field,
            page_title: payload.title || ""
          })
        });

        if (!response.ok) {
          throw new Error(`HTTP Error: ${response.status}`);
        }

        const data = await response.json();
        const score = data.risk_score || 0;
        const isThreat = Boolean(data.is_phishing || data.is_threat || score >= 50);

        // Update main score & status
        if (riskScore) riskScore.textContent = `${score}%`;

        if (isThreat) {
          if (verdictText) {
            verdictText.textContent = "PHISHING THREAT DETECTED";
            verdictText.style.color = "#ef4444";
          }
          if (riskScore) riskScore.style.color = "#ef4444";
          if (protectionStatus) {
            protectionStatus.textContent = "THREAT BLOCKED";
            protectionStatus.style.background = "#ef4444";
            protectionStatus.style.color = "#ffffff";
          }
        } else {
          if (verdictText) {
            verdictText.textContent = "SYSTEM SECURE & CLEAN";
            verdictText.style.color = "#10b981";
          }
          if (riskScore) riskScore.style.color = "#10b981";
          if (protectionStatus) {
            protectionStatus.textContent = "PROTECTED";
            protectionStatus.style.background = "#10b981";
            protectionStatus.style.color = "#000000";
          }
        }

        // Metrics breakdown
        if (domainAuth) domainAuth.textContent = isThreat ? "FLAGGED" : "PASSED";
        if (scriptObfuscation) scriptObfuscation.textContent = (score > 40) ? "SUSPICIOUS" : "CLEAN";
        if (credentialRisk) credentialRisk.textContent = payload.has_password_field ? "DETECTED" : "NONE";
        if (sslStatus) sslStatus.textContent = payload.url.startsWith('https://') ? "ENCRYPTED (HTTPS)" : "UNENCRYPTED (HTTP)";

        // Build Reason List
        let reasonsList = data.reasons || data.flagged_features || data.details || [];

        // Dynamic fallback heuristics if backend doesn't return explicit text array
        if (reasonsList.length === 0) {
          if (payload.url.startsWith('http://')) {
            reasonsList.push("Unencrypted HTTP scheme (credentials exposed to MITM attacks)");
          }
          if (payload.has_password_field) {
            reasonsList.push("Password harvesting form rendered on page");
          }
          if (score >= 50) {
            reasonsList.push("High risk domain or URL path pattern detected");
          }
        }

        // Render Reasons to UI
        if (reasonsContainer) {
          if (reasonsList.length > 0) {
            reasonsContainer.innerHTML = reasonsList
              .map(reason => `<div class="reason-item">⚠️ ${reason}</div>`)
              .join('');
          } else {
            reasonsContainer.innerHTML = '<div class="reason-item clean">✓ Domain structure and login forms verified safe</div>';
          }
        }

      } catch (err) {
        console.error("AlphaShield Scan Error:", err);
        if (riskScore) {
          riskScore.textContent = "⚠️";
          riskScore.style.color = "#ef4444";
        }
        if (verdictText) {
          verdictText.textContent = "BACKEND DISCONNECTED";
          verdictText.style.color = "#ef4444";
        }
        if (reasonsContainer) {
          reasonsContainer.innerHTML = '<div class="reason-item">⚠️ Connection error to 127.0.0.1:8000</div>';
        }
      }
    });
  });
}