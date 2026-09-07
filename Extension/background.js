// background.js - CyberShield Service Worker

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "scan_url") {
    fetch('http://127.0.0.1:8000/api/v1/scan-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        url: request.url, 
        email_text: request.text || request.url,
        has_password_field: request.has_password_field || false
      })
    })
    .then(async (res) => {
      if (!res.ok) {
        throw new Error(`HTTP status ${res.status}`);
      }
      return res.json();
    })
    .then(data => sendResponse({ success: true, data: data }))
    .catch(err => {
      console.error("Background Worker Error:", err);
      sendResponse({ success: false, error: err.toString() });
    });
    
    return true; // Keep async response channel open
  }
});