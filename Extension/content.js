// content.js - AlphaShield Deep Page & URL Context Extractor

function extractPageTelemetry() {
  // 1. Capture full visible text content (up to 10,000 chars for deep NLP checks)
  const visibleText = document.body ? document.body.innerText.slice(0, 10000) : "";
  
  // 2. Extract DOM inputs & credential security markers
  const passwordInputs = document.querySelectorAll('input[type="password"]');
  const creditCardInputs = document.querySelectorAll(
    'input[name*="card"], input[name*="cc"], input[autocomplete*="cc-number"], input[id*="cvv"]'
  );
  const formActionUrls = Array.from(document.forms).map(form => form.action || "");

  // 3. Extract outbound links for typosquatting & domain misalignment analysis
  const pageLinks = Array.from(document.querySelectorAll('a[href]'))
    .slice(0, 50)
    .map(a => ({ text: a.innerText.trim(), href: a.href }));

  // 4. Return aggregated payload object
  return {
    url: window.location.href,
    protocol: window.location.protocol, // http: or https:
    hostname: window.location.hostname,
    pathname: window.location.pathname,
    title: document.title || "",
    visible_text: visibleText,
    has_password_field: passwordInputs.length > 0,
    has_credit_card_field: creditCardInputs.length > 0,
    form_actions: formActionUrls,
    page_links: pageLinks
  };
}

// Listen for scan requests coming from popup or background worker
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "extract_page_data") {
    sendResponse(extractPageTelemetry());
  }
  return true;
});