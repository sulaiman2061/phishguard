// AIPDA Extension — Connected to: https://aipda-qwkn.onrender.com
const AIPDA_API = 'https://aipda-qwkn.onrender.com';

// AIPDA Extension Background Service Worker
chrome.runtime.onInstalled.addListener(() => {
  // Create context menu for analyzing text/links
  chrome.contextMenus.create({
    id: "analyzePhishing",
    title: "Scan with AIPDA",
    contexts: ["selection", "link"]
  });
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "analyzePhishing") {
    const textToAnalyze = info.selectionText || info.linkUrl;
    
    // Send a request to our local AIPDA API (Assuming it's running on localhost:5000)
    try {
      const res = await fetch(AIPDA_API + '/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: textToAnalyze })
      });
      const data = await res.json();
      
      // Inject alert into the active tab based on the result
      chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: showResultAlert,
        args: [data]
      });
    } catch (e) {
      console.error("AIPDA Server not reachable", e);
    }
  }
});

function showResultAlert(data) {
  alert(`AIPDA Verdict: ${data.verdict}\n\nConfidence: ${data.confidence}\nExplanation: ${data.explanation}`);
}
