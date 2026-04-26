// AIPDA Content Script — Connected to: https://aipda-qwkn.onrender.com
const AIPDA_API = 'https://aipda-qwkn.onrender.com';

// Automatically analyze the current page URL when loaded
const currentUrl = window.location.href;

// Check if it's not a local or chrome-internal page
if (!currentUrl.startsWith('chrome://') && !currentUrl.includes('onrender.com') && !currentUrl.startsWith('http://localhost')) {
  fetch(AIPDA_API + '/proxy/check?url=' + encodeURIComponent(currentUrl))
    .then(r => r.json())
    .then(data => {
      if (data.action === "BLOCK" || data.verdict === "PHISHING") {
        injectPhishingBlocker();
      }
    })
    .catch(err => console.log("AIPDA connection failed", err));
}

function injectPhishingBlocker() {
  const overlay = document.createElement('div');
  overlay.innerHTML = `
    <div style="position:fixed; top:0; left:0; width:100vw; height:100vh; background:rgba(220,38,38,0.95); z-index:999999; display:flex; flex-direction:column; align-items:center; justify-content:center; color:white; font-family:sans-serif; text-align:center;">
      <h1 style="font-size:4rem; margin-bottom:10px;">⚠️ DANGER</h1>
      <h2 style="font-size:2rem; margin-bottom:20px;">AIPDA BLOCKED THIS SITE</h2>
      <p style="font-size:1.2rem; max-width:600px;">This website has been classified as a Phishing threat by the AIPDA Enterprise Security Engine.</p>
      <button onclick="document.body.removeChild(this.parentElement.parentElement)" style="margin-top:30px; padding:10px 20px; background:black; color:white; border:none; cursor:pointer;">I understand the risk, proceed anyway</button>
    </div>
  `;
  document.body.appendChild(overlay);
}
