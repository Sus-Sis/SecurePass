document.addEventListener("DOMContentLoaded", async () => {
  const screenDisconnected = document.getElementById("screen-disconnected");
  const screenConnected = document.getElementById("screen-connected");
  const screenPhishing = document.getElementById("screen-phishing");
  const currentDomainDisplay = document.getElementById("current-domain-display");
  const phishingDomainDisplay = document.getElementById("phishing-domain-display");
  const credentialsList = document.getElementById("credentials-list");
  const noCredentialsText = document.getElementById("no-credentials-text");
  
  const btnOpenLocked = document.getElementById("btn-open-dashboard-locked");
  const btnOpenConnected = document.getElementById("btn-open-dashboard");
  const btnPhishingClose = document.getElementById("btn-phishing-close");
  const toast = document.getElementById("toast");

  let currentDomain = "";

  // 1. Get active tab's domain
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs.length > 0 && tabs[0].url) {
      try {
        const url = new URL(tabs[0].url);
        // Only extract domain for http/https
        if (url.protocol.startsWith("http")) {
          currentDomain = url.hostname.replace("www.", "");
          currentDomainDisplay.textContent = currentDomain;
        } else {
          currentDomain = "browser-page";
          currentDomainDisplay.textContent = "Unsupported Page";
        }
      } catch (e) {
        currentDomain = "unknown";
        currentDomainDisplay.textContent = "Unknown Domain";
      }
    }
    
    // 2. Check connection status to SecurePass web app
    checkStatus();
  });

  function showPhishingScreen() {
    screenDisconnected.classList.add("hidden");
    screenConnected.classList.add("hidden");
    screenPhishing.classList.remove("hidden");
    if (phishingDomainDisplay) {
      phishingDomainDisplay.textContent = currentDomain || "this domain";
    }
  }

  function checkStatus() {
    chrome.runtime.sendMessage({ type: "POPUP_GET_STATUS" }, (res) => {
      console.log("Popup status check response:", res);
      if (res && res.isPhishing) {
        showPhishingScreen();
        return;
      }
      if (res && res.connected) {
        screenPhishing.classList.add("hidden");
        screenDisconnected.classList.add("hidden");
        screenConnected.classList.remove("hidden");
        
        if (currentDomain && currentDomain !== "browser-page" && currentDomain !== "unknown") {
          // Request credentials for the active domain
          chrome.runtime.sendMessage({ 
            type: "POPUP_GET_CREDENTIALS", 
            domain: currentDomain 
          });
        } else {
          noCredentialsText.classList.remove("hidden");
        }
      } else {
        screenPhishing.classList.add("hidden");
        screenDisconnected.classList.remove("hidden");
        screenConnected.classList.add("hidden");
      }
    });
  }

  // 3. Listen for credential results relayed from background
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "POPUP_CREDENTIALS_RESULT") {
      if (message.isPhishing) {
        showPhishingScreen();
        return;
      }
      const creds = message.credentials || [];
      renderCredentials(creds);
    }
  });

  function renderCredentials(creds) {
    credentialsList.innerHTML = "";
    
    if (creds.length === 0) {
      noCredentialsText.classList.remove("hidden");
      return;
    }

    noCredentialsText.classList.add("hidden");
    
    creds.forEach(item => {
      const itemDiv = document.createElement("div");
      itemDiv.className = "cred-item";
      
      itemDiv.innerHTML = `
        <div class="cred-info">
          <span class="cred-name">${item.name || item.url}</span>
          <span class="cred-user">${item.username}</span>
        </div>
        <div class="cred-actions">
          <button class="btn-icon btn-copy-user" title="Copy Username">
            <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"></path></svg>
          </button>
          <button class="btn-icon btn-copy-pass" title="Copy Password">
            <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"></path></svg>
          </button>
        </div>
      `;

      // Copy username event
      itemDiv.querySelector(".btn-copy-user").onclick = async () => {
        await navigator.clipboard.writeText(item.username);
        showToast("Copied Username!");
        // Ask background to relay log creation to Web App
        chrome.runtime.sendMessage({
          type: "SAVE_CREDENTIALS_LOG",
          action: "credential_copied_username"
        });
      };

      // Copy password event
      itemDiv.querySelector(".btn-copy-pass").onclick = async () => {
        await navigator.clipboard.writeText(item.password);
        showToast("Copied Password!");
        // Ask background to relay log creation to Web App
        chrome.runtime.sendMessage({
          type: "SAVE_CREDENTIALS_LOG",
          action: "credential_copied_password"
        });
      };

      credentialsList.appendChild(itemDiv);
    });
  }

  function showToast(text) {
    toast.textContent = text;
    toast.classList.remove("hidden");
    setTimeout(() => {
      toast.classList.add("hidden");
    }, 2000);
  }

  // Bind Open Dashboard buttons
  const openDashboard = () => {
    chrome.tabs.create({ url: "http://localhost:5173/vault" });
  };
  btnOpenLocked.onclick = openDashboard;
  btnOpenConnected.onclick = openDashboard;
  if (btnPhishingClose) {
    btnPhishingClose.onclick = () => {
      window.close();
    };
  }
});
