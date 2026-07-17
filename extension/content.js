const currentDomain = window.location.hostname.replace("www.", "");
const isSecurePassTab = window.location.href.includes("localhost:3000") || 
                        window.location.href.includes("localhost:5173") || 
                        window.location.href.includes("securepass.com");

console.log("SecurePass content script loaded on:", window.location.href);

if (isSecurePassTab) {
  // ==========================================
  // WEB APP INTEGRATION LOGIC
  // ==========================================
  
  // Register this tab with the background script
  chrome.runtime.sendMessage({ type: "SECUREPASS_REGISTER_TAB" }, (response) => {
    console.log("Web tab registered with background worker:", response);
  });

  // Listen for messages from background script
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log("SecurePass Tab received background message:", message);
    
    if (message.type === "REQ_CREDENTIALS") {
      // Ask React App for credentials of a specific domain
      window.postMessage({ 
        type: "SECUREPASS_GET_CREDENTIALS", 
        domain: message.domain,
        requesterTabId: message.requesterTabId
      }, "*");
    }

    if (message.type === "REQ_SAVE_CREDENTIALS") {
      // Send credentials to React app to save
      window.postMessage({
        type: "SECUREPASS_SAVE_CREDENTIALS",
        credentials: message.credentials
      }, "*");
    }

    if (message.type === "REQ_POPUP_CREDENTIALS") {
      // Ask React App for credentials list for the popup
      window.postMessage({
        type: "SECUREPASS_GET_POPUP_CREDENTIALS",
        domain: message.domain
      }, "*");
    }

    if (message.type === "REQ_LOG_ACTION") {
      // Ask React App to create a custom activity log
      window.postMessage({
        type: "SECUREPASS_LOG_ACTION",
        action: message.action
      }, "*");
    }
  });

  // Listen for postMessage from the React App
  window.addEventListener("message", (event) => {
    // Only accept messages from our own window
    if (event.source !== window) return;

    if (event.data.type === "SECUREPASS_CREDENTIALS") {
      console.log("SecurePass App returned credentials:", event.data);
      chrome.runtime.sendMessage({
        type: "RELAY_CREDENTIALS",
        credentials: event.data.data,
        requesterTabId: event.data.requesterTabId
      });
    }

    if (event.data.type === "SECUREPASS_POPUP_CREDENTIALS") {
      console.log("SecurePass App returned popup credentials:", event.data);
      chrome.runtime.sendMessage({
        type: "RELAY_POPUP_CREDENTIALS",
        credentials: event.data.data
      });
    }
  });

} else {
  // ==========================================
  // THIRD PARTY WEBSITE LOGIC
  // ==========================================
  
  // Run on load
  setTimeout(() => {
    detectAndSetupForms();
    checkForPendingSave();
  }, 1000);

  // Monitor dynamic DOM insertions to catch Javascript dynamic login forms
  const observer = new MutationObserver(() => {
    detectAndSetupForms();
  });
  observer.observe(document.body, { childList: true, subtree: true });

  let autofillData = null;

  function detectAndSetupForms() {
    const passwordInputs = document.querySelectorAll("input[type='password']");
    if (passwordInputs.length === 0) return;

    passwordInputs.forEach(passInput => {
      // Avoid double binding
      if (passInput.dataset.securepassBound) return;
      passInput.dataset.securepassBound = "true";

      const form = passInput.closest("form");
      const usernameInput = findUsernameField(passInput, form);

      // Check if credentials exist for this domain
      chrome.runtime.sendMessage({ 
        type: "GET_CREDENTIALS", 
        domain: currentDomain 
      });

      // Bind submit listener
      if (form) {
        form.addEventListener("submit", (e) => {
          captureCredentials(usernameInput, passInput);
        });
      } else {
        // Fallback for formless password submit inputs
        passInput.addEventListener("keydown", (e) => {
          if (e.key === "Enter") {
            captureCredentials(usernameInput, passInput);
          }
        });
      }
    });
  }

  function findUsernameField(passInput, form) {
    if (form) {
      // Look inside the same form first
      const fields = form.querySelectorAll("input[type='text'], input[type='email']");
      if (fields.length > 0) return fields[0];
    }
    
    // Look in surrounding DOM preceding the password field
    const inputs = Array.from(document.querySelectorAll("input"));
    const passIdx = inputs.indexOf(passInput);
    if (passIdx > 0) {
      for (let i = passIdx - 1; i >= 0; i--) {
        const input = inputs[i];
        if (input.type === "text" || input.type === "email") {
          return input;
        }
      }
    }
    return null;
  }

  // Capture credentials on submit event
  function captureCredentials(usernameInput, passInput) {
    const username = usernameInput ? usernameInput.value.trim() : "";
    const password = passInput ? passInput.value : "";
    
    if (username && password) {
      // Save temporarily in sessionStorage so we can show "Save?" prompt on redirect
      sessionStorage.setItem("securepass_pending", JSON.stringify({
        domain: currentDomain,
        username,
        password,
        timestamp: Date.now()
      }));
      console.log("SecurePass captured credentials submission draft.");
    }
  }

  // Check if we successfully logged in and navigated
  function checkForPendingSave() {
    const pendingStr = sessionStorage.getItem("securepass_pending");
    if (!pendingStr) return;

    try {
      const pending = JSON.parse(pendingStr);
      // Ensure it's for this domain and within 5 minutes
      if (pending.domain === currentDomain && (Date.now() - pending.timestamp) < 300000) {
        // Clear immediately so it doesn't prompt again
        sessionStorage.removeItem("securepass_pending");
        
        // Show save dialog!
        showSavePrompt(pending);
      }
    } catch (e) {
      sessionStorage.removeItem("securepass_pending");
    }
  }

  // Listen for autofill credentials relay
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "AUTOFILL_CREDENTIALS") {
      if (message.data) {
        autofillData = message.data;
        injectAutofill(message.data);
      }
    }
  });

  function injectAutofill(data) {
    const passwordInputs = document.querySelectorAll("input[type='password']");
    passwordInputs.forEach(passInput => {
      const form = passInput.closest("form");
      const usernameInput = findUsernameField(passInput, form);

      if (usernameInput && data.username) {
        usernameInput.value = data.username;
        usernameInput.dispatchEvent(new Event("input", { bubbles: true }));
        usernameInput.dispatchEvent(new Event("change", { bubbles: true }));
      }
      
      if (passInput && data.password) {
        passInput.value = data.password;
        passInput.dispatchEvent(new Event("input", { bubbles: true }));
        passInput.dispatchEvent(new Event("change", { bubbles: true }));
      }
    });
  }

  // Show a premium floating save password prompt
  function showSavePrompt(creds) {
    // Avoid double prompts
    if (document.getElementById("securepass-save-banner")) return;

    const div = document.createElement("div");
    div.id = "securepass-save-banner";
    
    // Inject stylesheet
    const style = document.createElement("style");
    style.textContent = `
      #securepass-save-banner {
        position: fixed;
        top: 20px;
        right: 20px;
        background: #0F1626;
        border: 1px solid rgba(59, 130, 246, 0.4);
        box-shadow: 0 10px 30px rgba(0,0,0,0.8), 0 0 10px rgba(59, 130, 246, 0.1);
        border-radius: 12px;
        padding: 16px;
        z-index: 999999999;
        font-family: system-ui, -apple-system, sans-serif;
        color: #F3F4F6;
        width: 340px;
        animation: spSlideIn 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards;
      }
      @keyframes spSlideIn {
        from { transform: translateY(-50px); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
      }
      .sp-header {
        display: flex;
        align-items: center;
        gap: 8px;
        font-weight: bold;
        font-size: 14px;
        margin-bottom: 8px;
        background: linear-gradient(135deg, #06B6D4, #3B82F6);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
      }
      .sp-text {
        font-size: 12px;
        color: #9CA3AF;
        margin-bottom: 12px;
      }
      .sp-username {
        font-weight: 600;
        color: #F3F4F6;
      }
      .sp-actions {
        display: flex;
        justify-content: flex-end;
        gap: 8px;
      }
      .sp-btn {
        padding: 6px 12px;
        border-radius: 6px;
        font-size: 12px;
        font-weight: 600;
        cursor: pointer;
        border: 1px solid transparent;
      }
      .sp-btn-primary {
        background: linear-gradient(135deg, #06B6D4, #3B82F6);
        color: white;
      }
      .sp-btn-secondary {
        background: #172237;
        color: #F3F4F6;
        border-color: rgba(255,255,255,0.08);
      }
    `;
    
    div.innerHTML = `
      <div class="sp-header">🛡️ Save to SecurePass?</div>
      <div class="sp-text">Would you like to save credentials for <span class="sp-username">${creds.username}</span> on <strong>${creds.domain}</strong>?</div>
      <div class="sp-actions">
        <button id="sp-btn-no" class="sp-btn sp-btn-secondary">Not Now</button>
        <button id="sp-btn-yes" class="sp-btn sp-btn-primary">Save Password</button>
      </div>
    `;

    document.body.appendChild(style);
    document.body.appendChild(div);

    document.getElementById("sp-btn-yes").onclick = () => {
      chrome.runtime.sendMessage({
        type: "SAVE_CREDENTIALS",
        credentials: {
          name: creds.domain.split(".")[0],
          url: creds.domain,
          username: creds.username,
          password: creds.password,
          category: "Logins"
        }
      }, (res) => {
        console.log("Credentials save submitted:", res);
        removeBanner();
      });
    };

    document.getElementById("sp-btn-no").onclick = () => {
      removeBanner();
    };

    function removeBanner() {
      div.style.animation = "spSlideOut 0.2s ease forwards";
      // Add keyframe for slide out
      const styleOut = document.createElement("style");
      styleOut.textContent = `
        @keyframes spSlideOut {
          to { transform: translateY(-50px); opacity: 0; }
        }
      `;
      document.body.appendChild(styleOut);
      setTimeout(() => {
        div.remove();
        style.remove();
        styleOut.remove();
      }, 200);
    }
  }
}
