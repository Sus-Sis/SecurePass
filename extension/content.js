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
        allLogins: event.data.allLogins,
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
  
  let isPhishingPage = false;

  function disableVaultForPhishing() {
    isPhishingPage = true;
    autofillData = null;
    removeExtensionVaultWidget();
    const trigger = document.getElementById("securepass-floating-trigger");
    const triggerStyle = document.getElementById("securepass-floating-trigger-styles");
    if (trigger) trigger.remove();
    if (triggerStyle) triggerStyle.remove();
  }

  // Run on load immediately
  chrome.runtime.sendMessage({ type: "GET_CREDENTIALS", domain: currentDomain });
  createFloatingVaultTrigger();

  setTimeout(() => {
    detectAndSetupForms();
    checkForPendingSave();
  }, 500);

  // Monitor dynamic DOM insertions to catch Javascript dynamic login forms
  const observer = new MutationObserver(() => {
    detectAndSetupForms();
  });
  observer.observe(document.body, { childList: true, subtree: true });

  let autofillData = null;

  function createFloatingVaultTrigger() {
    if (isPhishingPage) return;
    if (document.getElementById("securepass-floating-trigger")) return;

    const btn = document.createElement("button");
    btn.id = "securepass-floating-trigger";
    btn.innerHTML = `🛡️ <span id="sp-trig-text">SecurePass</span>`;

    const style = document.createElement("style");
    style.id = "securepass-floating-trigger-styles";
    style.textContent = `
      #securepass-floating-trigger {
        position: fixed !important;
        top: 100px !important;
        right: 0 !important;
        z-index: 2147483646 !important;
        background: linear-gradient(135deg, #0f172a, #1e293b) !important;
        color: #06b6d4 !important;
        border: 1px solid rgba(6, 182, 212, 0.4) !important;
        border-right: none !important;
        border-radius: 20px 0 0 20px !important;
        padding: 8px 12px 8px 10px !important;
        font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
        font-size: 12px !important;
        font-weight: 700 !important;
        cursor: pointer !important;
        box-shadow: 0 8px 20px rgba(0, 0, 0, 0.5), 0 0 10px rgba(6, 182, 212, 0.2) !important;
        display: flex !important;
        align-items: center !important;
        gap: 6px !important;
        transition: transform 0.2s ease, background 0.2s ease !important;
      }
      #securepass-floating-trigger:hover {
        transform: translateX(-4px) !important;
        background: linear-gradient(135deg, #06b6d4, #3b82f6) !important;
        color: #ffffff !important;
      }
    `;

    document.head.appendChild(style);
    document.body.appendChild(btn);

    btn.onclick = () => {
      if (document.getElementById("securepass-extension-vault-popup")) {
        removeExtensionVaultWidget();
      } else {
        if (autofillData && autofillData.length > 0) {
          showExtensionVaultWidget(autofillData, "ready");
        } else {
          // Re-query credentials
          chrome.runtime.sendMessage({ type: "GET_CREDENTIALS", domain: currentDomain });
          showExtensionVaultWidget([], "no_creds");
        }
      }
    };
  }

  function detectAndSetupForms() {
    const inputs = document.querySelectorAll("input");
    if (inputs.length === 0) return;

    inputs.forEach(inputEl => {
      if (inputEl.dataset.securepassBound) return;
      inputEl.dataset.securepassBound = "true";

      const showVaultOnFocus = () => {
        if (autofillData && autofillData.length > 0) {
          showExtensionVaultWidget(autofillData, "ready");
        }
      };

      inputEl.addEventListener("focus", showVaultOnFocus);
      inputEl.addEventListener("click", showVaultOnFocus);

      const form = inputEl.closest("form");
      if (form && !form.dataset.securepassFormBound) {
        form.dataset.securepassFormBound = "true";
        form.addEventListener("submit", () => {
          const passInput = form.querySelector("input[type='password']");
          const usernameInput = findUsernameField(passInput, form);
          if (passInput) {
            captureCredentials(usernameInput, passInput);
          }
        });
      }
    });
  }

  function findUsernameField(passInput, form) {
    if (form) {
      const fields = form.querySelectorAll("input[type='text'], input[type='email'], input[name*='user'], input[name*='email']");
      if (fields.length > 0) return fields[0];
    }
    
    const inputs = Array.from(document.querySelectorAll("input"));
    const passIdx = passInput ? inputs.indexOf(passInput) : -1;
    if (passIdx > 0) {
      for (let i = passIdx - 1; i >= 0; i--) {
        const input = inputs[i];
        if (input.type === "text" || input.type === "email") {
          return input;
        }
      }
    }
    return inputs.find(i => i.type === "email" || i.type === "text" || i.name.includes("user") || i.name.includes("email")) || null;
  }

  // Capture credentials on submit event
  function captureCredentials(usernameInput, passInput) {
    const username = usernameInput ? usernameInput.value.trim() : "";
    const password = passInput ? passInput.value : "";
    
    if (username && password) {
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
      if (pending.domain === currentDomain && (Date.now() - pending.timestamp) < 300000) {
        sessionStorage.removeItem("securepass_pending");
        showSavePrompt(pending);
      }
    } catch (e) {
      sessionStorage.removeItem("securepass_pending");
    }
  }

  let allLoginsData = [];

  // Listen for autofill credentials relay
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "AUTOFILL_CREDENTIALS") {
      if (isPhishingPage || (message.error && message.error.includes("Phishing"))) {
        disableVaultForPhishing();
        return;
      }
      const trigText = document.getElementById("sp-trig-text");
      allLoginsData = message.allLogins || [];

      if (message.data) {
        const creds = Array.isArray(message.data) ? message.data : [message.data];
        if (creds.length > 0) {
          autofillData = creds;
          if (trigText) trigText.textContent = `SecurePass (${creds.length})`;
          showExtensionVaultWidget(creds, "ready");
        } else if (allLoginsData.length > 0) {
          autofillData = allLoginsData;
          if (trigText) trigText.textContent = `SecurePass (${allLoginsData.length})`;
          showExtensionVaultWidget(allLoginsData, "all_saved");
        } else {
          autofillData = null;
          if (trigText) trigText.textContent = "SecurePass";
          showExtensionVaultWidget([], "no_creds");
        }
      } else if (message.error && message.error.includes("locked")) {
        autofillData = null;
        if (trigText) trigText.textContent = "SecurePass (Locked)";
        showExtensionVaultWidget([], "locked");
      } else if (allLoginsData.length > 0) {
        autofillData = allLoginsData;
        if (trigText) trigText.textContent = `SecurePass (${allLoginsData.length})`;
        showExtensionVaultWidget(allLoginsData, "all_saved");
      } else {
        autofillData = null;
        if (trigText) trigText.textContent = "SecurePass";
        showExtensionVaultWidget([], "no_creds");
      }
    }
  });

  function showExtensionVaultWidget(credsList, statusType = "ready") {
    if (isPhishingPage) return;
    if (document.getElementById("securepass-extension-vault-popup")) return;

    const popup = document.createElement("div");
    popup.id = "securepass-extension-vault-popup";

    const style = document.createElement("style");
    style.id = "securepass-vault-popup-styles";
    style.textContent = `
      #securepass-extension-vault-popup {
        position: fixed !important;
        top: 24px !important;
        right: 24px !important;
        width: 330px !important;
        z-index: 2147483647 !important;
        background: #0f172a !important;
        border: 1px solid rgba(6, 182, 212, 0.4) !important;
        border-radius: 12px !important;
        padding: 14px 16px !important;
        box-shadow: 0 15px 35px rgba(0, 0, 0, 0.8), 0 0 15px rgba(6, 182, 212, 0.15) !important;
        font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
        color: #f8fafc !important;
        box-sizing: border-box !important;
        animation: spVaultPopIn 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards !important;
      }
      @keyframes spVaultPopIn {
        from { transform: translateY(-20px) scale(0.95); opacity: 0; }
        to { transform: translateY(0) scale(1); opacity: 1; }
      }
      .sp-vp-header {
        display: flex !important;
        align-items: center !important;
        justify-content: space-between !important;
        margin-bottom: 10px !important;
        padding-bottom: 8px !important;
        border-bottom: 1px solid rgba(255, 255, 255, 0.08) !important;
      }
      .sp-vp-title-group {
        display: flex !important;
        align-items: center !important;
        gap: 6px !important;
      }
      .sp-vp-title {
        font-weight: 700 !important;
        font-size: 13px !important;
        background: linear-gradient(135deg, #06b6d4, #3b82f6) !important;
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        letter-spacing: 0.02em !important;
      }
      .sp-vp-badge {
        font-size: 10px !important;
        font-weight: 600 !important;
        background: rgba(6, 182, 212, 0.15) !important;
        color: #22d3ee !important;
        padding: 2px 6px !important;
        border-radius: 4px !important;
        border: 1px solid rgba(6, 182, 212, 0.3) !important;
      }
      .sp-vp-close {
        background: none !important;
        border: none !important;
        color: #94a3b8 !important;
        font-size: 16px !important;
        cursor: pointer !important;
        padding: 0 4px !important;
        line-height: 1 !important;
        border-radius: 4px !important;
      }
      .sp-vp-close:hover {
        color: #ffffff !important;
        background: rgba(255, 255, 255, 0.1) !important;
      }
      .sp-vp-list {
        display: flex !important;
        flex-direction: column !important;
        gap: 8px !important;
        max-height: 220px !important;
        overflow-y: auto !important;
      }
      .sp-vp-item {
        display: flex !important;
        align-items: center !important;
        justify-content: space-between !important;
        background: rgba(30, 41, 59, 0.7) !important;
        border: 1px solid rgba(255, 255, 255, 0.06) !important;
        border-radius: 8px !important;
        padding: 8px 10px !important;
        gap: 8px !important;
        transition: border-color 0.15s ease !important;
      }
      .sp-vp-item:hover {
        border-color: rgba(6, 182, 212, 0.4) !important;
        background: rgba(30, 41, 59, 0.95) !important;
      }
      .sp-vp-user-info {
        display: flex !important;
        flex-direction: column !important;
        overflow: hidden !important;
      }
      .sp-vp-username {
        font-size: 12px !important;
        font-weight: 600 !important;
        color: #f1f5f9 !important;
        white-space: nowrap !important;
        overflow: hidden !important;
        text-overflow: ellipsis !important;
      }
      .sp-vp-site {
        font-size: 10px !important;
        color: #64748b !important;
      }
      .sp-vp-fill-btn {
        background: linear-gradient(135deg, #06b6d4, #3b82f6) !important;
        color: #ffffff !important;
        border: none !important;
        padding: 5px 10px !important;
        border-radius: 6px !important;
        font-size: 11px !important;
        font-weight: 600 !important;
        cursor: pointer !important;
        white-space: nowrap !important;
        box-shadow: 0 2px 8px rgba(6, 182, 212, 0.3) !important;
        transition: transform 0.1s ease, box-shadow 0.1s ease !important;
      }
      .sp-vp-fill-btn:hover {
        transform: translateY(-1px) !important;
        box-shadow: 0 4px 12px rgba(6, 182, 212, 0.4) !important;
      }
      .sp-vp-action-btn {
        width: 100% !important;
        background: linear-gradient(135deg, #06b6d4, #3b82f6) !important;
        color: #ffffff !important;
        border: none !important;
        padding: 8px 12px !important;
        border-radius: 6px !important;
        font-size: 12px !important;
        font-weight: 600 !important;
        cursor: pointer !important;
        margin-top: 6px !important;
      }
      .sp-vp-footer {
        margin-top: 10px !important;
        font-size: 10px !important;
        color: #64748b !important;
        text-align: center !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        gap: 4px !important;
      }
    `;

    let bodyHtml = "";
    let badgeText = "Vault Ready";

    const displayList = (credsList && credsList.length > 0) ? credsList : allLoginsData;

    if (displayList && displayList.length > 0) {
      const isExactMatch = statusType === "ready";
      badgeText = isExactMatch ? `${credsList.length} Ready` : `${displayList.length} Saved`;

      const itemsHtml = displayList.map((item, idx) => `
        <div class="sp-vp-item">
          <div class="sp-vp-user-info">
            <span class="sp-vp-username">👤 ${escapeHtml(item.username || "Account")}</span>
            <span class="sp-vp-site">${escapeHtml(item.name || item.title || item.url || "Vault Password")}</span>
          </div>
          <button class="sp-vp-fill-btn" data-index="${idx}">⚡ AutoFill</button>
        </div>
      `).join("");

      bodyHtml = `
        ${!isExactMatch ? `<div style="font-size: 11px; color: #94a3b8; margin-bottom: 6px;">Select from your saved vault passwords:</div>` : ''}
        <div class="sp-vp-list">${itemsHtml}</div>
        <button id="sp-vp-open-dash" class="sp-vp-action-btn" style="background: rgba(255,255,255,0.06) !important; border: 1px solid rgba(255,255,255,0.1) !important; margin-top: 8px !important;">➕ Save Password for ${escapeHtml(currentDomain)}</button>
      `;
    } else if (statusType === "locked") {
      badgeText = "Locked";
      bodyHtml = `
        <div style="font-size: 11px; color: #94a3b8; margin-bottom: 8px;">
          Vault is locked. Open dashboard to unlock passwords.
        </div>
        <button id="sp-vp-open-dash" class="sp-vp-action-btn">🔓 Open Web Dashboard</button>
      `;
    } else {
      badgeText = "Active";
      bodyHtml = `
        <div style="font-size: 11px; color: #94a3b8; margin-bottom: 8px;">
          No saved logins found in your vault.
        </div>
        <button id="sp-vp-open-dash" class="sp-vp-action-btn">➕ Open Web Dashboard to Save</button>
      `;
    }

    popup.innerHTML = `
      <div class="sp-vp-header">
        <div class="sp-vp-title-group">
          <span>🛡️</span>
          <span class="sp-vp-title">SecurePass Extension</span>
          <span class="sp-vp-badge">${badgeText}</span>
        </div>
        <button id="sp-vp-close-btn" class="sp-vp-close" title="Dismiss">✕</button>
      </div>
      ${bodyHtml}
      <div class="sp-vp-footer">
        🔒 Zero-Knowledge Encrypted
      </div>
    `;

    document.head.appendChild(style);
    document.body.appendChild(popup);

    // Event listeners
    document.getElementById("sp-vp-close-btn").onclick = () => {
      removeExtensionVaultWidget();
    };

    const openDashBtn = document.getElementById("sp-vp-open-dash");
    if (openDashBtn) {
      openDashBtn.onclick = () => {
        window.open("http://localhost:5173/vault", "_blank");
      };
    }

    const fillButtons = popup.querySelectorAll(".sp-vp-fill-btn");
    fillButtons.forEach(btn => {
      btn.onclick = (e) => {
        const idx = parseInt(e.target.dataset.index, 10);
        const selectedCred = displayList[idx];
        if (selectedCred) {
          injectAutofill(selectedCred);
          btn.textContent = "✓ Filled!";
          btn.style.background = "#10b981";
          setTimeout(() => {
            removeExtensionVaultWidget();
          }, 600);
        }
      };
    });
  }

  function removeExtensionVaultWidget() {
    const popup = document.getElementById("securepass-extension-vault-popup");
    const style = document.getElementById("securepass-vault-popup-styles");
    if (popup) popup.remove();
    if (style) style.remove();
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function injectAutofill(data) {
    if (!data) return;
    const cred = Array.isArray(data) ? data[0] : data;

    // 1. Find username / email input element
    let usernameInput = document.querySelector("input[name='email'], input[name='username'], input[type='email'], input[id='email'], input[autocomplete='username'], input[autocomplete='email']");
    if (!usernameInput) {
      const textInputs = document.querySelectorAll("input[type='text'], input[type='email']");
      if (textInputs.length > 0) usernameInput = textInputs[0];
    }

    // 2. Find password input element
    let passInput = document.querySelector("input[type='password'], input[name='pass'], input[name='password'], input[id='pass'], input[autocomplete='current-password']");

    // 3. Inject username & password using prototype setter for React/Vue/Facebook compatibility
    if (usernameInput && cred.username) {
      setNativeInputValue(usernameInput, cred.username);
    }
    
    if (passInput && cred.password) {
      setNativeInputValue(passInput, cred.password);
    }
  }

  function setNativeInputValue(inputEl, value) {
    if (!inputEl) return;
    try {
      const valueSetter = Object.getOwnPropertyDescriptor(inputEl, 'value')?.set ||
                          Object.getOwnPropertyDescriptor(Object.getPrototypeOf(inputEl), 'value')?.set;
      if (valueSetter) {
        valueSetter.call(inputEl, value);
      } else {
        inputEl.value = value;
      }
    } catch (e) {
      inputEl.value = value;
    }

    inputEl.focus();
    inputEl.dispatchEvent(new Event('input', { bubbles: true }));
    inputEl.dispatchEvent(new Event('change', { bubbles: true }));
    inputEl.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, key: 'a' }));
    inputEl.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: 'a' }));
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

  // ==========================================
  // AUTOMATIC AI PHISHING PROTECTION
  // ==========================================
  const SAFE_DOMAINS_LIST = [
    "google.", "bing.com", "duckduckgo.com", "yahoo.com", "facebook.com", 
    "github.com", "youtube.com", "microsoft.com", "apple.com", "amazon.com", 
    "wikipedia.org", "localhost", "whatsapp.com", "whatsapp.net", "web.whatsapp.com", 
    "meta.com", "messenger.com"
  ];
  const currentHref = window.location.href.toLowerCase();

  if (!SAFE_DOMAINS_LIST.some(d => currentHref.includes(d))) {
    chrome.runtime.sendMessage({ type: "CHECK_URL_PHISHING", url: window.location.href }, (res) => {
      if (res && res.isPhishing) {
        disableVaultForPhishing();
        showPhishingWarningOverlay(res.result, window.location.href);
      }
    });
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "PHISHING_WARNING") {
      if (!SAFE_DOMAINS_LIST.some(d => (message.url || "").toLowerCase().includes(d))) {
        disableVaultForPhishing();
        showPhishingWarningOverlay(message.result, message.url);
      }
    }
  });

  function showPhishingWarningOverlay(result, url) {
    disableVaultForPhishing();
    if (document.getElementById("securepass-phishing-warning-toast")) return;

    const overlay = document.createElement("div");
    overlay.id = "securepass-phishing-warning-toast";
    overlay.style.cssText = `
      position: fixed !important;
      top: 24px !important;
      right: 24px !important;
      width: 380px !important;
      max-width: calc(100vw - 48px) !important;
      z-index: 2147483647 !important;
      background: #0f172a !important;
      border: 1px solid rgba(239, 68, 68, 0.5) !important;
      border-left: 5px solid #ef4444 !important;
      border-radius: 12px !important;
      color: #f8fafc !important;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
      padding: 1.25rem !important;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6), 0 0 20px rgba(239, 68, 68, 0.2) !important;
      box-sizing: border-box !important;
      animation: spSideToastSlide 0.35s cubic-bezier(0.16, 1, 0.3, 1) !important;
    `;

    const cleanDomain = url ? new URL(url).hostname : window.location.hostname;

    overlay.innerHTML = `
      <style>
        @keyframes spSideToastSlide {
          from { transform: translateX(120%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        .sp-side-btn-safe {
          background: #ef4444 !important;
          color: #ffffff !important;
          border: none !important;
          padding: 0.55rem 1rem !important;
          border-radius: 6px !important;
          font-weight: 700 !important;
          font-size: 0.82rem !important;
          cursor: pointer !important;
          flex: 1 !important;
          text-align: center !important;
          box-shadow: 0 4px 12px rgba(239,68,68,0.4) !important;
        }
        .sp-side-btn-safe:hover {
          background: #dc2626 !important;
        }
        .sp-side-btn-ignore {
          background: rgba(255,255,255,0.08) !important;
          color: #94a3b8 !important;
          border: 1px solid rgba(255,255,255,0.15) !important;
          padding: 0.55rem 0.85rem !important;
          border-radius: 6px !important;
          font-weight: 500 !important;
          font-size: 0.82rem !important;
          cursor: pointer !important;
        }
        .sp-side-btn-ignore:hover {
          color: #ffffff !important;
          background: rgba(255,255,255,0.18) !important;
        }
      </style>
      <div style="display: flex; flex-direction: column; gap: 0.75rem;">
        <div style="display: flex; align-items: flex-start; gap: 0.75rem;">
          <div style="font-size: 1.8rem; background: rgba(239,68,68,0.15); padding: 0.4rem; border-radius: 8px; flex-shrink: 0; line-height: 1;">🚨</div>
          <div style="flex: 1;">
            <div style="font-size: 0.95rem; font-weight: 800; color: #f87171; text-transform: uppercase; letter-spacing: 0.04em; display: flex; align-items: center; justify-content: space-between;">
              <span>Phishing Warning</span>
              <span style="font-size: 0.65rem; font-weight: 600; background: rgba(239,68,68,0.2); color: #fca5a5; padding: 0.1rem 0.4rem; border-radius: 4px;">AI Active</span>
            </div>
            <p style="margin: 0.4rem 0 0 0; font-size: 0.83rem; color: #cbd5e1; line-height: 1.45;">
              <strong>${cleanDomain}</strong> is flagged as a dangerous phishing attempt by SecurePass AI (Linear SVM).
            </p>
          </div>
        </div>
        <div style="display: flex; align-items: center; gap: 0.5rem; margin-top: 0.25rem;">
          <button id="sp-btn-phishing-safety" class="sp-side-btn-safe">
            🛡️ Leave Site
          </button>
          <button id="sp-btn-phishing-ignore" class="sp-side-btn-ignore">
            Dismiss
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    document.getElementById("sp-btn-phishing-safety").onclick = () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.close();
      }
    };

    document.getElementById("sp-btn-phishing-ignore").onclick = () => {
      overlay.remove();
    };
  }
}
