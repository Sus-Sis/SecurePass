let securepassTabId = null;

// Listen for messages from content scripts and popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log("Background received message:", message);

  // 1. Web App Content Script registers the SecurePass Tab
  if (message.type === "SECUREPASS_REGISTER_TAB") {
    securepassTabId = sender.tab.id;
    console.log("SecurePass Web Tab registered with ID:", securepassTabId);
    sendResponse({ success: true });
    return true;
  }

  // 2. Regular Content Script requests credentials for a domain
  if (message.type === "GET_CREDENTIALS") {
    if (!securepassTabId) {
      // Find SecurePass tab if it wasn't registered automatically
      findSecurePassTab().then(tabId => {
        if (tabId) {
          securepassTabId = tabId;
          queryWebTabForCredentials(message.domain, sender.tab.id);
        } else {
          // Send back empty response since no web app is open
          chrome.tabs.sendMessage(sender.tab.id, { 
            type: "AUTOFILL_CREDENTIALS", 
            data: null, 
            error: "SecurePass web app dashboard is not open. Please open and unlock it." 
          });
        }
      });
    } else {
      queryWebTabForCredentials(message.domain, sender.tab.id);
    }
    sendResponse({ status: "searching" });
    return true;
  }

  // 3. Web App relays decrypted credentials back to background
  if (message.type === "RELAY_CREDENTIALS") {
    const { requesterTabId, credentials } = message;
    if (requesterTabId) {
      chrome.tabs.sendMessage(requesterTabId, { 
        type: "AUTOFILL_CREDENTIALS", 
        data: credentials 
      });
    }
    sendResponse({ success: true });
    return true;
  }

  // 4. Regular Content Script wants to save credentials
  if (message.type === "SAVE_CREDENTIALS") {
    if (securepassTabId) {
      chrome.tabs.sendMessage(securepassTabId, {
        type: "REQ_SAVE_CREDENTIALS",
        credentials: message.credentials
      });
      sendResponse({ success: true });
    } else {
      sendResponse({ error: "SecurePass web app not connected" });
    }
    return true;
  }

  // 4b. Popup wants to save action log
  if (message.type === "SAVE_CREDENTIALS_LOG") {
    if (securepassTabId) {
      chrome.tabs.sendMessage(securepassTabId, {
        type: "REQ_LOG_ACTION",
        action: message.action
      });
      sendResponse({ success: true });
    } else {
      sendResponse({ error: "SecurePass web app not connected" });
    }
    return true;
  }

  // 5. Popup requests status
  if (message.type === "POPUP_GET_STATUS") {
    findSecurePassTab().then(tabId => {
      if (tabId) {
        securepassTabId = tabId;
        sendResponse({ connected: true });
      } else {
        securepassTabId = null;
        sendResponse({ connected: false });
      }
    });
    return true; // async
  }

  // 6. Popup requests credentials list for current domain
  if (message.type === "POPUP_GET_CREDENTIALS") {
    if (securepassTabId) {
      // Relay request to SecurePass tab, which will send response back
      // Since it's async, we can setup a temporary response path,
      // or we can query the web app tab using a specific message
      // We will tell the Web App to relay credentials and target this request.
      // But wait! Since popup runs in its own context, the RELAY_CREDENTIALS message
      // can be captured by background, and background can relay it to the popup.
      // To handle this, we can store the popup listener's sendResponse callback
      // or simply broadcast a message that popup is listening to.
      // Let's broadcast "POPUP_CREDENTIALS_RESULT" which the popup's chrome.runtime.onMessage will listen to!
      chrome.tabs.sendMessage(securepassTabId, {
        type: "REQ_POPUP_CREDENTIALS",
        domain: message.domain
      });
      sendResponse({ status: "requested" });
    } else {
      sendResponse({ error: "SecurePass web app not connected" });
    }
    return true;
  }

  // 7. Web App relays credentials list back for the popup
  if (message.type === "RELAY_POPUP_CREDENTIALS") {
    chrome.runtime.sendMessage({
      type: "POPUP_CREDENTIALS_RESULT",
      credentials: message.credentials
    });
    sendResponse({ success: true });
    return true;
  }
});

// Helper: Query the SecurePass Web App tab for a domain's credentials
function queryWebTabForCredentials(domain, requesterTabId) {
  if (securepassTabId) {
    chrome.tabs.sendMessage(securepassTabId, {
      type: "REQ_CREDENTIALS",
      domain,
      requesterTabId
    });
  }
}

// Helper: Find active SecurePass tab
async function findSecurePassTab() {
  const tabs = await chrome.tabs.query({});
  for (const tab of tabs) {
    if (tab.url && (tab.url.includes("localhost:3000") || tab.url.includes("localhost:5173") || tab.url.includes("securepass.com"))) {
      return tab.id;
    }
  }
  return null;
}

// Handle browser action click - open dashboard
chrome.action?.onClicked?.addListener((tab) => {
  chrome.tabs.create({ url: "http://localhost:5173/vault" });
});
