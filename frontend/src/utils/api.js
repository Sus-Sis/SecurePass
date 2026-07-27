const API_BASE = "http://localhost:8000"; // Default FastAPI backend URL

async function request(endpoint, method = "GET", body = null, token = null) {
  const headers = {
    "Content-Type": "application/json",
  };
  
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const config = {
    method,
    headers,
  };

  if (body) {
    config.body = JSON.stringify(body);
  }

  const response = await fetch(`${API_BASE}${endpoint}`, config);
  
  if (response.status === 401) {
    // Session expired or invalid - let context handle it
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.detail || "Unauthorized");
  }

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.detail || `Request failed with status ${response.status}`);
  }

  return await response.json();
}

export const api = {
  // Authentication
  register: (data) => request("/api/auth/register", "POST", data),
  
  prelogin: (data) => request("/api/auth/prelogin", "POST", data),
  
  login: (email, verifier, mfaCode = null) => 
    request("/api/auth/login", "POST", { email, verifier, mfa_code: mfaCode }),
    
  logout: (token) => request("/api/auth/logout", "POST", null, token),
  
  getMe: (token) => request("/api/auth/me", "GET", null, token),
  
  deleteAccount: (token) => request("/api/auth/delete-account", "DELETE", null, token),

  // MFA
  enableMFA: (token) => request("/api/auth/mfa/enable", "POST", null, token),
  
  verifyMFA: (token, totpCode) => 
    request("/api/auth/mfa/verify", "POST", { totp_code: totpCode }, token),
    
  disableMFA: (token, totpCode) => 
    request("/api/auth/mfa/disable", "POST", { totp_code: totpCode }, token),

  // Vault
  getVault: (token) => request("/api/vault", "GET", null, token),
  
  updateVault: (token, encryptedVault) => 
    request("/api/vault", "PUT", { encrypted_vault: encryptedVault }, token),
    
  exportVault: (token) => request("/api/vault/export", "GET", null, token),

  // Logs
  getLogs: (token) => request("/api/logs", "GET", null, token),
  
  createLog: (token, action) => 
    request("/api/logs", "POST", { action }, token),

  changePassword: (token, data) => 
    request("/api/auth/change-password", "POST", data, token),

  // Recovery
  initiateRecovery: (email) => 
    request("/api/auth/recovery/initiate", "POST", { email }),
    
  verifyRecovery: (data) => 
    request("/api/auth/recovery/verify", "POST", data),

  // AI Phishing Scan
  scanUrl: (url) => 
    request("/api/scan-url", "POST", { url }),
};
