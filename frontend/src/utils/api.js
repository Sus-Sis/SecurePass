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
  
  srpChallenge: (email, client_A) => 
    request("/api/auth/srp/challenge", "POST", { email, client_A }),
    
  srpAuthenticate: (email, client_A, client_M1) => 
    request("/api/auth/srp/authenticate", "POST", { email, client_A, client_M1 }),

  login: (email, verifier) => 
    request("/api/auth/login", "POST", { email, verifier }),
    
  logout: (token) => request("/api/auth/logout", "POST", null, token),
  
  getMe: (token) => request("/api/auth/me", "GET", null, token),
  
  deleteAccount: (token) => request("/api/auth/delete-account", "DELETE", null, token),

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

  // Admin Management Endpoints
  getAdminStats: (token) => request("/api/admin/stats", "GET", null, token),
  getAdminUsers: (token) => request("/api/admin/users", "GET", null, token),
  toggleAdminRole: (token, userId, isAdmin) => request(`/api/admin/users/${userId}/role`, "PUT", { is_admin: isAdmin }, token),
  toggleUserLockout: (token, userId, locked) => request(`/api/admin/users/${userId}/lockout`, "PUT", { locked }, token),
  revokeUserSessions: (token, userId) => request(`/api/admin/users/${userId}/revoke-sessions`, "POST", null, token),
  deleteAdminUser: (token, userId) => request(`/api/admin/users/${userId}`, "DELETE", null, token),
  getAdminLogs: (token) => request("/api/admin/logs", "GET", null, token),
};
