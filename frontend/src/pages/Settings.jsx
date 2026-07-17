import React, { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { api } from "../utils/api";
import { useNavigate } from "react-router-dom";
import { deriveMasterKey, computeAuthVerifier } from "../utils/crypto";

export default function Settings() {
  const { token, logout, changeMasterPassword, decryptedVault, user } = useAuth();
  const navigate = useNavigate();

  // Change Password States
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmNewPassword, setConfirmNewPassword] = useState("");
  const [pwdError, setPwdError] = useState("");
  const [pwdSuccess, setPwdSuccess] = useState("");

  // MFA States
  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [mfaSetupData, setMfaSetupData] = useState(null); // { qr_code_url, secret }
  const [mfaVerifyCode, setMfaVerifyCode] = useState("");
  const [mfaError, setMfaError] = useState("");
  const [mfaSuccess, setMfaSuccess] = useState("");
  const [showMfaModal, setShowMfaModal] = useState(false);
  const [mfaDisableCode, setMfaDisableCode] = useState("");

  // Export States
  const [exportWarning, setExportWarning] = useState(false);

  // Delete Account States
  const [deleteEmailConfirm, setDeleteEmailConfirm] = useState("");
  const [deleteError, setDeleteError] = useState("");

  // Activity Logs States
  const [logs, setLogs] = useState([]);
  const [logsLoading, setLogsLoading] = useState(false);

  // General Message State
  const [toastMessage, setToastMessage] = useState("");

  // Fetch Activity Logs & MFA status on mount
  useEffect(() => {
    fetchLogs();
    checkUserMfaStatus();
  }, []);

  const showToast = (msg) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(""), 3000);
  };

  const fetchLogs = async () => {
    if (!token) return;
    setLogsLoading(true);
    try {
      const res = await api.getLogs(token);
      setLogs(res.logs || []);
    } catch (e) {
      showToast("Failed to fetch activity logs.");
    } finally {
      setLogsLoading(false);
    }
  };

  const checkUserMfaStatus = async () => {
    if (!token) return;
    try {
      const res = await api.getMe(token);
      setMfaEnabled(res.mfa_enabled);
    } catch (e) {
      showToast("Failed to fetch user security status.");
    }
  };

  const handleChangePasswordSubmit = async (e) => {
    e.preventDefault();
    setPwdError("");
    setPwdSuccess("");

    if (newPassword !== confirmNewPassword) {
      setPwdError("New passwords do not match.");
      return;
    }

    if (newPassword.length < 12) {
      setPwdError("New password must be at least 12 characters.");
      return;
    }

    try {
      // 1. Derive re-encryption details in AuthContext
      const changePayload = await changeMasterPassword(currentPassword, newPassword);
      
      // 2. Submit change request to server
      // The current verifier should be calculated using the old salt
      const oldSalt = await api.prelogin({ email: user.email }).then(r => r.salt);
      const oldMK = await deriveMasterKey(currentPassword, oldSalt);
      const currentVerifierHex = await computeAuthVerifier(oldMK);

      await api.changePassword(token, {
        current_verifier: currentVerifierHex,
        new_salt: changePayload.newSalt,
        new_verifier: changePayload.newVerifier,
        new_encrypted_vault: changePayload.newEncryptedVault,
        new_encrypted_key_recovery: changePayload.newEncryptedMKRecovery,
        new_recovery_codes_hash: changePayload.recoveryHash
      });

      setPwdSuccess("Master password successfully updated! All other sessions have been logged out.");
      setCurrentPassword("");
      setNewPassword("");
      setConfirmNewPassword("");
      
      // Since changing password logs out all sessions, let's delay logout slightly so the user sees the success message
      setTimeout(() => {
        logout();
        navigate("/login");
      }, 3000);
    } catch (err) {
      setPwdError(err.message || "Failed to update master password.");
    }
  };

  // MFA Setup
  const handleInitiateMfa = async () => {
    setMfaError("");
    setMfaSuccess("");
    try {
      const res = await api.enableMFA(token);
      setMfaSetupData(res);
      setShowMfaModal(true);
    } catch (err) {
      setMfaError("MFA setup failed: " + err.message);
    }
  };

  const handleVerifyMfaSubmit = async (e) => {
    e.preventDefault();
    setMfaError("");
    try {
      await api.verifyMFA(token, mfaVerifyCode);
      setMfaSuccess("MFA successfully enabled!");
      setMfaEnabled(true);
      setShowMfaModal(false);
      setMfaSetupData(null);
      setMfaVerifyCode("");
      fetchLogs();
    } catch (err) {
      setMfaError("Invalid code. Please try again.");
    }
  };

  const handleDisableMfa = async (e) => {
    e.preventDefault();
    setMfaError("");
    setMfaSuccess("");
    try {
      await api.disableMFA(token, mfaDisableCode);
      setMfaSuccess("MFA successfully disabled!");
      setMfaEnabled(false);
      setMfaDisableCode("");
      fetchLogs();
    } catch (err) {
      setMfaError("Failed to disable MFA. Incorrect code.");
    }
  };

  // Exports
  const handleExportVault = () => {
    if (!decryptedVault) return;
    const element = document.createElement("a");
    const file = new Blob([JSON.stringify(decryptedVault, null, 2)], { type: "application/json" });
    element.href = URL.createObjectURL(file);
    element.download = `SecurePass-DecryptedVault-${user?.email}.json`;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
    setExportWarning(false);
    showToast("Vault exported successfully.");
  };

  // Delete account
  const handleDeleteAccountSubmit = async (e) => {
    e.preventDefault();
    setDeleteError("");
    if (deleteEmailConfirm.toLowerCase() !== user?.email.toLowerCase()) {
      setDeleteError("Email confirmation does not match your active account email.");
      return;
    }

    if (!window.confirm("CRITICAL WARNING: This will permanently delete your account, vault, and recovery keys. This action CANNOT be undone. Proceed?")) return;

    try {
      await api.deleteAccount(token);
      showToast("Account deleted.");
      logout();
      navigate("/register");
    } catch (err) {
      setDeleteError("Failed to delete account: " + err.message);
    }
  };

  // Logs Export
  const handleExportLogsCSV = () => {
    if (logs.length === 0) return;
    const headers = "Action,Timestamp,IP Address\n";
    const rows = logs.map(log => 
      `"${log.action}","${new Date(log.timestamp).toLocaleString()}","${log.ip_address || "unknown"}"`
    ).join("\n");
    
    const element = document.createElement("a");
    const file = new Blob([headers + rows], { type: "text/csv" });
    element.href = URL.createObjectURL(file);
    element.download = `SecurePass-ActivityLogs-${user?.email}.csv`;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
    showToast("Logs exported as CSV.");
  };

  return (
    <div style={{ maxWidth: '800px', margin: '0 auto', padding: '1rem' }}>
      <h1 className="auth-title" style={{ textAlign: 'left', marginBottom: '2rem', fontSize: '2rem' }}>Account Settings</h1>

      {/* 1. Change Master Password Section */}
      <section className="card settings-section">
        <h2 className="settings-section-title">Change Master Password</h2>
        
        {pwdError && <div className="alert alert-danger">{pwdError}</div>}
        {pwdSuccess && <div className="alert alert-success">{pwdSuccess}</div>}

        <form onSubmit={handleChangePasswordSubmit}>
          <div className="form-group">
            <label className="form-label" htmlFor="current-master-pwd">Current Master Password</label>
            <input 
              id="current-master-pwd"
              type="password" 
              className="form-input" 
              placeholder="Current password..."
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="new-master-pwd">New Master Password</label>
            <input 
              id="new-master-pwd"
              type="password" 
              className="form-input" 
              placeholder="New password (min 12 chars)..."
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="confirm-new-master-pwd">Confirm New Master Password</label>
            <input 
              id="confirm-new-master-pwd"
              type="password" 
              className="form-input" 
              placeholder="Confirm new password..."
              value={confirmNewPassword}
              onChange={(e) => setConfirmNewPassword(e.target.value)}
              required
            />
          </div>

          <button type="submit" className="btn btn-primary" style={{ marginTop: '0.5rem' }}>
            Update Master Password
          </button>
        </form>
      </section>

      {/* 2. Multi-Factor Authentication Section */}
      <section className="card settings-section">
        <h2 className="settings-section-title">Multi-Factor Authentication (MFA)</h2>
        
        {mfaError && <div className="alert alert-danger">{mfaError}</div>}
        {mfaSuccess && <div className="alert alert-success">{mfaSuccess}</div>}

        <div className="settings-row">
          <div className="settings-info">
            <span className="settings-title">TOTP Authenticator Apps</span>
            <span className="settings-desc">
              Secure your account by requiring an authenticator code (like Google Authenticator or Authy) on login attempts.
            </span>
          </div>
          <div>
            {!mfaEnabled ? (
              <button onClick={handleInitiateMfa} className="btn btn-primary">
                Enable MFA
              </button>
            ) : (
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                <input 
                  type="text" 
                  className="form-input" 
                  placeholder="Code to disable..." 
                  maxLength="6"
                  style={{ width: '150px', padding: '0.5rem' }}
                  value={mfaDisableCode}
                  onChange={(e) => setMfaDisableCode(e.target.value)}
                />
                <button onClick={handleDisableMfa} className="btn btn-danger">
                  Disable MFA
                </button>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* 3. Export Decrypted Vault Section */}
      <section className="card settings-section">
        <h2 className="settings-section-title">Export Vault</h2>
        <div className="settings-row">
          <div className="settings-info">
            <span className="settings-title">Export Decrypted Vault (JSON)</span>
            <span className="settings-desc" style={{ color: 'var(--accent-red)' }}>
              WARNING: This will download all passwords in plain readable text. Store the downloaded file in a highly secure, encrypted container.
            </span>
          </div>
          <div>
            <button onClick={() => setExportWarning(true)} className="btn btn-secondary">
              Export Decrypted JSON
            </button>
          </div>
        </div>
      </section>

      {/* 4. Activity Logs Section */}
      <section className="card settings-section">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.5rem' }}>
          <h2 className="settings-section-title" style={{ borderBottom: 'none', margin: 0 }}>Activity Log History</h2>
          <button onClick={handleExportLogsCSV} disabled={logs.length === 0} className="btn btn-secondary" style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem' }}>
            Export CSV
          </button>
        </div>

        {logsLoading ? (
          <p style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>Loading logs...</p>
        ) : logs.length === 0 ? (
          <p style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>No logs recorded yet.</p>
        ) : (
          <div className="logs-table-container">
            <table className="logs-table">
              <thead>
                <tr>
                  <th>Action Event</th>
                  <th>Timestamp</th>
                  <th>IP Address</th>
                </tr>
              </thead>
              <tbody>
                {logs.map(log => (
                  <tr key={log.id}>
                    <td>
                      <span className={`badge ${
                        log.action.includes("success") || log.action.includes("enabled") ? "badge-success" : 
                        log.action.includes("failed") || log.action.includes("delete") ? "badge-danger" : "badge-info"
                      }`}>
                        {log.action.replace(/_/g, " ")}
                      </span>
                    </td>
                    <td>{new Date(log.timestamp).toLocaleString()}</td>
                    <td>{log.ip_address || "unknown"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* 5. Delete Account Section */}
      <section className="card settings-section" style={{ borderColor: 'rgba(239, 68, 68, 0.3)' }}>
        <h2 className="settings-section-title" style={{ color: 'var(--accent-red)' }}>Delete Account</h2>
        {deleteError && <div className="alert alert-danger">{deleteError}</div>}
        
        <form onSubmit={handleDeleteAccountSubmit} className="settings-row">
          <div className="settings-info">
            <span className="settings-title">Danger Zone: Delete Account</span>
            <span className="settings-desc">
              To verify deletion, type your account email (<strong>{user?.email}</strong>) below and submit.
            </span>
            <input 
              type="email" 
              className="form-input" 
              placeholder="Confirm account email..."
              value={deleteEmailConfirm}
              onChange={(e) => setDeleteEmailConfirm(e.target.value)}
              style={{ marginTop: '0.5rem', maxWidth: '320px' }}
              required
            />
          </div>
          <div>
            <button type="submit" className="btn btn-danger">
              Permanently Delete Account
            </button>
          </div>
        </form>
      </section>

      {/* MFA Verification Modal */}
      {showMfaModal && mfaSetupData && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="modal-header">
              <h2 className="modal-title">Enable Authenticator App MFA</h2>
              <button onClick={() => { setShowMfaModal(false); setMfaSetupData(null); }} className="btn-icon">
                <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              </button>
            </div>
            
            <form onSubmit={handleVerifyMfaSubmit}>
              <div className="modal-body">
                <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
                  Scan the QR code below using your authenticator app (such as Google Authenticator, Microsoft Authenticator, Authy, or Duo).
                </p>
                
                <div className="mfa-qr-container">
                  <div className="mfa-qr-code">
                    <img src={mfaSetupData.qr_code_url} alt="MFA QR Code" />
                  </div>
                  <div>
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Or enter this code manually:</p>
                    <div className="mfa-secret-text">{mfaSetupData.secret}</div>
                  </div>
                </div>

                <div className="form-group" style={{ marginTop: '1.5rem' }}>
                  <label className="form-label">Enter Authenticator Verification Code</label>
                  <input 
                    type="text" 
                    className="form-input" 
                    placeholder="6-digit code"
                    maxLength="6"
                    value={mfaVerifyCode}
                    onChange={(e) => setMfaVerifyCode(e.target.value)}
                    required
                    autoFocus
                  />
                </div>
              </div>

              <div className="modal-footer">
                <button type="button" onClick={() => { setShowMfaModal(false); setMfaSetupData(null); }} className="btn btn-secondary">
                  Cancel
                </button>
                <button type="submit" className="btn btn-success">
                  Verify & Enable
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Export Confirmation Warning Modal */}
      {exportWarning && (
        <div className="modal-overlay">
          <div className="modal-content" style={{ maxWidth: '440px' }}>
            <div className="modal-header">
              <h2 className="modal-title" style={{ color: 'var(--accent-red)' }}>Security Risk Warning</h2>
              <button onClick={() => setExportWarning(false)} className="btn-icon">
                <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              </button>
            </div>
            
            <div className="modal-body">
              <p style={{ fontSize: '0.95rem', lineHeight: '1.5', color: 'var(--text-primary)' }}>
                You are about to export your entire password vault in an unencrypted JSON format. 
              </p>
              <p style={{ fontSize: '0.9rem', lineHeight: '1.5', color: 'var(--text-secondary)', marginTop: '0.75rem' }}>
                Any person or software with access to this file will be able to read all of your usernames, passwords, and secure notes. 
              </p>
              <p style={{ fontSize: '0.85rem', color: 'var(--accent-yellow)', fontWeight: 'bold', marginTop: '0.75rem' }}>
                Are you absolutely sure you want to download this unencrypted file?
              </p>
            </div>

            <div className="modal-footer" style={{ background: 'rgba(239, 68, 68, 0.05)' }}>
              <button type="button" onClick={() => setExportWarning(false)} className="btn btn-secondary">
                Cancel
              </button>
              <button type="button" onClick={handleExportVault} className="btn btn-danger">
                Yes, Export Decrypted
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Global Toast confirmation */}
      {toastMessage && (
        <div className="toast">
          <svg width="18" height="18" fill="none" stroke="var(--accent-green)" strokeWidth="2.5" viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
          <span>{toastMessage}</span>
        </div>
      )}
    </div>
  );
}
