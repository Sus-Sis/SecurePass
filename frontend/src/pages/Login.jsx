import React, { useState, useEffect } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { api } from "../utils/api";
import { 
  decryptMasterKeyWithRecoveryCode, 
  decryptVault, 
  deriveMasterKey, 
  computeAuthVerifier, 
  encryptMasterKeyWithRecoveryCode, 
  encryptVault,
  generateRecoveryCode
} from "../utils/crypto";

export default function Login() {
  const { login, unlock, token, isLocked, user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [loading, setLoading] = useState(false);

  // Recovery States
  const [isRecoveryMode, setIsRecoveryMode] = useState(false);
  const [recoveryEmail, setRecoveryEmail] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmNewPassword, setConfirmNewPassword] = useState("");
  const [recoveryStep, setRecoveryStep] = useState(1); // 1: initiate, 2: decrypt & set password
  const [recoveryPayload, setRecoveryPayload] = useState(null); // { salt, encrypted_key_recovery, encrypted_vault }
  const [newRecoveryCode, setNewRecoveryCode] = useState("");

  // Determine redirection
  const from = location.state?.from?.pathname || "/vault";

  // Redirect if already logged in and unlocked
  useEffect(() => {
    if (token && !isLocked) {
      navigate(from, { replace: true });
    }
  }, [token, isLocked, navigate, from]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      if (token && isLocked) {
        // Unlock mode
        await unlock(password);
        navigate(from, { replace: true });
      } else {
        // Login mode
        const result = await login(email, password, mfaRequired ? mfaCode : null);
        if (result.mfaRequired) {
          setMfaRequired(true);
        } else if (result.success) {
          navigate(from, { replace: true });
        }
      }
    } catch (err) {
      setError(err.message || "Authentication failed.");
    } finally {
      setLoading(false);
    }
  };

  // ZK Recovery Flow - Step 1: Fetch recovery payload
  const handleInitiateRecovery = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const res = await api.initiateRecovery(recoveryEmail);
      if (!res.salt || !res.encrypted_key_recovery) {
        throw new Error("Account is not recoverable or email was not found.");
      }
      setRecoveryPayload({
        salt: res.salt,
        encrypted_key_recovery: res.encrypted_key_recovery,
        encrypted_vault: res.encrypted_vault || "[]"
      });
      setRecoveryStep(2);
    } catch (err) {
      setError(err.message || "Failed to initiate recovery.");
    } finally {
      setLoading(false);
    }
  };

  // ZK Recovery Flow - Step 2: Decrypt old vault, encrypt with new credentials
  const handleVerifyRecovery = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    if (newPassword !== confirmNewPassword) {
      setError("Passwords do not match.");
      setLoading(false);
      return;
    }

    if (newPassword.length < 12) {
      setError("Master password must be at least 12 characters.");
      setLoading(false);
      return;
    }

    try {
      // 1. Decrypt Master Key (MK) using Recovery Code inputted by user
      const cleanRecoveryCode = recoveryCode.trim();
      const oldMK = await decryptMasterKeyWithRecoveryCode(
        recoveryPayload.encrypted_key_recovery, 
        cleanRecoveryCode
      );

      // 2. Decrypt old vault using the decrypted old master key
      const decryptedVaultArray = await decryptVault(
        recoveryPayload.encrypted_vault, 
        oldMK
      );

      // 3. Derive new Master Key (MK') using new password and new salt
      const newSalt = generateRecoveryCode(); // generate random salt hex (32 bytes hex = 64 chars)
      const newMK = await deriveMasterKey(newPassword, newSalt);
      const newVerifier = await computeAuthVerifier(newMK);

      // 4. Encrypt decrypted vault with new master key
      const newEncryptedVault = await encryptVault(decryptedVaultArray, newMK);

      // 5. Encrypt new master key with a newly generated recovery code
      const generatedCode = generateRecoveryCode();
      const newEncryptedMKRecovery = await encryptMasterKeyWithRecoveryCode(newMK, generatedCode);
      const newRecoveryHash = await computeAuthVerifier(await deriveMasterKey(generatedCode, newSalt));

      // 6. Send recovery details to backend
      const hashedRecoverySent = await computeAuthVerifier(await deriveMasterKey(cleanRecoveryCode, recoveryPayload.salt));
      
      await api.verifyRecovery({
        email: recoveryEmail,
        recovery_code: hashedRecoverySent, // Hash it so server checks against bcrypt hash
        new_verifier: newVerifier,
        new_salt: newSalt,
        new_encrypted_vault: newEncryptedVault,
        new_encrypted_key_recovery: newEncryptedMKRecovery,
        new_recovery_codes_hash: newRecoveryHash
      });

      setNewRecoveryCode(generatedCode);
      setRecoveryStep(3);
      setInfo("Account recovered successfully!");
    } catch (err) {
      setError("Failed to decrypt or recover account. Please check your recovery code. Details: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadNewRecoveryCode = () => {
    if (!newRecoveryCode) return;
    const element = document.createElement("a");
    const file = new Blob([
      `SECUREPASS RECOVERY CODE\n`,
      `Registered Email: ${recoveryEmail}\n`,
      `Generated At: ${new Date().toISOString()}\n\n`,
      `Recovery Code: ${newRecoveryCode}\n\n`,
      `WARNING: Keep this code safe. Anyone with this code can decrypt and access your passwords if you forget your master password.`
    ], { type: 'text/plain' });
    element.href = URL.createObjectURL(file);
    element.download = `SecurePass-NEW-RecoveryCode-${recoveryEmail}.txt`;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const resetRecovery = () => {
    setIsRecoveryMode(false);
    setRecoveryEmail("");
    setRecoveryCode("");
    setNewPassword("");
    setConfirmNewPassword("");
    setRecoveryStep(1);
    setRecoveryPayload(null);
    setNewRecoveryCode("");
    setError("");
  };

  // Render Lock Mode
  if (token && isLocked) {
    return (
      <div className="auth-wrapper">
        <div className="card auth-card">
          <div className="auth-header">
            <h1 className="auth-title">Vault Locked</h1>
            <p className="auth-subtitle">Signed in as <strong>{user?.email}</strong>. Enter your master password to unlock.</p>
          </div>

          {error && <div className="alert alert-danger">{error}</div>}

          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label className="form-label" htmlFor="unlock-password">Master Password</label>
              <div className="input-wrapper">
                <input
                  id="unlock-password"
                  type={showPassword ? "text" : "password"}
                  className="form-input form-input-icon-right"
                  placeholder="Master password..."
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  autoFocus
                  disabled={loading}
                />
                <button
                  type="button"
                  className="input-icon-btn"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? (
                    <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0112 19c-7 0-11-7-11-7a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 7 11 7a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
                  ) : (
                    <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                  )}
                </button>
              </div>
            </div>

            <button
              type="submit"
              className="btn btn-primary"
              style={{ width: "100%", marginTop: "1rem" }}
              disabled={loading}
            >
              {loading ? (
                <>
                  <svg className="animate-spin" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" style={{ marginRight: '8px', animation: 'spin 1s linear infinite' }}><circle cx="12" cy="12" r="10" opacity="0.25"></circle><path d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" fill="currentColor"></path></svg>
                  Deriving Key...
                </>
              ) : (
                "Unlock Vault"
              )}
            </button>
            
            <button
              type="button"
              className="btn btn-secondary"
              style={{ width: "100%", marginTop: "0.5rem" }}
              onClick={logout}
            >
              Switch Account / Logout
            </button>
          </form>
        </div>
        <style>{`
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
        `}</style>
      </div>
    );
  }

  // Render Recovery Mode
  if (isRecoveryMode) {
    return (
      <div className="auth-wrapper">
        <div className="card auth-card">
          <div className="auth-header">
            <h1 className="auth-title">Account Recovery</h1>
            <p className="auth-subtitle">Zero-knowledge recovery decrypts your vault client-side.</p>
          </div>

          {error && <div className="alert alert-danger">{error}</div>}
          {info && <div className="alert alert-success">{info}</div>}

          {recoveryStep === 1 && (
            <form onSubmit={handleInitiateRecovery}>
              <div className="form-group">
                <label className="form-label" htmlFor="recovery-email">Your Account Email</label>
                <input
                  id="recovery-email"
                  type="email"
                  className="form-input"
                  placeholder="name@domain.com"
                  value={recoveryEmail}
                  onChange={(e) => setRecoveryEmail(e.target.value)}
                  required
                  disabled={loading}
                />
              </div>

              <button
                type="submit"
                className="btn btn-primary"
                style={{ width: "100%", marginTop: "1rem" }}
                disabled={loading}
              >
                {loading ? "Fetching Payload..." : "Initiate Recovery"}
              </button>
              
              <button
                type="button"
                className="btn btn-secondary"
                style={{ width: "100%", marginTop: "0.5rem" }}
                onClick={resetRecovery}
              >
                Back to Login
              </button>
            </form>
          )}

          {recoveryStep === 2 && (
            <form onSubmit={handleVerifyRecovery}>
              <div className="form-group">
                <label className="form-label" htmlFor="recovery-code">Recovery Code</label>
                <input
                  id="recovery-code"
                  type="text"
                  className="form-input"
                  placeholder="Enter 64-char recovery code..."
                  value={recoveryCode}
                  onChange={(e) => setRecoveryCode(e.target.value)}
                  required
                  disabled={loading}
                />
              </div>

              <div className="form-group">
                <label className="form-label" htmlFor="new-password">New Master Password</label>
                <input
                  id="new-password"
                  type="password"
                  className="form-input"
                  placeholder="At least 12 characters..."
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                  disabled={loading}
                />
              </div>

              <div className="form-group">
                <label className="form-label" htmlFor="confirm-new-password">Confirm New Password</label>
                <input
                  id="confirm-new-password"
                  type="password"
                  className="form-input"
                  placeholder="Confirm new password..."
                  value={confirmNewPassword}
                  onChange={(e) => setConfirmNewPassword(e.target.value)}
                  required
                  disabled={loading}
                />
              </div>

              <button
                type="submit"
                className="btn btn-primary"
                style={{ width: "100%", marginTop: "1rem" }}
                disabled={loading}
              >
                {loading ? "Decrypting & Updating..." : "Recover Account"}
              </button>
              
              <button
                type="button"
                className="btn btn-secondary"
                style={{ width: "100%", marginTop: "0.5rem" }}
                onClick={resetRecovery}
              >
                Cancel
              </button>
            </form>
          )}

          {recoveryStep === 3 && (
            <div>
              <div className="recovery-box">
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                  Your account has been recovered! Here is your NEW recovery code. Write this down or download it.
                </p>
                <div className="recovery-code-display">{newRecoveryCode}</div>
                <p style={{ fontSize: '0.75rem', color: 'var(--accent-red)', fontWeight: 'bold' }}>
                  The old recovery code is now invalid.
                </p>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <button
                  onClick={handleDownloadNewRecoveryCode}
                  className="btn btn-secondary"
                  style={{ width: '100%' }}
                >
                  Download New Recovery Code (.txt)
                </button>
                <button
                  onClick={resetRecovery}
                  className="btn btn-primary"
                  style={{ width: '100%' }}
                >
                  Go to Login
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  }

  // Render Standard Login Mode
  return (
    <div className="auth-wrapper">
      <div className="card auth-card">
        <div className="auth-header">
          <h1 className="auth-title">Welcome Back</h1>
          <p className="auth-subtitle">Log in to unlock your SecurePass vault.</p>
        </div>

        {error && <div className="alert alert-danger">{error}</div>}

        <form onSubmit={handleSubmit}>
          {!mfaRequired ? (
            <>
              <div className="form-group">
                <label className="form-label" htmlFor="login-email">Email Address</label>
                <input
                  id="login-email"
                  type="email"
                  className="form-input"
                  placeholder="name@domain.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  disabled={loading}
                />
              </div>

              <div className="form-group">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <label className="form-label" htmlFor="login-password">Master Password</label>
                  <button 
                    type="button" 
                    className="nav-link" 
                    style={{ background: 'none', border: 'none', fontSize: '0.8rem', padding: 0, textDecoration: 'underline' }}
                    onClick={() => setIsRecoveryMode(true)}
                  >
                    Forgot Password?
                  </button>
                </div>
                <div className="input-wrapper">
                  <input
                    id="login-password"
                    type={showPassword ? "text" : "password"}
                    className="form-input form-input-icon-right"
                    placeholder="Master password..."
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    disabled={loading}
                  />
                  <button
                    type="button"
                    className="input-icon-btn"
                    onClick={() => setShowPassword(!showPassword)}
                    aria-label={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? (
                      <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0112 19c-7 0-11-7-11-7a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 7 11 7a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
                    ) : (
                      <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                    )}
                  </button>
                </div>
              </div>
            </>
          ) : (
            <div className="form-group">
              <label className="form-label" htmlFor="mfa-code">MFA Verification Code</label>
              <input
                id="mfa-code"
                type="text"
                className="form-input"
                placeholder="6-digit authenticator code..."
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                required
                maxLength="6"
                disabled={loading}
                autoFocus
              />
              <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                Multi-factor authentication is active. Enter the code from your app.
              </p>
            </div>
          )}

          <button
            type="submit"
            className="btn btn-primary"
            style={{ width: "100%", marginTop: "1rem" }}
            disabled={loading}
          >
            {loading ? (
              <>
                <svg className="animate-spin" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" style={{ marginRight: '8px', animation: 'spin 1s linear infinite' }}><circle cx="12" cy="12" r="10" opacity="0.25"></circle><path d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" fill="currentColor"></path></svg>
                {mfaRequired ? "Verifying code..." : "Deriving Key & Login..."}
              </>
            ) : (
              mfaRequired ? "Verify and Log In" : "Log In"
            )}
          </button>
          
          {mfaRequired && (
            <button
              type="button"
              className="btn btn-secondary"
              style={{ width: "100%", marginTop: "0.5rem" }}
              onClick={() => { setMfaRequired(false); setMfaCode(""); setError(""); }}
            >
              Cancel
            </button>
          )}
        </form>

        <div style={{ textAlign: "center", marginTop: "1.5rem" }}>
          <span style={{ fontSize: "0.9rem", color: "var(--text-secondary)" }}>
            Don't have an account?{" "}
            <Link to="/register" className="nav-link" style={{ display: "inline", textDecoration: "underline" }}>
              Register here
            </Link>
          </span>
        </div>
      </div>
      
      <style>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
