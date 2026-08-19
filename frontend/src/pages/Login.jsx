import React, { useState, useEffect } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { api } from "../utils/api";
import { 
  decryptVault, 
  deriveMasterKey, 
  computeAuthVerifier, 
  encryptVault,
  generateSalt,
  getRawMasterKeyBytes,
  benchmarkArgon2Parameters,
  generateSrpVerifier,
  decryptMasterKeyWithEmailRecovery,
  encryptMasterKeyWithEmailRecovery
} from "../utils/crypto";

export default function Login() {
  const { login, unlock, token, isLocked, user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [loading, setLoading] = useState(false);

  // Recovery States
  const [isRecoveryMode, setIsRecoveryMode] = useState(false);
  const [recoveryEmail, setRecoveryEmail] = useState("");
  const [otpCode, setOtpCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmNewPassword, setConfirmNewPassword] = useState("");
  const [recoveryStep, setRecoveryStep] = useState(1);
  const [recoveryPayload, setRecoveryPayload] = useState(null);

  // Determine redirection target (always fallback to /vault)
  let targetPath = location.state?.from?.pathname || "/vault";
  if (targetPath === "/login" || targetPath === "/register" || targetPath === "/") {
    targetPath = "/vault";
  }

  // Redirect if already logged in and unlocked
  useEffect(() => {
    if (token && !isLocked) {
      navigate("/vault", { replace: true });
    }
  }, [token, isLocked, navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      if (token && isLocked) {
        // Unlock mode
        await unlock(password);
        navigate("/vault", { replace: true });
      } else {
        // Login mode
        const result = await login(email, password);
        if (result && result.success) {
          navigate("/vault", { replace: true });
        }
      }
    } catch (err) {
      setError(err.message || "Authentication failed.");
    } finally {
      setLoading(false);
    }
  };

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
        encrypted_vault: res.encrypted_vault || "[]",
        dev_otp: res.dev_otp
      });
      setRecoveryStep(2);
    } catch (err) {
      setError(err.message || "Failed to initiate recovery.");
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyRecovery = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    if (!otpCode || otpCode.trim().length !== 6) {
      setError("Please enter your 6-digit email verification code.");
      setLoading(false);
      return;
    }

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
      const oldMK = await decryptMasterKeyWithEmailRecovery(
        recoveryPayload.encrypted_key_recovery, 
        recoveryEmail,
        recoveryPayload.salt
      );

      const decryptedVaultArray = await decryptVault(
        recoveryPayload.encrypted_vault, 
        oldMK
      );

      const newSalt = generateSalt();
      const newKdfParams = await benchmarkArgon2Parameters(300);
      const newMK = await deriveMasterKey(newPassword, newSalt, newKdfParams);
      const newMKBytes = await getRawMasterKeyBytes(newMK);
      const newVerifier = await generateSrpVerifier(newSalt, newMKBytes);

      const newEncryptedVault = await encryptVault(decryptedVaultArray, newMK);
      const newEncryptedMKRecovery = await encryptMasterKeyWithEmailRecovery(newMK, recoveryEmail, newSalt);
      const newRecoveryHash = await computeAuthVerifier(newMK);

      await api.verifyRecovery({
        email: recoveryEmail,
        otp_code: otpCode.trim(),
        recovery_code: "email_otp_authenticated",
        new_verifier: newVerifier,
        new_salt: newSalt,
        new_kdf_params: newKdfParams,
        new_encrypted_vault: newEncryptedVault,
        new_encrypted_key_recovery: newEncryptedMKRecovery,
        new_recovery_codes_hash: newRecoveryHash
      });

      setInfo("Account recovered & Master Password updated! Please log in below.");
      setIsRecoveryMode(false);
      setEmail(recoveryEmail);
      setPassword("");
    } catch (err) {
      setError("Failed to recover account. Details: " + err.message);
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
    setOtpCode("");
    setRecoveryCode("");
    setNewPassword("");
    setConfirmNewPassword("");
    setRecoveryStep(1);
    setRecoveryPayload(null);
    setNewRecoveryCode("");
    setError("");
    setInfo("");
  };

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

  if (isRecoveryMode) {
    return (
      <div className="auth-wrapper">
        <div className="card auth-card">
          <div className="auth-header">
            <h1 className="auth-title">Account Recovery</h1>
            <p className="auth-subtitle">Zero-knowledge dual-factor recovery decrypts your vault client-side.</p>
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
              {recoveryPayload?.dev_otp && (
                <div style={{ background: 'rgba(6, 182, 212, 0.15)', border: '1px dashed var(--accent-cyan)', padding: '0.75rem', borderRadius: '8px', marginBottom: '1rem', textAlign: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)', fontWeight: 'bold', display: 'block', marginBottom: '4px' }}>
                    🛠️ LOCALHOST TESTING - EMAIL VERIFICATION OTP
                  </span>
                  <span style={{ fontFamily: 'monospace', fontSize: '1.2rem', letterSpacing: '4px', color: '#6EE7B7', fontWeight: 'bold' }}>
                    {recoveryPayload.dev_otp}
                  </span>
                  <span style={{ fontSize: '0.7rem', color: '#94A3B8', display: 'block', marginTop: '4px' }}>
                    (Check backend terminal or use code above for local testing)
                  </span>
                </div>
              )}

              <div className="form-group">
                <label className="form-label" htmlFor="otp-code">6-Digit Email Verification Code (OTP)</label>
                <input
                  id="otp-code"
                  type="text"
                  className="form-input"
                  placeholder="Enter 6-digit email OTP (e.g. 123456)..."
                  value={otpCode}
                  onChange={(e) => setOtpCode(e.target.value)}
                  maxLength={6}
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
                {loading ? "Decrypting & Updating..." : "Recover Account & Reset Password"}
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
              <div className="recovery-box" style={{ background: 'rgba(16, 185, 129, 0.1)', border: '1px solid var(--accent-green, #10B981)', borderRadius: '12px', padding: '1.25rem', marginBottom: '1.25rem' }}>
                <h3 style={{ fontSize: '1.1rem', fontWeight: '600', color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
                  🎉 Account Successfully Recovered!
                </h3>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
                  Here is your <strong>NEW Emergency Recovery Code</strong>. Save this immediately. The old recovery code has been permanently revoked.
                </p>
                <div className="recovery-code-display" style={{ background: 'rgba(0,0,0,0.4)', padding: '0.85rem', borderRadius: '8px', fontFamily: 'monospace', fontSize: '0.95rem', wordBreak: 'break-all', textAlign: 'center', border: '1px dashed var(--accent-purple)', color: '#6EE7B7' }}>
                  {newRecoveryCode}
                </div>
                <p style={{ fontSize: '0.75rem', color: '#F87171', fontWeight: 'bold', marginTop: '0.75rem', textAlign: 'center' }}>
                  ⚠️ Save this key safely. SecurePass cannot retrieve it for you!
                </p>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(newRecoveryCode);
                    setInfo("New recovery code copied to clipboard!");
                  }}
                  className="btn btn-secondary"
                  style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}
                >
                  📋 Copy New Recovery Code
                </button>
                <button
                  onClick={handleDownloadNewRecoveryCode}
                  className="btn btn-secondary"
                  style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}
                >
                  💾 Download New Recovery Code (.txt)
                </button>
                <button
                  onClick={resetRecovery}
                  className="btn btn-primary"
                  style={{ width: '100%', marginTop: '0.5rem' }}
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

  return (
    <div className="auth-wrapper">
      <div className="card auth-card">
        <div className="auth-header">
          <h1 className="auth-title">Welcome Back</h1>
          <p className="auth-subtitle">Log in to unlock your SecurePass vault.</p>
        </div>

        {error && <div className="alert alert-danger">{error}</div>}

        <form onSubmit={handleSubmit}>
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

          <button
            type="submit"
            className="btn btn-primary"
            style={{ width: "100%", marginTop: "1rem" }}
            disabled={loading}
          >
            {loading ? (
              <>
                <svg className="animate-spin" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" style={{ marginRight: '8px', animation: 'spin 1s linear infinite' }}><circle cx="12" cy="12" r="10" opacity="0.25"></circle><path d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" fill="currentColor"></path></svg>
                Deriving Key & Login...
              </>
            ) : (
              "Log In"
            )}
          </button>
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
