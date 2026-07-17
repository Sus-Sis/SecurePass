import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function Register() {
  const { register } = useAuth();
  const navigate = useNavigate();
  
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);
  const [recoveryCode, setRecoveryCode] = useState("");

  // Calculate password strength
  const getPasswordStrength = (pwd) => {
    if (!pwd) return { score: 0, label: "None", color: "#6B7280" };
    let score = 0;
    if (pwd.length >= 8) score += 1;
    if (pwd.length >= 12) score += 1;
    if (/[A-Z]/.test(pwd)) score += 1;
    if (/[a-z]/.test(pwd)) score += 1;
    if (/[0-9]/.test(pwd)) score += 1;
    if (/[^A-Za-z0-9]/.test(pwd)) score += 1;

    // Map score (0-6) to meter
    if (score <= 2) return { score: 20, label: "Weak", color: "#EF4444" };
    if (score <= 4) return { score: 60, label: "Medium", color: "#F59E0B" };
    return { score: 100, label: "Strong", color: "#10B981" };
  };

  const strength = getPasswordStrength(password);

  const handleRegister = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");
    
    if (!email || !password || !confirmPassword) {
      setError("Please fill out all fields.");
      return;
    }

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    if (password.length < 12) {
      setError("Master password must be at least 12 characters long.");
      return;
    }

    setLoading(true);
    try {
      const res = await register(email, password);
      setRecoveryCode(res.recoveryCode);
      setSuccess("Account successfully registered! Please write down or download your Recovery Code.");
    } catch (err) {
      setError(err.message || "Registration failed. Try again.");
    } finally {
      setLoading(false);
    }
  };

  const downloadRecoveryCode = () => {
    if (!recoveryCode) return;
    const element = document.createElement("a");
    const file = new Blob([
      `SECUREPASS RECOVERY CODE\n`,
      `Registered Email: ${email}\n`,
      `Generated At: ${new Date().toISOString()}\n\n`,
      `Recovery Code: ${recoveryCode}\n\n`,
      `WARNING: Keep this code safe. Anyone with this code can decrypt and access your passwords if you forget your master password.`
    ], { type: 'text/plain' });
    element.href = URL.createObjectURL(file);
    element.download = `SecurePass-RecoveryCode-${email}.txt`;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  return (
    <div className="auth-wrapper">
      <div className="card auth-card">
        <div className="auth-header">
          <h1 className="auth-title">Create Account</h1>
          <p className="auth-subtitle">Welcome to SecurePass. Your zero-knowledge vault awaits.</p>
        </div>

        {error && <div className="alert alert-danger">{error}</div>}
        {success && <div className="alert alert-success">{success}</div>}

        {!recoveryCode ? (
          <form onSubmit={handleRegister}>
            <div className="form-group">
              <label className="form-label" htmlFor="email">Email Address</label>
              <input
                id="email"
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
              <label className="form-label" htmlFor="password">Master Password</label>
              <div className="input-wrapper">
                <input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  className="form-input form-input-icon-right"
                  placeholder="At least 12 characters..."
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
              
              {password && (
                <div className="strength-meter-container">
                  <div className="strength-bar-bg">
                    <div 
                      className="strength-bar" 
                      style={{ 
                        width: `${strength.score}%`, 
                        backgroundColor: strength.color 
                      }}
                    ></div>
                  </div>
                  <div className="strength-label">
                    <span>Password Strength:</span>
                    <span style={{ color: strength.color }}>{strength.label}</span>
                  </div>
                </div>
              )}
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="confirm-password">Confirm Master Password</label>
              <input
                id="confirm-password"
                type={showPassword ? "text" : "password"}
                className="form-input"
                placeholder="Re-enter master password..."
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
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
              {loading ? (
                <>
                  <svg className="animate-spin" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" style={{ marginRight: '8px', animation: 'spin 1s linear infinite' }}><circle cx="12" cy="12" r="10" opacity="0.25"></circle><path d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" fill="currentColor"></path></svg>
                  Creating Vault...
                </>
              ) : (
                "Register"
              )}
            </button>
          </form>
        ) : (
          <div>
            <div className="recovery-box">
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                This is your emergency recovery code. If you forget your password, you will need this code to decrypt your credentials.
              </p>
              <div className="recovery-code-display">{recoveryCode}</div>
              <p style={{ fontSize: '0.75rem', color: 'var(--accent-red)', fontWeight: 'bold' }}>
                Store this safely. We cannot recover it for you!
              </p>
            </div>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <button 
                onClick={downloadRecoveryCode} 
                className="btn btn-secondary" 
                style={{ width: '100%' }}
              >
                Download Recovery Code (.txt)
              </button>
              <button 
                onClick={() => navigate("/login")} 
                className="btn btn-primary" 
                style={{ width: '100%' }}
              >
                Go to Login
              </button>
            </div>
          </div>
        )}

        {!recoveryCode && (
          <div style={{ textAlign: "center", marginTop: "1.5rem" }}>
            <span style={{ fontSize: "0.9rem", color: "var(--text-secondary)" }}>
              Already have an account?{" "}
              <Link to="/login" className="nav-link" style={{ display: "inline", textDecoration: "underline" }}>
                Login here
              </Link>
            </span>
          </div>
        )}
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
