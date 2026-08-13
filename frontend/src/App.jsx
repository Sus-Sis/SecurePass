import React from "react";
import { BrowserRouter, Routes, Route, Navigate, Link, useLocation } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";

import Register from "./pages/Register";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Settings from "./pages/Settings";

function Navigation() {
  const { token, isLocked, logout, lock, user } = useAuth();
  const location = useLocation();
  const [currentTheme, setCurrentTheme] = React.useState(localStorage.getItem("securepass_theme") || "obsidian");

  React.useEffect(() => {
    const savedTheme = localStorage.getItem("securepass_theme");
    if (savedTheme && savedTheme !== "obsidian") {
      document.documentElement.setAttribute("data-theme", savedTheme);
    }
  }, []);

  const changeTheme = (e) => {
    const theme = e.target.value;
    setCurrentTheme(theme);
    localStorage.setItem("securepass_theme", theme);
    if (theme === "obsidian") {
      document.documentElement.removeAttribute("data-theme");
    } else {
      document.documentElement.setAttribute("data-theme", theme);
    }
  };

  if (!token || isLocked) return null;

  return (
    <nav className="navbar" style={{ padding: '0.85rem 1.75rem', background: 'rgba(9, 13, 22, 0.85)', backdropFilter: 'blur(20px)', borderBottom: '1px solid rgba(255, 255, 255, 0.08)' }}>
      <div className="nav-brand" style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
        <div style={{ width: '34px', height: '34px', borderRadius: '10px', background: 'var(--gradient-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.1rem', boxShadow: '0 0 15px rgba(6, 182, 212, 0.4)' }}>
          🛡️
        </div>
        <span style={{ fontFamily: 'var(--font-display)', fontWeight: 800, fontSize: '1.2rem', letterSpacing: '-0.02em', background: 'linear-gradient(135deg, #ffffff, #94a3b8)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
          SecurePass
        </span>
        <span style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--accent-cyan)', background: 'rgba(6, 182, 212, 0.15)', border: '1px solid rgba(6, 182, 212, 0.3)', padding: '0.15rem 0.5rem', borderRadius: '12px' }}>
          Zero-Knowledge
        </span>
      </div>
      
      <div className="nav-links" style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
        <Link 
          to="/vault" 
          className={`nav-link ${location.pathname === "/vault" ? "active" : ""}`}
          style={{ padding: '0.4rem 0.85rem', borderRadius: '8px', fontSize: '0.88rem', fontWeight: 600 }}
        >
          🔐 Vault Workspace
        </Link>
        <Link 
          to="/settings" 
          className={`nav-link ${location.pathname === "/settings" ? "active" : ""}`}
          style={{ padding: '0.4rem 0.85rem', borderRadius: '8px', fontSize: '0.88rem', fontWeight: 600 }}
        >
          ⚙️ Settings
        </Link>

        {/* Theme Picker Dropdown */}
        <select 
          value={currentTheme}
          onChange={changeTheme}
          style={{ background: 'rgba(30, 41, 59, 0.7)', border: '1px solid rgba(255,255,255,0.12)', color: '#f1f5f9', padding: '0.35rem 0.65rem', borderRadius: '8px', fontSize: '0.78rem', fontWeight: 600, cursor: 'pointer' }}
          title="Change Color Theme"
        >
          <option value="obsidian">🎨 Obsidian Cyan</option>
          <option value="emerald">🌿 Dark Emerald</option>
          <option value="amethyst">🔮 Amethyst Violet</option>
          <option value="titanium">⚡ Titanium Blue</option>
        </select>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', background: 'rgba(30, 41, 59, 0.6)', border: '1px solid rgba(255, 255, 255, 0.08)', padding: '0.3rem 0.75rem', borderRadius: '20px', fontSize: '0.78rem', color: '#cbd5e1' }}>
          <span>👤</span>
          <span>{user?.email}</span>
        </div>

        <button onClick={lock} className="btn btn-secondary" style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
          🔒 Lock Vault
        </button>
        <button onClick={logout} className="btn btn-danger" style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem' }}>
          Log Out
        </button>
      </div>
    </nav>
  );
}

function ProtectedRoute({ children }) {
  const { token, isLocked } = useAuth();
  const location = useLocation();

  if (!token) {
    // Redirect to login if not authenticated at all
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (isLocked) {
    // Redirect to login (which will render the unlock screen) if session is active but vault is locked
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return children;
}

function AppContent() {
  const { loading } = useAuth();

  if (loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', gap: '1rem' }}>
        <svg className="animate-spin" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--accent-blue)" strokeWidth="3" style={{ animation: 'spin 1s linear infinite' }}><circle cx="12" cy="12" r="10" opacity="0.25"></circle><path d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" fill="currentColor"></path></svg>
        <p style={{ fontFamily: 'var(--font-display)', fontWeight: '600', color: 'var(--text-secondary)' }}>Decrypting Secure Vault...</p>
        <style>{`
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
        `}</style>
      </div>
    );
  }

  return (
    <div className="app-container">
      <Navigation />
      <Routes>
        <Route path="/register" element={<Register />} />
        <Route path="/login" element={<Login />} />
        <Route 
          path="/vault" 
          element={
            <ProtectedRoute>
              <Dashboard />
            </ProtectedRoute>
          } 
        />
        <Route 
          path="/settings" 
          element={
            <ProtectedRoute>
              <Settings />
            </ProtectedRoute>
          } 
        />
        {/* Fallback */}
        <Route path="*" element={<Navigate to="/vault" replace />} />
      </Routes>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <AppContent />
      </BrowserRouter>
    </AuthProvider>
  );
}
