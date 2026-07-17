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

  if (!token || isLocked) return null; // Hide navigation on login/register/unlock screens

  return (
    <nav className="navbar">
      <div className="nav-brand">
        <span>🛡️ SecurePass</span>
      </div>
      <div className="nav-links">
        <Link 
          to="/vault" 
          className={`nav-link ${location.pathname === "/vault" ? "active" : ""}`}
        >
          Vault
        </Link>
        <Link 
          to="/settings" 
          className={`nav-link ${location.pathname === "/settings" ? "active" : ""}`}
        >
          Settings
        </Link>
        <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginLeft: '0.5rem' }}>
          ({user?.email})
        </span>
        <button onClick={lock} className="btn btn-secondary" style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem' }}>
          Lock Vault
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
