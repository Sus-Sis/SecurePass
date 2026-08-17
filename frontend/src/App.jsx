import React from "react";
import { BrowserRouter, Routes, Route, Navigate, Link, useLocation } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";

import Register from "./pages/Register";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Settings from "./pages/Settings";
import Admin from "./pages/Admin";

function Navigation() {
  const { token, isLocked, logout, lock, user } = useAuth();
  const location = useLocation();
  const [menuOpen, setMenuOpen] = React.useState(false);
  const menuRef = React.useRef(null);

  React.useEffect(() => {
    setMenuOpen(false);
  }, [location.pathname]);

  React.useEffect(() => {
    const handleClickOutside = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        setMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  if (!token || isLocked) return null;

  return (
    <nav className="navbar" style={{ padding: '0.85rem 1.75rem', background: 'rgba(9, 13, 22, 0.85)', backdropFilter: 'blur(20px)', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', position: 'relative', zIndex: 1000 }}>
      <Link to="/vault" className="nav-brand" style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', textDecoration: 'none', cursor: 'pointer' }}>
        <div style={{ width: '34px', height: '34px', borderRadius: '10px', background: 'var(--gradient-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.1rem', boxShadow: '0 0 15px rgba(6, 182, 212, 0.4)' }}>
          🛡️
        </div>
        <span style={{ fontFamily: 'var(--font-display)', fontWeight: 800, fontSize: '1.2rem', letterSpacing: '-0.02em', background: 'linear-gradient(135deg, #ffffff, #94a3b8)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
          SecurePass
        </span>
        <span style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--accent-cyan)', background: 'rgba(6, 182, 212, 0.15)', border: '1px solid rgba(6, 182, 212, 0.3)', padding: '0.15rem 0.5rem', borderRadius: '12px' }}>
          Zero-Knowledge
        </span>
      </Link>
      
      {/* Consolidated Single User Account & Navigation Menu */}
      <div style={{ position: 'relative' }} ref={menuRef}>
        <button 
          onClick={() => setMenuOpen(!menuOpen)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.55rem',
            background: menuOpen ? 'rgba(6, 182, 212, 0.2)' : 'rgba(30, 41, 59, 0.7)',
            border: menuOpen ? '1px solid var(--accent-cyan)' : '1px solid rgba(255, 255, 255, 0.12)',
            color: '#f8fafc',
            padding: '0.45rem 0.95rem',
            borderRadius: '24px',
            fontSize: '0.85rem',
            fontWeight: 600,
            cursor: 'pointer',
            transition: 'all 0.2s ease',
            boxShadow: menuOpen ? '0 0 15px rgba(6, 182, 212, 0.25)' : 'none'
          }}
        >
          <span style={{ fontSize: '0.95rem' }}>👤</span>
          <span>{user?.email}</span>
          {user?.is_admin && (
            <span style={{ background: 'rgba(245, 158, 11, 0.25)', border: '1px solid rgba(245, 158, 11, 0.4)', color: '#fbbf24', padding: '0.1rem 0.45rem', borderRadius: '10px', fontSize: '0.68rem', fontWeight: 800 }}>
              👑 ADMIN
            </span>
          )}
          <span style={{ fontSize: '0.75rem', color: '#94a3b8', marginLeft: '0.2rem', transform: menuOpen ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s ease' }}>
            ▼
          </span>
        </button>

        {/* Dropdown Menu */}
        {menuOpen && (
          <div style={{
            position: 'absolute',
            top: 'calc(100% + 0.6rem)',
            right: 0,
            width: '230px',
            background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.96), rgba(30, 41, 59, 0.96))',
            border: '1px solid rgba(255, 255, 255, 0.12)',
            borderRadius: '14px',
            padding: '0.5rem',
            boxShadow: '0 15px 35px rgba(0, 0, 0, 0.6)',
            backdropFilter: 'blur(20px)',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.25rem',
            animation: 'fadeInMenu 0.15s ease-out'
          }}>
            <Link 
              to="/vault"
              onClick={() => setMenuOpen(false)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.65rem',
                padding: '0.6rem 0.85rem',
                borderRadius: '8px',
                color: location.pathname === "/vault" ? 'var(--accent-cyan)' : '#f8fafc',
                background: location.pathname === "/vault" ? 'rgba(6, 182, 212, 0.15)' : 'transparent',
                fontWeight: 600,
                fontSize: '0.86rem',
                textDecoration: 'none'
              }}
            >
              <span>🔐</span>
              <span>Vault Workspace</span>
            </Link>

            {user?.is_admin && (
              <Link 
                to="/admin"
                onClick={() => setMenuOpen(false)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.65rem',
                  padding: '0.6rem 0.85rem',
                  borderRadius: '8px',
                  color: location.pathname === "/admin" ? '#fbbf24' : '#fbbf24',
                  background: location.pathname === "/admin" ? 'rgba(245, 158, 11, 0.2)' : 'rgba(245, 158, 11, 0.08)',
                  fontWeight: 700,
                  fontSize: '0.86rem',
                  textDecoration: 'none'
                }}
              >
                <span>👑</span>
                <span>Admin Panel</span>
              </Link>
            )}

            <Link 
              to="/settings"
              onClick={() => setMenuOpen(false)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.65rem',
                padding: '0.6rem 0.85rem',
                borderRadius: '8px',
                color: location.pathname === "/settings" ? 'var(--accent-cyan)' : '#f8fafc',
                background: location.pathname === "/settings" ? 'rgba(6, 182, 212, 0.15)' : 'transparent',
                fontWeight: 600,
                fontSize: '0.86rem',
                textDecoration: 'none'
              }}
            >
              <span>⚙️</span>
              <span>Settings</span>
            </Link>

            <div style={{ height: '1px', background: 'rgba(255, 255, 255, 0.08)', margin: '0.25rem 0' }} />

            <button
              onClick={() => {
                setMenuOpen(false);
                lock();
              }}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.65rem',
                padding: '0.6rem 0.85rem',
                borderRadius: '8px',
                color: '#cbd5e1',
                background: 'transparent',
                border: 'none',
                fontWeight: 600,
                fontSize: '0.86rem',
                cursor: 'pointer',
                textAlign: 'left',
                width: '100%'
              }}
            >
              <span>🔒</span>
              <span>Lock Vault</span>
            </button>

            <button
              onClick={() => {
                setMenuOpen(false);
                logout();
              }}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.65rem',
                padding: '0.6rem 0.85rem',
                borderRadius: '8px',
                color: '#f87171',
                background: 'rgba(239, 68, 68, 0.1)',
                border: 'none',
                fontWeight: 600,
                fontSize: '0.86rem',
                cursor: 'pointer',
                textAlign: 'left',
                width: '100%'
              }}
            >
              <span>🚪</span>
              <span>Log Out</span>
            </button>
          </div>
        )}
      </div>
    </nav>
  );
}

function ProtectedRoute({ children }) {
  const { token, isLocked } = useAuth();
  const location = useLocation();

  if (!token) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (isLocked) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return children;
}

function AdminRoute({ children }) {
  const { token, isLocked, user } = useAuth();
  const location = useLocation();

  if (!token || isLocked) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (!user?.is_admin) {
    return <Navigate to="/vault" replace />;
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
        <Route 
          path="/admin" 
          element={
            <AdminRoute>
              <Admin />
            </AdminRoute>
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
