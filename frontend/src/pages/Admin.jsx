import React, { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { api } from "../utils/api";

export default function Admin() {
  const { token, user } = useAuth();
  const [activeTab, setActiveTab] = useState("users"); // "users" | "logs"
  const [stats, setStats] = useState(null);
  const [users, setUsers] = useState([]);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [successMsg, setSuccessMsg] = useState("");

  // Filters & Search
  const [searchQuery, setSearchQuery] = useState("");
  const [roleFilter, setRoleFilter] = useState("all"); // "all" | "admin" | "user" | "locked"
  const [logSearchQuery, setLogSearchQuery] = useState("");

  // Modal confirm state
  const [confirmModal, setConfirmModal] = useState(null); // { type, userItem, title, text, actionFn }

  const fetchData = async () => {
    setLoading(true);
    setError("");
    try {
      const [statsRes, usersRes, logsRes] = await Promise.all([
        api.getAdminStats(token),
        api.getAdminUsers(token),
        api.getAdminLogs(token)
      ]);
      setStats(statsRes);
      setUsers(usersRes.users || []);
      setLogs(logsRes.logs || []);
    } catch (err) {
      setError(err.message || "Failed to load administrative data");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (token) {
      fetchData();
    }
  }, [token]);

  const showNotification = (msg) => {
    setSuccessMsg(msg);
    setTimeout(() => setSuccessMsg(""), 4000);
  };

  const handleToggleAdminRole = async (targetUser) => {
    const newRole = !targetUser.is_admin;
    try {
      const res = await api.toggleAdminRole(token, targetUser.id, newRole);
      showNotification(res.message);
      fetchData();
    } catch (err) {
      setError(err.message || "Failed to update user role");
    }
  };

  const handleToggleLockout = async (targetUser) => {
    const shouldLock = !targetUser.locked_until || new Date(targetUser.locked_until) <= new Date();
    try {
      const res = await api.toggleUserLockout(token, targetUser.id, shouldLock);
      showNotification(res.message);
      fetchData();
    } catch (err) {
      setError(err.message || "Failed to update account lockout status");
    }
  };

  const handleRevokeSessions = async (targetUser) => {
    try {
      const res = await api.revokeUserSessions(token, targetUser.id);
      showNotification(res.message);
      fetchData();
    } catch (err) {
      setError(err.message || "Failed to revoke user sessions");
    }
  };

  const handleDeleteUser = async (targetUser) => {
    try {
      const res = await api.deleteAdminUser(token, targetUser.id);
      showNotification(res.message);
      fetchData();
    } catch (err) {
      setError(err.message || "Failed to delete user account");
    }
  };

  const filteredUsers = users.filter((u) => {
    const matchesSearch = u.email.toLowerCase().includes(searchQuery.toLowerCase()) || u.id.toString() === searchQuery.trim();
    const isCurrentlyLocked = u.locked_until && new Date(u.locked_until) > new Date();

    if (!matchesSearch) return false;
    if (roleFilter === "admin") return u.is_admin;
    if (roleFilter === "user") return !u.is_admin;
    if (roleFilter === "locked") return isCurrentlyLocked;
    return true;
  });

  const filteredLogs = logs.filter((l) => {
    const q = logSearchQuery.toLowerCase();
    return (
      l.email.toLowerCase().includes(q) ||
      l.action.toLowerCase().includes(q) ||
      (l.ip_address && l.ip_address.includes(q))
    );
  });

  if (loading && !stats) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '60vh', gap: '1rem' }}>
        <svg className="animate-spin" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--accent-blue)" strokeWidth="3"><circle cx="12" cy="12" r="10" opacity="0.25"></circle><path d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" fill="currentColor"></path></svg>
        <p style={{ fontFamily: 'var(--font-display)', color: 'var(--text-secondary)', fontWeight: 600 }}>Loading Administrator Workspace...</p>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: '1240px', margin: '2rem auto', padding: '0 1.5rem' }}>
      {/* Header Banner */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.9), rgba(30, 41, 59, 0.7))',
        border: '1px solid rgba(255, 255, 255, 0.1)',
        borderRadius: '16px',
        padding: '1.75rem 2rem',
        marginBottom: '2rem',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        boxShadow: '0 10px 30px rgba(0, 0, 0, 0.3)',
        backdropFilter: 'blur(16px)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
          <div style={{
            width: '54px',
            height: '54px',
            borderRadius: '14px',
            background: 'linear-gradient(135deg, #f59e0b, #d97706)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '1.75rem',
            boxShadow: '0 0 20px rgba(245, 158, 11, 0.4)'
          }}>
            👑
          </div>
          <div>
            <h1 style={{ margin: 0, fontSize: '1.6rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
              System Administration Panel
            </h1>
            <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.88rem', color: '#94a3b8' }}>
              Zero-Knowledge Administrative Controls, System Metrics, User Management & Audit Logs
            </p>
          </div>
        </div>

        <button 
          onClick={fetchData} 
          className="btn btn-secondary" 
          style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.55rem 1.1rem', fontSize: '0.85rem' }}
        >
          🔄 Refresh Metrics
        </button>
      </div>

      {/* Notifications / Alerts */}
      {error && (
        <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.4)', borderRadius: '12px', padding: '1rem 1.25rem', color: '#f87171', marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <span>⚠️</span>
          <span>{error}</span>
        </div>
      )}

      {successMsg && (
        <div style={{ background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.4)', borderRadius: '12px', padding: '1rem 1.25rem', color: '#34d399', marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <span>✅</span>
          <span>{successMsg}</span>
        </div>
      )}

      {/* Metrics Overview Grid */}
      {stats && (
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
          gap: '1.25rem',
          marginBottom: '2rem'
        }}>
          {/* Total Users */}
          <div style={{ background: 'rgba(30, 41, 59, 0.6)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '14px', padding: '1.25rem', backdropFilter: 'blur(12px)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: '#94a3b8', fontSize: '0.82rem', fontWeight: 600 }}>
              <span>Total Registered Users</span>
              <span style={{ fontSize: '1.2rem' }}>👥</span>
            </div>
            <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#f8fafc', marginTop: '0.5rem' }}>
              {stats.total_users}
            </div>
            <div style={{ fontSize: '0.75rem', color: '#06b6d4', marginTop: '0.25rem' }}>Account Database</div>
          </div>

          {/* Active Sessions */}
          <div style={{ background: 'rgba(30, 41, 59, 0.6)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '14px', padding: '1.25rem', backdropFilter: 'blur(12px)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: '#94a3b8', fontSize: '0.82rem', fontWeight: 600 }}>
              <span>Active User Sessions</span>
              <span style={{ fontSize: '1.2rem' }}>⚡</span>
            </div>
            <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#38bdf8', marginTop: '0.5rem' }}>
              {stats.active_sessions}
            </div>
            <div style={{ fontSize: '0.75rem', color: '#38bdf8', marginTop: '0.25rem' }}>Valid JWT Tokens</div>
          </div>

          {/* MFA Protection */}
          <div style={{ background: 'rgba(30, 41, 59, 0.6)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '14px', padding: '1.25rem', backdropFilter: 'blur(12px)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: '#94a3b8', fontSize: '0.82rem', fontWeight: 600 }}>
              <span>MFA Enrolled Users</span>
              <span style={{ fontSize: '1.2rem' }}>🛡️</span>
            </div>
            <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#34d399', marginTop: '0.5rem' }}>
              {stats.mfa_users} <span style={{ fontSize: '0.9rem', color: '#94a3b8', fontWeight: 500 }}>({stats.total_users ? Math.round((stats.mfa_users / stats.total_users) * 100) : 0}%)</span>
            </div>
            <div style={{ fontSize: '0.75rem', color: '#34d399', marginTop: '0.25rem' }}>TOTP Authenticator Enabled</div>
          </div>

          {/* Locked Accounts */}
          <div style={{ background: 'rgba(30, 41, 59, 0.6)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '14px', padding: '1.25rem', backdropFilter: 'blur(12px)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: '#94a3b8', fontSize: '0.82rem', fontWeight: 600 }}>
              <span>Locked Accounts</span>
              <span style={{ fontSize: '1.2rem' }}>🔒</span>
            </div>
            <div style={{ fontSize: '1.8rem', fontWeight: 800, color: stats.locked_accounts > 0 ? '#f87171' : '#f8fafc', marginTop: '0.5rem' }}>
              {stats.locked_accounts}
            </div>
            <div style={{ fontSize: '0.75rem', color: stats.locked_accounts > 0 ? '#f87171' : '#94a3b8', marginTop: '0.25rem' }}>Brute-force / Manual Lockouts</div>
          </div>

          {/* AI Phishing Model */}
          <div style={{ background: 'rgba(30, 41, 59, 0.6)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '14px', padding: '1.25rem', backdropFilter: 'blur(12px)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: '#94a3b8', fontSize: '0.82rem', fontWeight: 600 }}>
              <span>AI Phishing Defense</span>
              <span style={{ fontSize: '1.2rem' }}>🤖</span>
            </div>
            <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#a78bfa', marginTop: '0.65rem' }}>
              {stats.phishing_model_status}
            </div>
            <div style={{ fontSize: '0.75rem', color: '#a78bfa', marginTop: '0.25rem' }}>Linear SVM URL Intelligence</div>
          </div>
        </div>
      )}

      {/* Navigation Tabs */}
      <div style={{ display: 'flex', gap: '1rem', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', marginBottom: '1.5rem', paddingBottom: '0.5rem' }}>
        <button
          onClick={() => setActiveTab("users")}
          style={{
            background: activeTab === "users" ? 'rgba(6, 182, 212, 0.15)' : 'transparent',
            border: activeTab === "users" ? '1px solid rgba(6, 182, 212, 0.4)' : '1px solid transparent',
            color: activeTab === "users" ? 'var(--accent-cyan)' : '#94a3b8',
            padding: '0.6rem 1.25rem',
            borderRadius: '10px',
            fontSize: '0.9rem',
            fontWeight: 700,
            cursor: 'pointer',
            transition: 'all 0.2s ease',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem'
          }}
        >
          <span>👤 User Accounts ({users.length})</span>
        </button>

        <button
          onClick={() => setActiveTab("logs")}
          style={{
            background: activeTab === "logs" ? 'rgba(6, 182, 212, 0.15)' : 'transparent',
            border: activeTab === "logs" ? '1px solid rgba(6, 182, 212, 0.4)' : '1px solid transparent',
            color: activeTab === "logs" ? 'var(--accent-cyan)' : '#94a3b8',
            padding: '0.6rem 1.25rem',
            borderRadius: '10px',
            fontSize: '0.9rem',
            fontWeight: 700,
            cursor: 'pointer',
            transition: 'all 0.2s ease',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem'
          }}
        >
          <span>📜 System Audit Logs ({logs.length})</span>
        </button>
      </div>

      {/* TAB 1: USER MANAGEMENT TABLE */}
      {activeTab === "users" && (
        <div style={{ background: 'rgba(30, 41, 59, 0.6)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '16px', padding: '1.5rem', backdropFilter: 'blur(16px)' }}>
          {/* Controls Bar */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
            <div style={{ flex: '1 1 300px', maxWidth: '400px' }}>
              <input
                type="text"
                placeholder="🔍 Search users by email or ID..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  width: '100%',
                  background: 'rgba(15, 23, 42, 0.7)',
                  border: '1px solid rgba(255, 255, 255, 0.12)',
                  borderRadius: '10px',
                  padding: '0.6rem 1rem',
                  color: '#f8fafc',
                  fontSize: '0.88rem'
                }}
              />
            </div>

            <div style={{ display: 'flex', gap: '0.5rem' }}>
              {[
                { id: "all", label: "All Users" },
                { id: "admin", label: "Admins Only" },
                { id: "user", label: "Standard Users" },
                { id: "locked", label: "Locked Accounts" }
              ].map((f) => (
                <button
                  key={f.id}
                  onClick={() => setRoleFilter(f.id)}
                  style={{
                    background: roleFilter === f.id ? 'rgba(6, 182, 212, 0.2)' : 'rgba(15, 23, 42, 0.5)',
                    border: roleFilter === f.id ? '1px solid var(--accent-cyan)' : '1px solid rgba(255, 255, 255, 0.08)',
                    color: roleFilter === f.id ? '#ffffff' : '#94a3b8',
                    padding: '0.4rem 0.85rem',
                    borderRadius: '8px',
                    fontSize: '0.78rem',
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  {f.label}
                </button>
              ))}
            </div>
          </div>

          {/* Table */}
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.1)', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em', fontSize: '0.72rem' }}>
                  <th style={{ padding: '0.75rem 1rem' }}>User Email</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Role</th>
                  <th style={{ padding: '0.75rem 1rem' }}>MFA</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Account Status</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Sessions</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Last Login</th>
                  <th style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredUsers.length === 0 ? (
                  <tr>
                    <td colSpan="7" style={{ padding: '2.5rem', textAlign: 'center', color: '#94a3b8' }}>
                      No matching user accounts found.
                    </td>
                  </tr>
                ) : (
                  filteredUsers.map((u) => {
                    const isLocked = u.locked_until && new Date(u.locked_until) > new Date();
                    const isSelf = user?.email === u.email;

                    return (
                      <tr key={u.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)', transition: 'background 0.15s ease' }}>
                        {/* Email */}
                        <td style={{ padding: '0.85rem 1rem', color: '#f8fafc', fontWeight: 600 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <span>{u.email}</span>
                            {isSelf && (
                              <span style={{ background: 'rgba(6, 182, 212, 0.2)', color: 'var(--accent-cyan)', border: '1px solid rgba(6, 182, 212, 0.3)', padding: '0.1rem 0.4rem', borderRadius: '6px', fontSize: '0.65rem' }}>
                                (You)
                              </span>
                            )}
                          </div>
                        </td>

                        {/* Role */}
                        <td style={{ padding: '0.85rem 1rem' }}>
                          {u.is_admin ? (
                            <span style={{ background: 'rgba(245, 158, 11, 0.2)', border: '1px solid rgba(245, 158, 11, 0.4)', color: '#fbbf24', padding: '0.2rem 0.6rem', borderRadius: '12px', fontSize: '0.72rem', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                              👑 Admin
                            </span>
                          ) : (
                            <span style={{ background: 'rgba(148, 163, 184, 0.15)', border: '1px solid rgba(148, 163, 184, 0.25)', color: '#cbd5e1', padding: '0.2rem 0.6rem', borderRadius: '12px', fontSize: '0.72rem', fontWeight: 600 }}>
                              Standard User
                            </span>
                          )}
                        </td>

                        {/* MFA */}
                        <td style={{ padding: '0.85rem 1rem' }}>
                          {u.mfa_enabled ? (
                            <span style={{ color: '#34d399', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}>
                              🟢 Enabled
                            </span>
                          ) : (
                            <span style={{ color: '#94a3b8' }}>⚪ Disabled</span>
                          )}
                        </td>

                        {/* Status */}
                        <td style={{ padding: '0.85rem 1rem' }}>
                          {isLocked ? (
                            <span style={{ background: 'rgba(239, 68, 68, 0.2)', border: '1px solid rgba(239, 68, 68, 0.4)', color: '#f87171', padding: '0.2rem 0.6rem', borderRadius: '12px', fontSize: '0.72rem', fontWeight: 700 }}>
                              🔴 Locked
                            </span>
                          ) : (
                            <span style={{ background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.3)', color: '#34d399', padding: '0.2rem 0.6rem', borderRadius: '12px', fontSize: '0.72rem', fontWeight: 600 }}>
                              🟢 Active
                            </span>
                          )}
                        </td>

                        {/* Sessions */}
                        <td style={{ padding: '0.85rem 1rem', color: '#cbd5e1' }}>
                          {u.active_sessions_count > 0 ? (
                            <span style={{ color: '#38bdf8', fontWeight: 700 }}>{u.active_sessions_count} active</span>
                          ) : (
                            <span style={{ color: '#64748b' }}>None</span>
                          )}
                        </td>

                        {/* Last Login */}
                        <td style={{ padding: '0.85rem 1rem', color: '#94a3b8', fontSize: '0.78rem' }}>
                          {u.last_login ? new Date(u.last_login).toLocaleString() : "Never"}
                        </td>

                        {/* Actions */}
                        <td style={{ padding: '0.85rem 1rem', textAlign: 'right' }}>
                          <div style={{ display: 'flex', gap: '0.4rem', justifyContent: 'flex-end' }}>
                            {/* Toggle Admin */}
                            <button
                              disabled={isSelf}
                              onClick={() => handleToggleAdminRole(u)}
                              title={u.is_admin ? "Demote to standard user" : "Promote to Admin"}
                              style={{
                                background: u.is_admin ? 'rgba(245, 158, 11, 0.15)' : 'rgba(30, 41, 59, 0.8)',
                                border: '1px solid rgba(255, 255, 255, 0.12)',
                                color: u.is_admin ? '#fbbf24' : '#cbd5e1',
                                padding: '0.35rem 0.65rem',
                                borderRadius: '6px',
                                fontSize: '0.75rem',
                                opacity: isSelf ? 0.4 : 1,
                                cursor: isSelf ? 'not-allowed' : 'pointer'
                              }}
                            >
                              {u.is_admin ? "Demote" : "Make Admin"}
                            </button>

                            {/* Lock/Unlock */}
                            <button
                              disabled={isSelf}
                              onClick={() => handleToggleLockout(u)}
                              title={isLocked ? "Unlock user account" : "Lock user account"}
                              style={{
                                background: isLocked ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                                border: '1px solid rgba(255, 255, 255, 0.12)',
                                color: isLocked ? '#34d399' : '#f87171',
                                padding: '0.35rem 0.65rem',
                                borderRadius: '6px',
                                fontSize: '0.75rem',
                                opacity: isSelf ? 0.4 : 1,
                                cursor: isSelf ? 'not-allowed' : 'pointer'
                              }}
                            >
                              {isLocked ? "Unlock" : "Lock"}
                            </button>

                            {/* Revoke Sessions */}
                            {u.active_sessions_count > 0 && (
                              <button
                                onClick={() => handleRevokeSessions(u)}
                                title="Terminate active sessions"
                                style={{
                                  background: 'rgba(56, 189, 248, 0.15)',
                                  border: '1px solid rgba(56, 189, 248, 0.3)',
                                  color: '#38bdf8',
                                  padding: '0.35rem 0.65rem',
                                  borderRadius: '6px',
                                  fontSize: '0.75rem',
                                  cursor: 'pointer'
                                }}
                              >
                                Revoke
                              </button>
                            )}

                            {/* Delete User */}
                            <button
                              disabled={isSelf}
                              onClick={() => {
                                setConfirmModal({
                                  userItem: u,
                                  title: "Delete User Account",
                                  text: `Are you sure you want to permanently delete user account "${u.email}"? This action cannot be undone.`,
                                  actionFn: () => handleDeleteUser(u)
                                });
                              }}
                              title="Delete account"
                              style={{
                                background: 'rgba(239, 68, 68, 0.2)',
                                border: '1px solid rgba(239, 68, 68, 0.4)',
                                color: '#f87171',
                                padding: '0.35rem 0.65rem',
                                borderRadius: '6px',
                                fontSize: '0.75rem',
                                opacity: isSelf ? 0.4 : 1,
                                cursor: isSelf ? 'not-allowed' : 'pointer'
                              }}
                            >
                              Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: SYSTEM AUDIT LOGS TABLE */}
      {activeTab === "logs" && (
        <div style={{ background: 'rgba(30, 41, 59, 0.6)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '16px', padding: '1.5rem', backdropFilter: 'blur(16px)' }}>
          <div style={{ marginBottom: '1.25rem' }}>
            <input
              type="text"
              placeholder="🔍 Search activity logs by email, action, or IP address..."
              value={logSearchQuery}
              onChange={(e) => setLogSearchQuery(e.target.value)}
              style={{
                width: '100%',
                maxWidth: '450px',
                background: 'rgba(15, 23, 42, 0.7)',
                border: '1px solid rgba(255, 255, 255, 0.12)',
                borderRadius: '10px',
                padding: '0.6rem 1rem',
                color: '#f8fafc',
                fontSize: '0.88rem'
              }}
            />
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.83rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.1)', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em', fontSize: '0.72rem' }}>
                  <th style={{ padding: '0.75rem 1rem' }}>Timestamp</th>
                  <th style={{ padding: '0.75rem 1rem' }}>User Email</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Action Event</th>
                  <th style={{ padding: '0.75rem 1rem' }}>IP Address</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Client Agent</th>
                </tr>
              </thead>
              <tbody>
                {filteredLogs.length === 0 ? (
                  <tr>
                    <td colSpan="5" style={{ padding: '2.5rem', textAlign: 'center', color: '#94a3b8' }}>
                      No activity logs match your search filter.
                    </td>
                  </tr>
                ) : (
                  filteredLogs.map((l) => {
                    const isFailure = l.action.includes("failed") || l.action.includes("recovery_failed");
                    const isSuccess = l.action.includes("success") || l.action.includes("registered");
                    const isAdminAct = l.action.startsWith("admin_");

                    return (
                      <tr key={l.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                        <td style={{ padding: '0.75rem 1rem', color: '#94a3b8', whiteSpace: 'nowrap' }}>
                          {new Date(l.timestamp).toLocaleString()}
                        </td>
                        <td style={{ padding: '0.75rem 1rem', color: '#f8fafc', fontWeight: 600 }}>
                          {l.email}
                        </td>
                        <td style={{ padding: '0.75rem 1rem' }}>
                          <span style={{
                            background: isFailure ? 'rgba(239, 68, 68, 0.15)' : (isAdminAct ? 'rgba(245, 158, 11, 0.15)' : (isSuccess ? 'rgba(16, 185, 129, 0.15)' : 'rgba(56, 189, 248, 0.15)')),
                            border: '1px solid ' + (isFailure ? 'rgba(239, 68, 68, 0.3)' : (isAdminAct ? 'rgba(245, 158, 11, 0.3)' : (isSuccess ? 'rgba(16, 185, 129, 0.3)' : 'rgba(56, 189, 248, 0.3)'))),
                            color: isFailure ? '#f87171' : (isAdminAct ? '#fbbf24' : (isSuccess ? '#34d399' : '#38bdf8')),
                            padding: '0.2rem 0.55rem',
                            borderRadius: '8px',
                            fontSize: '0.75rem',
                            fontWeight: 600,
                            fontFamily: 'monospace'
                          }}>
                            {l.action}
                          </span>
                        </td>
                        <td style={{ padding: '0.75rem 1rem', color: '#cbd5e1', fontFamily: 'monospace' }}>
                          {l.ip_address || "unknown"}
                        </td>
                        <td style={{ padding: '0.75rem 1rem', color: '#64748b', fontSize: '0.75rem', maxWidth: '250px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {l.user_agent || "unknown"}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Confirmation Dialog Modal */}
      {confirmModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999,
          padding: '1rem'
        }}>
          <div style={{
            background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.95), rgba(30, 41, 59, 0.95))',
            border: '1px solid rgba(239, 68, 68, 0.4)',
            borderRadius: '16px',
            padding: '2rem',
            maxWidth: '480px',
            width: '100%',
            boxShadow: '0 20px 50px rgba(0, 0, 0, 0.6)'
          }}>
            <h3 style={{ margin: '0 0 1rem 0', fontSize: '1.25rem', color: '#f87171', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span>⚠️</span>
              <span>{confirmModal.title}</span>
            </h3>
            <p style={{ color: '#cbd5e1', fontSize: '0.9rem', lineHeight: 1.5, marginBottom: '1.5rem' }}>
              {confirmModal.text}
            </p>
            <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end' }}>
              <button
                onClick={() => setConfirmModal(null)}
                className="btn btn-secondary"
                style={{ padding: '0.5rem 1rem', fontSize: '0.85rem' }}
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  confirmModal.actionFn();
                  setConfirmModal(null);
                }}
                className="btn btn-danger"
                style={{ padding: '0.5rem 1.1rem', fontSize: '0.85rem' }}
              >
                Confirm Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
