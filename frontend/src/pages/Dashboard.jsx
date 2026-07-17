import React, { useState } from "react";
import { useAuth } from "../context/AuthContext";
import { api } from "../utils/api";
import { generateSecurePassword } from "../utils/crypto";

export default function Dashboard() {
  const { decryptedVault, syncVault, token } = useAuth();
  
  // Navigation & Filtering States
  const [activeTab, setActiveTab] = useState("all"); // all, logins, notes, cards, generator
  const [searchQuery, setSearchQuery] = useState("");
  
  // Modal States
  const [showAddEditModal, setShowAddEditModal] = useState(false);
  const [editingItem, setEditingItem] = useState(null); // null if adding
  
  const [showGenModal, setShowGenModal] = useState(false);
  
  // Form States
  const [siteName, setSiteName] = useState("");
  const [siteUrl, setSiteUrl] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [notes, setNotes] = useState("");
  const [category, setCategory] = useState("Logins");

  // Generator States (within modal or floating)
  const [genLength, setGenLength] = useState(16);
  const [genOptions, setGenOptions] = useState({
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true
  });
  const [generatedPass, setGeneratedPass] = useState("");

  // Visible Passwords Mapping
  const [visiblePasswords, setVisiblePasswords] = useState({}); // { id: boolean }
  
  // Notification / Toast States
  const [toastMessage, setToastMessage] = useState("");

  // Helpers
  const showToast = (msg) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(""), 3000);
  };

  const copyToClipboard = async (text, type, label) => {
    try {
      await navigator.clipboard.writeText(text);
      showToast(`${label} copied to clipboard!`);
      // Log event to backend
      if (token) {
        await api.createLog(token, `credential_copied_${type}`);
      }
    } catch (err) {
      showToast("Failed to copy.");
    }
  };

  const togglePasswordVisibility = async (id) => {
    const isVisible = !visiblePasswords[id];
    setVisiblePasswords(prev => ({ ...prev, [id]: isVisible }));
    if (isVisible && token) {
      // Log password viewed
      await api.createLog(token, "credential_viewed");
    }
  };

  const formatToDomain = (url) => {
    if (!url) return "";
    try {
      let cleanUrl = url.trim();
      if (!cleanUrl.startsWith("http://") && !cleanUrl.startsWith("https://")) {
        cleanUrl = "https://" + cleanUrl;
      }
      const parsed = new URL(cleanUrl);
      return parsed.hostname.replace("www.", "");
    } catch (e) {
      return url;
    }
  };

  const handleOpenAdd = () => {
    setEditingItem(null);
    setSiteName("");
    setSiteUrl("");
    setUsername("");
    setPassword("");
    setNotes("");
    setCategory("Logins");
    setShowAddEditModal(true);
  };

  const handleOpenEdit = (item) => {
    setEditingItem(item);
    setSiteName(item.name || "");
    setSiteUrl(item.url || "");
    setUsername(item.username || "");
    setPassword(item.password || "");
    setNotes(item.notes || "");
    setCategory(item.category || "Logins");
    setShowAddEditModal(true);
  };

  const handleSaveCredential = async (e) => {
    e.preventDefault();
    if (!siteName || !username || !password) {
      showToast("Please fill in required fields.");
      return;
    }

    const cleanUrl = siteUrl ? formatToDomain(siteUrl) : "";
    const updatedVault = [...(decryptedVault || [])];

    if (editingItem) {
      // Edit mode
      const idx = updatedVault.findIndex(x => x.id === editingItem.id);
      if (idx !== -1) {
        updatedVault[idx] = {
          ...editingItem,
          name: siteName,
          url: cleanUrl,
          username,
          password,
          notes,
          category,
          updated_at: new Date().toISOString()
        };
      }
      showToast("Credential updated.");
    } else {
      // Add mode
      const newItem = {
        id: crypto.randomUUID(),
        name: siteName,
        url: cleanUrl,
        username,
        password,
        notes,
        category,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };
      updatedVault.push(newItem);
      showToast("Credential added.");
    }

    try {
      await syncVault(updatedVault);
      setShowAddEditModal(false);
    } catch (err) {
      showToast(err.message || "Failed to sync vault.");
    }
  };

  const handleDeleteCredential = async (id) => {
    if (!window.confirm("Are you sure you want to delete this credential?")) return;
    
    const updatedVault = (decryptedVault || []).filter(x => x.id !== id);
    try {
      await syncVault(updatedVault);
      showToast("Credential deleted.");
    } catch (err) {
      showToast("Failed to delete credential.");
    }
  };

  const handleGenerate = () => {
    const pw = generateSecurePassword(genLength, genOptions);
    setGeneratedPass(pw);
  };

  const calculateEntropy = (pw) => {
    if (!pw) return { bits: 0, strength: "None", color: "#6B7280" };
    let poolSize = 0;
    if (/[a-z]/.test(pw)) poolSize += 26;
    if (/[A-Z]/.test(pw)) poolSize += 26;
    if (/[0-9]/.test(pw)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) poolSize += 26; // approx symbols pool

    const bits = Math.floor(pw.length * Math.log2(poolSize));
    if (bits < 40) return { bits, strength: "Weak", color: "#EF4444" };
    if (bits < 80) return { bits, strength: "Moderate", color: "#F59E0B" };
    return { bits, strength: "Strong", color: "#10B981" };
  };

  const currentEntropy = calculateEntropy(generatedPass);

  // Filters
  const filteredItems = (decryptedVault || []).filter(item => {
    const matchesSearch = 
      item.name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.username?.toLowerCase().includes(searchQuery.toLowerCase());
    
    if (activeTab === "all") return matchesSearch;
    if (activeTab === "logins") return matchesSearch && item.category === "Logins";
    if (activeTab === "notes") return matchesSearch && item.category === "Secure Notes";
    if (activeTab === "cards") return matchesSearch && item.category === "Cards";
    return false;
  });

  return (
    <div className="dashboard-layout">
      {/* Sidebar */}
      <aside className="sidebar">
        <button 
          className={`sidebar-item ${activeTab === "all" ? "active" : ""}`}
          onClick={() => setActiveTab("all")}
        >
          <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="9" rx="1"></rect><rect x="14" y="3" width="7" height="5" rx="1"></rect><rect x="14" y="12" width="7" height="9" rx="1"></rect><rect x="3" y="16" width="7" height="5" rx="1"></rect></svg>
          All Credentials
        </button>
        <button 
          className={`sidebar-item ${activeTab === "logins" ? "active" : ""}`}
          onClick={() => setActiveTab("logins")}
        >
          <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
          Logins
        </button>
        <button 
          className={`sidebar-item ${activeTab === "notes" ? "active" : ""}`}
          onClick={() => setActiveTab("notes")}
        >
          <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
          Secure Notes
        </button>
        <button 
          className={`sidebar-item ${activeTab === "cards" ? "active" : ""}`}
          onClick={() => setActiveTab("cards")}
        >
          <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><rect x="1" y="4" width="22" height="16" rx="2" ry="2"></rect><line x1="1" y1="10" x2="23" y2="10"></line></svg>
          Cards / Identity
        </button>
        <button 
          className="sidebar-item"
          onClick={() => { setShowGenModal(true); handleGenerate(); }}
        >
          <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><key d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></key><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"></path></svg>
          Password Generator
        </button>
      </aside>

      {/* Main Panel */}
      <main className="main-content">
        <div className="actions-bar">
          <div className="search-wrapper">
            <svg className="search-icon" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
            <input 
              type="text" 
              className="search-input" 
              placeholder="Search website, username..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
          <button onClick={handleOpenAdd} className="btn btn-primary">
            <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
            Add Credential
          </button>
        </div>

        {filteredItems.length === 0 ? (
          <div className="card empty-state">
            <div className="site-icon" style={{ width: '60px', height: '60px', borderRadius: '50%', fontSize: '1.8rem' }}>🔒</div>
            <h2 className="empty-state-title">No credentials found</h2>
            <p className="empty-state-desc">
              {searchQuery ? "No items matched your search query." : "Your zero-knowledge vault is empty. Get started by adding your first password."}
            </p>
            {!searchQuery && (
              <button onClick={handleOpenAdd} className="btn btn-primary" style={{ marginTop: '0.5rem' }}>
                Add Password
              </button>
            )}
          </div>
        ) : (
          <div className="credentials-grid">
            {filteredItems.map(item => (
              <div key={item.id} className="card credential-card">
                <div>
                  <div className="card-header">
                    <div className="site-icon">
                      {item.name ? item.name.substring(0, 2).toUpperCase() : "?"}
                    </div>
                    <div className="card-title-group">
                      <span className="card-site-name">{item.name}</span>
                      {item.url && (
                        <a 
                          href={item.url.startsWith("http") ? item.url : `https://${item.url}`} 
                          target="_blank" 
                          rel="noopener noreferrer" 
                          className="card-site-url"
                        >
                          {item.url}
                        </a>
                      )}
                    </div>
                    <span 
                      className="badge badge-info" 
                      style={{ marginLeft: 'auto', alignSelf: 'center' }}
                    >
                      {item.category}
                    </span>
                  </div>

                  <div className="card-body">
                    <div className="card-field">
                      <span className="field-label">Username</span>
                      <span className="field-value">{item.username}</span>
                      <div className="field-actions">
                        <button 
                          className="btn-icon" 
                          onClick={() => copyToClipboard(item.username, "username", "Username")}
                          aria-label="Copy Username"
                        >
                          <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"></path></svg>
                        </button>
                      </div>
                    </div>

                    <div className="card-field">
                      <span className="field-label">Password</span>
                      <span className="field-value">
                        {visiblePasswords[item.id] ? item.password : "••••••••••••"}
                      </span>
                      <div className="field-actions">
                        <button 
                          className="btn-icon" 
                          onClick={() => togglePasswordVisibility(item.id)}
                          aria-label="Toggle password visibility"
                        >
                          {visiblePasswords[item.id] ? (
                            <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0112 19c-7 0-11-7-11-7a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 7 11 7a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
                          ) : (
                            <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                          )}
                        </button>
                        <button 
                          className="btn-icon" 
                          onClick={() => copyToClipboard(item.password, "password", "Password")}
                          aria-label="Copy Password"
                        >
                          <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"></path></svg>
                        </button>
                      </div>
                    </div>
                    
                    {item.notes && (
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', padding: '0.25rem 0.5rem', background: 'rgba(255,255,255,0.02)', borderRadius: '6px' }}>
                        <strong>Notes:</strong> {item.notes}
                      </div>
                    )}
                  </div>
                </div>

                <div className="card-actions">
                  <button onClick={() => handleOpenEdit(item)} className="btn btn-secondary" style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem' }}>
                    Edit
                  </button>
                  <button onClick={() => handleDeleteCredential(item.id)} className="btn btn-danger" style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem' }}>
                    Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </main>

      {/* Add / Edit Credential Modal */}
      {showAddEditModal && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="modal-header">
              <h2 className="modal-title">{editingItem ? "Edit Credential" : "Add Credential"}</h2>
              <button onClick={() => setShowAddEditModal(false)} className="btn-icon">
                <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              </button>
            </div>
            
            <form onSubmit={handleSaveCredential}>
              <div className="modal-body">
                <div className="form-group">
                  <label className="form-label" htmlFor="site-name">Website Name *</label>
                  <input 
                    id="site-name"
                    type="text" 
                    className="form-input" 
                    placeholder="e.g. Google"
                    value={siteName}
                    onChange={(e) => setSiteName(e.target.value)}
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label" htmlFor="site-url">Website URL (will auto-format)</label>
                  <input 
                    id="site-url"
                    type="text" 
                    className="form-input" 
                    placeholder="e.g. https://google.com"
                    value={siteUrl}
                    onChange={(e) => setSiteUrl(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label" htmlFor="username">Username / Email *</label>
                  <input 
                    id="username"
                    type="text" 
                    className="form-input" 
                    placeholder="e.g. user@example.com"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                  />
                </div>

                <div className="form-group">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <label className="form-label" htmlFor="credential-password">Password *</label>
                    <button 
                      type="button" 
                      onClick={() => setPassword(generateSecurePassword(16))} 
                      className="nav-link" 
                      style={{ background: 'none', border: 'none', fontSize: '0.8rem', textDecoration: 'underline' }}
                    >
                      Generate Secure
                    </button>
                  </div>
                  <div className="input-wrapper">
                    <input 
                      id="credential-password"
                      type={showPassword ? "text" : "password"} 
                      className="form-input form-input-icon-right" 
                      placeholder="Enter site password..."
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                    />
                    <button
                      type="button"
                      className="input-icon-btn"
                      onClick={() => setShowPassword(!showPassword)}
                    >
                      {showPassword ? (
                        <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0112 19c-7 0-11-7-11-7a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 7 11 7a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
                      ) : (
                        <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                      )}
                    </button>
                  </div>
                </div>

                <div className="form-group">
                  <label className="form-label" htmlFor="credential-category">Category / Folder</label>
                  <select 
                    id="credential-category"
                    className="select-input"
                    value={category}
                    onChange={(e) => setCategory(e.target.value)}
                  >
                    <option value="Logins">Logins</option>
                    <option value="Secure Notes">Secure Notes</option>
                    <option value="Cards">Cards / Identity</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label" htmlFor="credential-notes">Notes</label>
                  <textarea 
                    id="credential-notes"
                    className="form-input" 
                    placeholder="Optional notes..."
                    rows="3"
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    style={{ resize: 'vertical' }}
                  ></textarea>
                </div>
              </div>
              
              <div className="modal-footer">
                <button type="button" onClick={() => setShowAddEditModal(false)} className="btn btn-secondary">
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  {editingItem ? "Save Changes" : "Add Credential"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Dedicated Password Generator Modal */}
      {showGenModal && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="modal-header">
              <h2 className="modal-title">Password Generator</h2>
              <button onClick={() => setShowGenModal(false)} className="btn-icon">
                <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              </button>
            </div>

            <div className="modal-body">
              <div className="form-group">
                <label className="form-label">Generated Password</label>
                <div className="input-wrapper">
                  <input 
                    type="text" 
                    className="form-input form-input-icon-right" 
                    value={generatedPass}
                    readOnly
                    style={{ fontFamily: 'monospace', fontWeight: 'bold', fontSize: '1.1rem', background: 'var(--bg-primary)' }}
                  />
                  <button 
                    type="button"
                    className="input-icon-btn"
                    onClick={() => copyToClipboard(generatedPass, "password", "Generated password")}
                  >
                    <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"></path></svg>
                  </button>
                </div>
              </div>

              {generatedPass && (
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
                  <span>Entropy: <strong>{currentEntropy.bits} bits</strong></span>
                  <span>Strength: <strong style={{ color: currentEntropy.color }}>{currentEntropy.strength}</strong></span>
                </div>
              )}

              <div className="generator-slider-group">
                <div className="slider-header">
                  <span>Length</span>
                  <span className="slider-value">{genLength} characters</span>
                </div>
                <input 
                  type="range" 
                  min="8" 
                  max="64"
                  className="generator-slider"
                  value={genLength}
                  onChange={(e) => { setGenLength(parseInt(e.target.value)); handleGenerate(); }}
                />
              </div>

              <div className="generator-options">
                <label className="checkbox-label">
                  <input 
                    type="checkbox" 
                    className="checkbox-input"
                    checked={genOptions.uppercase}
                    onChange={(e) => { setGenOptions({ ...genOptions, uppercase: e.target.checked }); handleGenerate(); }}
                  />
                  Uppercase (A-Z)
                </label>
                <label className="checkbox-label">
                  <input 
                    type="checkbox" 
                    className="checkbox-input"
                    checked={genOptions.lowercase}
                    onChange={(e) => { setGenOptions({ ...genOptions, lowercase: e.target.checked }); handleGenerate(); }}
                  />
                  Lowercase (a-z)
                </label>
                <label className="checkbox-label">
                  <input 
                    type="checkbox" 
                    className="checkbox-input"
                    checked={genOptions.numbers}
                    onChange={(e) => { setGenOptions({ ...genOptions, numbers: e.target.checked }); handleGenerate(); }}
                  />
                  Numbers (0-9)
                </label>
                <label className="checkbox-label">
                  <input 
                    type="checkbox" 
                    className="checkbox-input"
                    checked={genOptions.symbols}
                    onChange={(e) => { setGenOptions({ ...genOptions, symbols: e.target.checked }); handleGenerate(); }}
                  />
                  Symbols (!@#$)
                </label>
              </div>

              <button onClick={handleGenerate} className="btn btn-secondary" style={{ width: '100%' }}>
                Regenerate
              </button>
            </div>
            
            <div className="modal-footer">
              <button onClick={() => setShowGenModal(false)} className="btn btn-primary" style={{ width: '100%' }}>
                Done
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
