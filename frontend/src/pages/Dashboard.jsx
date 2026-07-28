import React, { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { api } from "../utils/api";
import { generateSecurePassword } from "../utils/crypto";

export default function Dashboard() {
  const { decryptedVault, syncVault, token } = useAuth();
  
  // Navigation & Filtering States
  const [activeTab, setActiveTab] = useState("all"); // all, logins, certificates, documents, notes
  const [searchQuery, setSearchQuery] = useState("");
  
  // AI Scanner Widget States
  const [scanUrlInput, setScanUrlInput] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);

  // Modal States
  const [showAddEditModal, setShowAddEditModal] = useState(false);
  const [editingItem, setEditingItem] = useState(null);
  const [showGenModal, setShowGenModal] = useState(false);
  const [showHealthModal, setShowHealthModal] = useState(false);
  
  // Form States
  const [title, setTitle] = useState("");
  const [category, setCategory] = useState("Logins");
  const [siteUrl, setSiteUrl] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [notes, setNotes] = useState("");

  // Additional Fields for Certificates & Identity Docs
  const [issuer, setIssuer] = useState("");
  const [docNumber, setDocNumber] = useState("");
  const [issueDate, setIssueDate] = useState("");
  const [expiryDate, setExpiryDate] = useState("");
  const [verifyUrl, setVerifyUrl] = useState("");

  // Generator States
  const [genLength, setGenLength] = useState(16);
  const [genOptions, setGenOptions] = useState({
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true
  });
  const [generatedPass, setGeneratedPass] = useState("");

  // Visible Passwords Mapping
  const [visiblePasswords, setVisiblePasswords] = useState({});
  const [showPassword, setShowPassword] = useState(false);

  // Notification / Toast States
  const [toastMessage, setToastMessage] = useState("");

  // Helpers
  const showToast = (msg) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(""), 3000);
  };

  const copyToClipboard = async (text, type, label) => {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      showToast(`${label} copied to clipboard!`);
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

  // Run AI Scanner on URL
  const handleRunAiScan = async (e) => {
    if (e) e.preventDefault();
    if (!scanUrlInput.trim()) {
      showToast("Please enter a URL to scan.");
      return;
    }
    setScanning(true);
    setScanResult(null);
    try {
      const res = await api.scanUrl(scanUrlInput.trim());
      setScanResult(res);
      if (token) {
        await api.createLog(token, `ai_url_scanned_${res.is_safe ? "safe" : "phishing"}`);
      }
    } catch (err) {
      showToast("Failed to run AI scan.");
    } finally {
      setScanning(false);
    }
  };

  const handleOpenAdd = (selectedCat = "Logins") => {
    setEditingItem(null);
    setTitle("");
    setSiteUrl("");
    setUsername("");
    setPassword("");
    setNotes("");
    setIssuer("");
    setDocNumber("");
    setIssueDate("");
    setExpiryDate("");
    setVerifyUrl("");
    setCategory(selectedCat);
    setShowAddEditModal(true);
  };

  const handleOpenEdit = (item) => {
    setEditingItem(item);
    setTitle(item.name || item.title || "");
    setSiteUrl(item.url || "");
    setUsername(item.username || "");
    setPassword(item.password || "");
    setNotes(item.notes || "");
    setCategory(item.category || "Logins");
    setIssuer(item.issuer || "");
    setDocNumber(item.doc_number || "");
    setIssueDate(item.issue_date || "");
    setExpiryDate(item.expiry_date || "");
    setVerifyUrl(item.verify_url || "");
    setShowAddEditModal(true);
  };

  const handleSaveCredential = async (e) => {
    e.preventDefault();
    if (!title) {
      showToast("Title / Name is required.");
      return;
    }

    const cleanUrl = siteUrl ? formatToDomain(siteUrl) : "";
    const cleanVerifyUrl = verifyUrl ? (verifyUrl.startsWith("http") ? verifyUrl : `https://${verifyUrl}`) : "";
    const updatedVault = [...(decryptedVault || [])];

    const newItemPayload = {
      id: editingItem ? editingItem.id : crypto.randomUUID(),
      name: title,
      title: title,
      category: category,
      url: cleanUrl,
      username: username,
      password: password,
      notes: notes,
      issuer: issuer,
      doc_number: docNumber,
      issue_date: issueDate,
      expiry_date: expiryDate,
      verify_url: cleanVerifyUrl,
      updated_at: new Date().toISOString(),
      created_at: editingItem ? editingItem.created_at : new Date().toISOString()
    };

    if (editingItem) {
      const idx = updatedVault.findIndex(x => x.id === editingItem.id);
      if (idx !== -1) {
        updatedVault[idx] = newItemPayload;
      }
      showToast("Vault record updated.");
    } else {
      updatedVault.push(newItemPayload);
      showToast("Record added to Zero-Knowledge Vault.");
    }

    try {
      await syncVault(updatedVault);
      setShowAddEditModal(false);
    } catch (err) {
      showToast(err.message || "Failed to sync vault.");
    }
  };

  const handleDeleteCredential = async (id) => {
    if (!window.confirm("Are you sure you want to delete this record from your vault?")) return;
    
    const updatedVault = (decryptedVault || []).filter(x => x.id !== id);
    try {
      await syncVault(updatedVault);
      showToast("Record deleted.");
    } catch (err) {
      showToast("Failed to delete record.");
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
    if (/[^a-zA-Z0-9]/.test(pw)) poolSize += 26;

    const bits = Math.floor(pw.length * Math.log2(poolSize));
    if (bits < 40) return { bits, strength: "Weak", color: "#EF4444" };
    if (bits < 80) return { bits, strength: "Moderate", color: "#F59E0B" };
    return { bits, strength: "Strong", color: "#10B981" };
  };

  const currentEntropy = calculateEntropy(generatedPass);

  // Expiration Status Helper
  const getExpiryStatus = (expDateStr) => {
    if (!expDateStr) return null;
    const exp = new Date(expDateStr);
    const now = new Date();
    const diffDays = Math.ceil((exp - now) / (1000 * 60 * 60 * 24));
    
    if (diffDays < 0) return { label: "Expired", color: "#EF4444", bg: "rgba(239,68,68,0.15)" };
    if (diffDays <= 30) return { label: `Expires in ${diffDays}d`, color: "#F59E0B", bg: "rgba(245,158,11,0.15)" };
    return { label: `Valid until ${expDateStr}`, color: "#10B981", bg: "rgba(16,185,129,0.15)" };
  };

  // Real Vault Health Audit Calculation
  const calculateVaultHealth = (items) => {
    if (!items || items.length === 0) {
      return {
        score: 100,
        label: "100% Excellent",
        statusText: "Excellent",
        color: "#10B981",
        totalItems: 0,
        weakCount: 0,
        moderateCount: 0,
        strongCount: 0,
        reusedCount: 0,
        expiredCount: 0,
        expiringCount: 0,
        noUrlCount: 0,
        issues: []
      };
    }

    // 1. Password reuse mapping
    const passwordCounts = {};
    items.forEach(item => {
      if (item.password) {
        passwordCounts[item.password] = (passwordCounts[item.password] || 0) + 1;
      }
    });

    let totalItemScores = 0;
    let weakCount = 0;
    let moderateCount = 0;
    let strongCount = 0;
    let reusedCount = 0;
    let expiredCount = 0;
    let expiringCount = 0;
    let noUrlCount = 0;
    const issues = [];

    items.forEach(item => {
      let itemScore = 100;
      const itemName = item.title || item.name || "Vault Item";

      // A. Password Analysis (for Logins or items containing passwords)
      if (item.category === "Logins" || item.password) {
        const pw = item.password || "";
        const entropy = calculateEntropy(pw);

        if (!pw) {
          itemScore -= 50;
          weakCount++;
          issues.push({ type: "danger", title: itemName, text: "No password specified." });
        } else if (entropy.strength === "Weak") {
          itemScore -= 40;
          weakCount++;
          issues.push({ type: "danger", title: itemName, text: `Weak password strength (${entropy.bits} bits).` });
        } else if (entropy.strength === "Moderate") {
          itemScore -= 15;
          moderateCount++;
          issues.push({ type: "warning", title: itemName, text: `Moderate password strength (${entropy.bits} bits).` });
        } else {
          strongCount++;
        }

        // Check password reuse
        if (pw && passwordCounts[pw] > 1) {
          itemScore -= 25;
          reusedCount++;
          issues.push({ type: "warning", title: itemName, text: "Password is reused across multiple vault items." });
        }

        // Check site URL presence
        if (!item.url && item.category === "Logins") {
          itemScore -= 10;
          noUrlCount++;
          issues.push({ type: "info", title: itemName, text: "Missing website URL (limits AI phishing detection)." });
        }
      }

      // B. Expiration Audit for Certificates / Documents
      if (item.expiry_date) {
        const exp = new Date(item.expiry_date);
        const now = new Date();
        const diffDays = Math.ceil((exp - now) / (1000 * 60 * 60 * 24));

        if (diffDays < 0) {
          itemScore -= 50;
          expiredCount++;
          issues.push({ type: "danger", title: itemName, text: `Credential expired on ${item.expiry_date}.` });
        } else if (diffDays <= 30) {
          itemScore -= 25;
          expiringCount++;
          issues.push({ type: "warning", title: itemName, text: `Credential expires soon (${diffDays} days left).` });
        }
      }

      totalItemScores += Math.max(0, Math.min(100, itemScore));
    });

    const finalScore = Math.max(0, Math.min(100, Math.round(totalItemScores / items.length)));

    let statusText = "Excellent";
    let color = "#10B981";

    if (finalScore < 50) {
      statusText = "At Risk";
      color = "#EF4444";
    } else if (finalScore < 75) {
      statusText = "Fair";
      color = "#F59E0B";
    } else if (finalScore < 90) {
      statusText = "Good";
      color = "#06B6D4";
    }

    return {
      score: finalScore,
      label: `${finalScore}% ${statusText}`,
      statusText,
      color,
      totalItems: items.length,
      weakCount,
      moderateCount,
      strongCount,
      reusedCount,
      expiredCount,
      expiringCount,
      noUrlCount,
      issues
    };
  };

  // Stats Calculations
  const vaultHealth = calculateVaultHealth(decryptedVault);
  const totalItems = (decryptedVault || []).length;
  const certsCount = (decryptedVault || []).filter(x => x.category === "Certificates").length;
  const docsCount = (decryptedVault || []).filter(x => x.category === "Documents" || x.category === "Cards").length;
  const loginsCount = (decryptedVault || []).filter(x => x.category === "Logins").length;

  // Filters
  const filteredItems = (decryptedVault || []).filter(item => {
    const q = searchQuery.toLowerCase();
    const matchesSearch = 
      (item.name || item.title || "").toLowerCase().includes(q) ||
      (item.username || "").toLowerCase().includes(q) ||
      (item.issuer || "").toLowerCase().includes(q) ||
      (item.doc_number || "").toLowerCase().includes(q) ||
      (item.notes || "").toLowerCase().includes(q);
    
    if (activeTab === "all") return matchesSearch;
    if (activeTab === "logins") return matchesSearch && item.category === "Logins";
    if (activeTab === "certificates") return matchesSearch && item.category === "Certificates";
    if (activeTab === "documents") return matchesSearch && (item.category === "Documents" || item.category === "Cards");
    if (activeTab === "notes") return matchesSearch && item.category === "Secure Notes";
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
          All Vault Items ({totalItems})
        </button>
        <button 
          className={`sidebar-item ${activeTab === "logins" ? "active" : ""}`}
          onClick={() => setActiveTab("logins")}
        >
          <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
          Logins ({loginsCount})
        </button>
        <button 
          className={`sidebar-item ${activeTab === "certificates" ? "active" : ""}`}
          onClick={() => setActiveTab("certificates")}
        >
          <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><path d="M22 10v6M2 10l10-5 10 5-10 5z"></path><path d="M6 12v5c3 3 9 3 12 0v-5"></path></svg>
          Student Certificates 🎓 ({certsCount})
        </button>
        <button 
          className={`sidebar-item ${activeTab === "documents" ? "active" : ""}`}
          onClick={() => setActiveTab("documents")}
        >
          <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><rect x="1" y="4" width="22" height="16" rx="2" ry="2"></rect><line x1="1" y1="10" x2="23" y2="10"></line></svg>
          ID & Documents 📄 ({docsCount})
        </button>
        <button 
          className={`sidebar-item ${activeTab === "notes" ? "active" : ""}`}
          onClick={() => setActiveTab("notes")}
        >
          <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>
          Secure Notes 📝
        </button>
        <button 
          className="sidebar-item"
          onClick={() => { setShowGenModal(true); handleGenerate(); }}
        >
          <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"></path></svg>
          Password Generator
        </button>
      </aside>

      {/* Main Content Area */}
      <main className="main-content">
        

        {/* AI Real-Time Extension Phishing Protection Status */}
        <div className="ai-scanner-box" style={{ background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.9))', border: '1px solid rgba(139, 92, 246, 0.3)', padding: '1.25rem 1.5rem' }}>
          <div className="ai-scanner-header" style={{ marginBottom: '0.4rem' }}>
            <span className="ai-scanner-title" style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', fontSize: '1.1rem' }}>
              🤖 AI Phishing Protection Shield
              <span style={{ fontSize: '0.72rem', fontWeight: 'bold', color: '#10B981', background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.3)', padding: '0.2rem 0.6rem', borderRadius: '20px' }}>
                ⚡ Browser Extension Active
              </span>
            </span>
          </div>
          <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            Automated real-time protection powered by <strong>TF-IDF + Linear SVM Model</strong>. The SecurePass Browser Extension continuously monitors website URLs in your browser tabs and instantly displays a side security warning if a phishing site is detected.
          </p>
        </div>

        {/* Actions Bar */}
        <div className="actions-bar">
          <div className="search-wrapper">
            <svg className="search-icon" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
            <input 
              type="text" 
              className="search-input" 
              placeholder="Search website, certificates, ID #..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
          <button onClick={() => handleOpenAdd("Logins")} className="btn btn-primary">
            <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
            Add to Vault
          </button>
        </div>

        {filteredItems.length === 0 ? (
          <div className="card empty-state">
            <div className="site-icon" style={{ width: '60px', height: '60px', borderRadius: '50%', fontSize: '1.8rem' }}>🔒</div>
            <h2 className="empty-state-title">No vault items found</h2>
            <p className="empty-state-desc">
              {searchQuery ? "No items matched your search query." : "Your zero-knowledge vault is empty. Store logins, student certificates, or important documents safely."}
            </p>
            {!searchQuery && (
              <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button onClick={() => handleOpenAdd("Logins")} className="btn btn-primary">
                  + Add Login
                </button>
                <button onClick={() => handleOpenAdd("Certificates")} className="btn btn-secondary">
                  + Add Certificate
                </button>
              </div>
            )}
          </div>
        ) : (
          <div className="credentials-grid">
            {filteredItems.map(item => {
              const expStatus = getExpiryStatus(item.expiry_date);

              return (
                <div key={item.id} className="card credential-card">
                  <div>
                    {/* Header */}
                    <div className="card-header">
                      <div className="site-icon">
                        {item.category === "Certificates" ? "🎓" : item.category === "Documents" || item.category === "Cards" ? "📄" : item.category === "Secure Notes" ? "📝" : "🔑"}
                      </div>
                      <div className="card-title-group">
                        <span className="card-site-name">{item.name || item.title}</span>
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
                        className={`badge ${item.category === "Certificates" ? "badge-success" : item.category === "Secure Notes" ? "badge-warning" : "badge-info"}`}
                        style={{ marginLeft: 'auto', alignSelf: 'center' }}
                      >
                        {item.category}
                      </span>
                    </div>

                    {/* Expiry Alert Badge */}
                    {expStatus && (
                      <div style={{ background: expStatus.bg, color: expStatus.color, padding: '0.25rem 0.6rem', borderRadius: '6px', fontSize: '0.75rem', fontWeight: '600', marginBottom: '0.75rem', display: 'inline-block' }}>
                        {expStatus.label}
                      </div>
                    )}

                    {/* Body Content by Category */}
                    <div className="card-body">

                      {/* Certificate Fields */}
                      {item.category === "Certificates" && (
                        <>
                          {item.issuer && (
                            <div className="card-field">
                              <span className="field-label">Issuing Authority</span>
                              <span className="field-value">{item.issuer}</span>
                            </div>
                          )}
                          {item.doc_number && (
                            <div className="card-field">
                              <span className="field-label">Certificate #</span>
                              <span className="field-value">{item.doc_number}</span>
                              <div className="field-actions">
                                <button 
                                  className="btn-icon" 
                                  onClick={() => copyToClipboard(item.doc_number, "cert_num", "Certificate Number")}
                                >
                                  <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"></path></svg>
                                </button>
                              </div>
                            </div>
                          )}
                          {item.verify_url && (
                            <a 
                              href={item.verify_url} 
                              target="_blank" 
                              rel="noopener noreferrer" 
                              className="btn btn-secondary" 
                              style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.75rem', padding: '0.3rem 0.6rem', marginTop: '0.5rem' }}
                            >
                              🔗 Verify Online
                            </a>
                          )}
                        </>
                      )}

                      {/* Identity / Document Fields */}
                      {(item.category === "Documents" || item.category === "Cards") && (
                        <>
                          {item.issuer && (
                            <div className="card-field">
                              <span className="field-label">Institution / Authority</span>
                              <span className="field-value">{item.issuer}</span>
                            </div>
                          )}
                          {item.doc_number && (
                            <div className="card-field">
                              <span className="field-label">Document / ID #</span>
                              <span className="field-value">{item.doc_number}</span>
                              <div className="field-actions">
                                <button 
                                  className="btn-icon" 
                                  onClick={() => copyToClipboard(item.doc_number, "doc_num", "Document Number")}
                                >
                                  <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"></path></svg>
                                </button>
                              </div>
                            </div>
                          )}
                        </>
                      )}

                      {/* Logins Fields */}
                      {item.category === "Logins" && (
                        <>
                          {item.username && (
                            <div className="card-field">
                              <span className="field-label">Username / Email</span>
                              <span className="field-value">{item.username}</span>
                              <div className="field-actions">
                                <button 
                                  className="btn-icon" 
                                  onClick={() => copyToClipboard(item.username, "username", "Username")}
                                >
                                  <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"></path></svg>
                                </button>
                              </div>
                            </div>
                          )}

                          {item.password && (
                            <div className="card-field">
                              <span className="field-label">Password</span>
                              <span className="field-value">
                                {visiblePasswords[item.id] ? item.password : "••••••••••••"}
                              </span>
                              <div className="field-actions">
                                <button 
                                  className="btn-icon" 
                                  onClick={() => togglePasswordVisibility(item.id)}
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
                                >
                                  <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"></path></svg>
                                </button>
                              </div>
                            </div>
                          )}
                        </>
                      )}
                      
                      {/* Encrypted Notes */}
                      {item.notes && (
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', padding: '0.4rem 0.6rem', background: 'rgba(255,255,255,0.02)', borderRadius: '6px', marginTop: '0.5rem', whiteSpace: 'pre-wrap' }}>
                          <strong>Notes:</strong> {item.notes}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="card-actions">
                    <button onClick={() => handleOpenEdit(item)} className="btn btn-secondary" style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem' }}>
                      Edit
                    </button>
                    <button onClick={() => handleDeleteCredential(item.id)} className="btn btn-danger" style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem' }}>
                      Delete
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </main>

      {/* Add / Edit Modal */}
      {showAddEditModal && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="modal-header">
              <h2 className="modal-title">
                {editingItem ? "Edit Record" : "Add to Zero-Knowledge Vault"}
              </h2>
              <button onClick={() => setShowAddEditModal(false)} className="btn-icon">
                <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              </button>
            </div>
            
            <form onSubmit={handleSaveCredential}>
              <div className="modal-body">
                
                <div className="form-group">
                  <label className="form-label" htmlFor="item-category">Record Category *</label>
                  <select 
                    id="item-category"
                    className="select-input"
                    value={category}
                    onChange={(e) => setCategory(e.target.value)}
                  >
                    <option value="Logins">Logins & Passwords</option>
                    <option value="Certificates">Student / Professional Certificate 🎓</option>
                    <option value="Documents">Identity / Important Document 📄</option>
                    <option value="Secure Notes">Secure Note 📝</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label" htmlFor="site-name">
                    {category === "Certificates" ? "Certificate Name *" : category === "Documents" ? "Document Title *" : category === "Secure Notes" ? "Note Title *" : "Website / App Name *"}
                  </label>
                  <input 
                    id="site-name"
                    type="text" 
                    className="form-input" 
                    placeholder={category === "Certificates" ? "e.g. Bachelor of Computer Science" : category === "Documents" ? "e.g. University Student ID" : "e.g. Student Portal / Google"}
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    required
                  />
                </div>

                {/* Logins Specific Fields */}
                {category === "Logins" && (
                  <>
                    <div className="form-group">
                      <label className="form-label" htmlFor="site-url">Website URL</label>
                      <input 
                        id="site-url"
                        type="text" 
                        className="form-input" 
                        placeholder="e.g. https://portal.university.edu"
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
                        placeholder="e.g. student@university.edu"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                      />
                    </div>

                    <div className="form-group">
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <label className="form-label" htmlFor="credential-password">Password</label>
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
                          placeholder="Enter password..."
                          value={password}
                          onChange={(e) => setPassword(e.target.value)}
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
                  </>
                )}

                {/* Certificates / Documents Specific Fields */}
                {(category === "Certificates" || category === "Documents" || category === "Cards") && (
                  <>
                    <div className="form-group">
                      <label className="form-label" htmlFor="issuer">
                        {category === "Certificates" ? "Issuing University / Organization" : "Issuing Authority / Institution"}
                      </label>
                      <input 
                        id="issuer"
                        type="text" 
                        className="form-input" 
                        placeholder={category === "Certificates" ? "e.g. Stanford University / Coursera" : "e.g. Ministry of Education"}
                        value={issuer}
                        onChange={(e) => setIssuer(e.target.value)}
                      />
                    </div>

                    <div className="form-group">
                      <label className="form-label" htmlFor="docNumber">
                        {category === "Certificates" ? "Certificate Serial / Registration #" : "Document / Student ID #"}
                      </label>
                      <input 
                        id="docNumber"
                        type="text" 
                        className="form-input" 
                        placeholder="e.g. CERT-2026-99238"
                        value={docNumber}
                        onChange={(e) => setDocNumber(e.target.value)}
                      />
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                      <div className="form-group">
                        <label className="form-label" htmlFor="issueDate">Issue Date</label>
                        <input 
                          id="issueDate"
                          type="date" 
                          className="form-input" 
                          value={issueDate}
                          onChange={(e) => setIssueDate(e.target.value)}
                        />
                      </div>
                      <div className="form-group">
                        <label className="form-label" htmlFor="expiryDate">Expiry Date</label>
                        <input 
                          id="expiryDate"
                          type="date" 
                          className="form-input" 
                          value={expiryDate}
                          onChange={(e) => setExpiryDate(e.target.value)}
                        />
                      </div>
                    </div>

                    {category === "Certificates" && (
                      <div className="form-group">
                        <label className="form-label" htmlFor="verifyUrl">Verification Link</label>
                        <input 
                          id="verifyUrl"
                          type="text" 
                          className="form-input" 
                          placeholder="e.g. https://university.edu/verify/99238"
                          value={verifyUrl}
                          onChange={(e) => setVerifyUrl(e.target.value)}
                        />
                      </div>
                    )}
                  </>
                )}

                {/* Notes (All categories) */}
                <div className="form-group">
                  <label className="form-label" htmlFor="credential-notes">Encrypted Notes & Extra Details</label>
                  <textarea 
                    id="credential-notes"
                    className="form-input" 
                    placeholder="Encrypted notes, verification keys, confidential details..."
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
                  {editingItem ? "Save Changes" : "Encrypted Save to Vault"}
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

      {/* Vault Security Health Audit Modal */}
      {showHealthModal && (
        <div className="modal-overlay" onClick={() => setShowHealthModal(false)}>
          <div className="modal-content health-audit-modal" onClick={e => e.stopPropagation()} style={{ maxWidth: '640px' }}>
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <div style={{ background: `${vaultHealth.color}20`, color: vaultHealth.color, padding: '0.5rem', borderRadius: '8px', fontSize: '1.4rem' }}>
                  🛡️
                </div>
                <div>
                  <h2 className="modal-title" style={{ margin: 0, fontSize: '1.25rem' }}>Vault Security Health Audit</h2>
                  <p style={{ margin: 0, fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    Real-time analysis based on password entropy, reuse, site coverage & document expiration
                  </p>
                </div>
              </div>
              <button onClick={() => setShowHealthModal(false)} className="btn-icon">
                <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              </button>
            </div>

            <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              {/* Overall Health Score Card */}
              <div style={{ 
                background: 'rgba(255,255,255,0.02)', 
                border: `1px solid ${vaultHealth.color}40`, 
                borderRadius: '12px', 
                padding: '1.25rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '1rem'
              }}>
                <div>
                  <span style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)', fontWeight: 600 }}>
                    Overall Health Score
                  </span>
                  <div style={{ fontSize: '2rem', fontWeight: 800, color: vaultHealth.color, display: 'flex', alignItems: 'baseline', gap: '0.5rem' }}>
                    {vaultHealth.score}% 
                    <span style={{ fontSize: '0.85rem', fontWeight: 600, padding: '0.2rem 0.6rem', borderRadius: '20px', background: `${vaultHealth.color}20`, color: vaultHealth.color }}>
                      {vaultHealth.statusText}
                    </span>
                  </div>
                </div>
                
                <div style={{ flex: 1, maxWidth: '200px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', marginBottom: '0.35rem', color: 'var(--text-secondary)' }}>
                    <span>Security Rating</span>
                    <span>{vaultHealth.score} / 100</span>
                  </div>
                  <div style={{ width: '100%', height: '8px', background: 'rgba(255,255,255,0.1)', borderRadius: '4px', overflow: 'hidden' }}>
                    <div style={{ width: `${vaultHealth.score}%`, height: '100%', background: vaultHealth.color, transition: 'width 0.4s ease' }} />
                  </div>
                </div>
              </div>

              {/* Health Metrics Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '0.75rem' }}>
                <div style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '0.85rem', textAlign: 'center' }}>
                  <div style={{ fontSize: '1.2rem', marginBottom: '0.2rem' }}>🔑</div>
                  <div style={{ fontSize: '1.2rem', fontWeight: 'bold', color: vaultHealth.strongCount > 0 ? '#10B981' : 'var(--text-primary)' }}>{vaultHealth.strongCount}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Strong Passwords</div>
                </div>
                <div style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '0.85rem', textAlign: 'center' }}>
                  <div style={{ fontSize: '1.2rem', marginBottom: '0.2rem' }}>⚠️</div>
                  <div style={{ fontSize: '1.2rem', fontWeight: 'bold', color: vaultHealth.reusedCount > 0 ? '#F59E0B' : '#10B981' }}>{vaultHealth.reusedCount}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Reused Passwords</div>
                </div>
                <div style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '0.85rem', textAlign: 'center' }}>
                  <div style={{ fontSize: '1.2rem', marginBottom: '0.2rem' }}>❌</div>
                  <div style={{ fontSize: '1.2rem', fontWeight: 'bold', color: vaultHealth.weakCount > 0 ? '#EF4444' : '#10B981' }}>{vaultHealth.weakCount}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Weak Passwords</div>
                </div>
                <div style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '0.85rem', textAlign: 'center' }}>
                  <div style={{ fontSize: '1.2rem', marginBottom: '0.2rem' }}>📅</div>
                  <div style={{ fontSize: '1.2rem', fontWeight: 'bold', color: (vaultHealth.expiredCount + vaultHealth.expiringCount) > 0 ? '#F59E0B' : '#10B981' }}>
                    {vaultHealth.expiredCount + vaultHealth.expiringCount}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Expiring / Expired</div>
                </div>
              </div>

              {/* Security Audit Findings */}
              <div>
                <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  🔍 Security Audit Findings ({vaultHealth.issues.length})
                </h3>
                {vaultHealth.issues.length === 0 ? (
                  <div style={{ 
                    padding: '1rem', 
                    borderRadius: '8px', 
                    background: 'rgba(16, 185, 129, 0.1)', 
                    border: '1px solid rgba(16, 185, 129, 0.3)',
                    color: '#10B981',
                    fontSize: '0.85rem',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem'
                  }}>
                    <span>✅</span>
                    <span>No security issues or vulnerabilities detected. Your vault is in peak health!</span>
                  </div>
                ) : (
                  <div style={{ maxHeight: '200px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.5rem', paddingRight: '0.25rem' }}>
                    {vaultHealth.issues.map((issue, idx) => (
                      <div key={idx} style={{ 
                        display: 'flex', 
                        alignItems: 'flex-start', 
                        gap: '0.6rem', 
                        padding: '0.65rem 0.85rem', 
                        borderRadius: '6px', 
                        background: 'rgba(255,255,255,0.03)',
                        borderLeft: `3px solid ${issue.type === 'danger' ? '#EF4444' : issue.type === 'warning' ? '#F59E0B' : '#06B6D4'}`,
                        fontSize: '0.82rem'
                      }}>
                        <span style={{ fontSize: '1rem' }}>{issue.type === 'danger' ? '🔴' : issue.type === 'warning' ? '⚠️' : 'ℹ️'}</span>
                        <div style={{ flex: 1 }}>
                          <strong style={{ color: 'var(--text-primary)' }}>{issue.title}</strong>: <span style={{ color: 'var(--text-secondary)' }}>{issue.text}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            <div className="modal-footer">
              <button onClick={() => setShowHealthModal(false)} className="btn btn-primary" style={{ width: '100%' }}>
                Close Security Audit
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
