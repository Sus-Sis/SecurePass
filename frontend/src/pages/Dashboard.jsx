import React, { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { api } from "../utils/api";
import { generateSecurePassword } from "../utils/crypto";

export default function Dashboard() {
  const { decryptedVault, syncVault, token } = useAuth();
  
  // Navigation & Workspace States
  const [activeTab, setActiveTab] = useState("all"); // all, websites, photos, documents, notes, favorites
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedItem, setSelectedItem] = useState(null);
  
  // AI Scanner Widget States
  const [scanUrlInput, setScanUrlInput] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);

  // Modal States
  const [showAddEditModal, setShowAddEditModal] = useState(false);
  const [editingItem, setEditingItem] = useState(null);
  const [showGenModal, setShowGenModal] = useState(false);
  const [previewPhotoItem, setPreviewPhotoItem] = useState(null);
  
  // Form States
  const [title, setTitle] = useState("");
  const [category, setCategory] = useState("Logins"); // Logins, Documents, Photos, Secure Notes, Certificates
  const [siteUrl, setSiteUrl] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [notes, setNotes] = useState("");
  const [tag, setTag] = useState("");
  const [isFavorite, setIsFavorite] = useState(false);

  // File & Photo Attachment States
  const [fileData, setFileData] = useState("");
  const [fileName, setFileName] = useState("");
  const [fileType, setFileType] = useState("");
  const [fileSize, setFileSize] = useState("");

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
  const [showInspectorPassword, setShowInspectorPassword] = useState(false);

  // Notification / Toast States
  const [toastMessage, setToastMessage] = useState("");

  // Auto-select first item on tab change
  useEffect(() => {
    if (filteredItems && filteredItems.length > 0 && !selectedItem) {
      setSelectedItem(filteredItems[0]);
    }
  }, [decryptedVault, activeTab]);

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
      return url.replace("www.", "");
    }
  };

  // Handle File / Photo Selection for Zero-Knowledge Base64 Encryption
  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    if (!selectedFile) return;

    if (selectedFile.size > 10 * 1024 * 1024) {
      showToast("File size exceeds 10MB limit.");
      return;
    }

    const reader = new FileReader();
    reader.onload = (uploadEvent) => {
      const base64 = uploadEvent.target.result;
      setFileData(base64);
      setFileName(selectedFile.name);
      setFileType(selectedFile.type);
      setFileSize((selectedFile.size / 1024).toFixed(1) + " KB");
      if (!title) {
        setTitle(selectedFile.name.split('.')[0]);
      }
    };
    reader.readAsDataURL(selectedFile);
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

  const handleOpenAdd = (selectedCat = "Logins", defaultDomain = "") => {
    setEditingItem(null);
    setTitle(defaultDomain ? formatToDomain(defaultDomain) : "");
    setSiteUrl(defaultDomain);
    setUsername("");
    setPassword("");
    setNotes("");
    setTag("");
    setIsFavorite(false);
    setFileData("");
    setFileName("");
    setFileType("");
    setFileSize("");
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
    setTag(item.tag || "");
    setIsFavorite(Boolean(item.is_favorite));
    setFileData(item.file_data || "");
    setFileName(item.file_name || "");
    setFileType(item.file_type || "");
    setFileSize(item.file_size || "");
    setIssuer(item.issuer || "");
    setDocNumber(item.doc_number || "");
    setIssueDate(item.issue_date || "");
    setExpiryDate(item.expiry_date || "");
    setVerifyUrl(item.verify_url || "");
    setShowAddEditModal(true);
  };

  const handleToggleFavorite = async (item, e) => {
    if (e) e.stopPropagation();
    const updatedVault = (decryptedVault || []).map(x => {
      if (x.id === item.id) {
        return { ...x, is_favorite: !x.is_favorite };
      }
      return x;
    });
    try {
      await syncVault(updatedVault);
      if (selectedItem && selectedItem.id === item.id) {
        setSelectedItem(prev => ({ ...prev, is_favorite: !prev.is_favorite }));
      }
      showToast(item.is_favorite ? "Removed from Favorites" : "Starred to Favorites ⭐");
    } catch (err) {
      showToast("Failed to update favorite status.");
    }
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
      tag: tag.trim(),
      is_favorite: isFavorite,
      file_data: fileData,
      file_name: fileName,
      file_type: fileType,
      file_size: fileSize,
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
      setSelectedItem(newItemPayload);
      setShowAddEditModal(false);
    } catch (err) {
      showToast(err.message || "Failed to sync vault.");
    }
  };

  const handleDeleteCredential = async (id) => {
    if (!window.confirm("Are you sure you want to delete this item from your vault?")) return;
    
    const updatedVault = (decryptedVault || []).filter(x => x.id !== id);
    try {
      await syncVault(updatedVault);
      if (selectedItem && selectedItem.id === id) {
        setSelectedItem(updatedVault.length > 0 ? updatedVault[0] : null);
      }
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

  // Real Vault Health Audit Calculation
  const calculateVaultHealth = (items) => {
    if (!items || items.length === 0) {
      return { score: 100, label: "100% Excellent", color: "#10B981", weakCount: 0, reusedCount: 0 };
    }

    const passwordCounts = {};
    items.forEach(item => {
      if (item.password) {
        passwordCounts[item.password] = (passwordCounts[item.password] || 0) + 1;
      }
    });

    let totalItemScores = 0;
    let weakCount = 0;
    let reusedCount = 0;

    items.forEach(item => {
      let itemScore = 100;
      if (item.category === "Logins" || item.password) {
        const pw = item.password || "";
        const entropy = calculateEntropy(pw);
        if (!pw || entropy.strength === "Weak") {
          itemScore -= 40;
          weakCount++;
        }
        if (pw && passwordCounts[pw] > 1) {
          itemScore -= 25;
          reusedCount++;
        }
      }
      totalItemScores += Math.max(0, Math.min(100, itemScore));
    });

    const finalScore = Math.max(0, Math.min(100, Math.round(totalItemScores / items.length)));
    let color = "#10B981";
    if (finalScore < 50) color = "#EF4444";
    else if (finalScore < 80) color = "#F59E0B";

    return { score: finalScore, label: `${finalScore}% Score`, color, weakCount, reusedCount };
  };

  const vaultHealth = calculateVaultHealth(decryptedVault);
  const totalItems = (decryptedVault || []).length;
  const passwordsCount = (decryptedVault || []).filter(x => x.category === "Logins").length;
  const documentsCount = (decryptedVault || []).filter(x => x.category === "Documents" || x.category === "Certificates").length;
  const photosCount = (decryptedVault || []).filter(x => x.category === "Photos" || (x.file_type && x.file_type.startsWith("image/"))).length;
  const notesCount = (decryptedVault || []).filter(x => x.category === "Secure Notes").length;
  const favoritesCount = (decryptedVault || []).filter(x => x.is_favorite).length;

  const existingWebsitesList = Array.from(new Set(
    (decryptedVault || [])
      .map(x => x.url ? formatToDomain(x.url) : "")
      .filter(Boolean)
  ));

  // Filtered items
  const filteredItems = (decryptedVault || []).filter(item => {
    const q = searchQuery.toLowerCase();
    const matchesSearch = 
      (item.name || item.title || "").toLowerCase().includes(q) ||
      (item.username || "").toLowerCase().includes(q) ||
      (item.url || "").toLowerCase().includes(q) ||
      (item.tag || "").toLowerCase().includes(q) ||
      (item.notes || "").toLowerCase().includes(q);
    
    if (activeTab === "all") return matchesSearch;
    if (activeTab === "websites") return matchesSearch && (item.category === "Logins" || Boolean(item.url));
    if (activeTab === "photos") return matchesSearch && (item.category === "Photos" || (item.file_type && item.file_type.startsWith("image/")));
    if (activeTab === "documents") return matchesSearch && (item.category === "Documents" || item.category === "Certificates");
    if (activeTab === "notes") return matchesSearch && item.category === "Secure Notes";
    if (activeTab === "favorites") return matchesSearch && Boolean(item.is_favorite);
    return false;
  });

  return (
    <div className="vault-workspace">
      
      {/* Column 1: Navigation Sidebar */}
      <aside className="workspace-sidebar">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: '0.75rem', borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
          <span style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Vault Categories
          </span>
          <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#06b6d4', background: 'rgba(6,182,212,0.15)', padding: '0.15rem 0.5rem', borderRadius: '10px' }}>
            {totalItems} Items
          </span>
        </div>

        <button 
          className={`sidebar-item ${activeTab === "all" ? "active" : ""}`}
          onClick={() => setActiveTab("all")}
        >
          <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="9" rx="1"></rect><rect x="14" y="3" width="7" height="5" rx="1"></rect><rect x="14" y="12" width="7" height="9" rx="1"></rect><rect x="3" y="16" width="7" height="5" rx="1"></rect></svg>
          All Items ({totalItems})
        </button>

        <button 
          className={`sidebar-item ${activeTab === "websites" ? "active" : ""}`}
          onClick={() => setActiveTab("websites")}
        >
          <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"></path></svg>
          Passwords 🔑 ({passwordsCount})
        </button>

        <button 
          className={`sidebar-item ${activeTab === "documents" ? "active" : ""}`}
          onClick={() => setActiveTab("documents")}
        >
          <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><rect x="1" y="4" width="22" height="16" rx="2" ry="2"></rect><line x1="1" y1="10" x2="23" y2="10"></line></svg>
          Documents 📄 ({documentsCount})
        </button>

        <button 
          className={`sidebar-item ${activeTab === "photos" ? "active" : ""}`}
          onClick={() => setActiveTab("photos")}
        >
          <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>
          Photos 🖼️ ({photosCount})
        </button>

        <button 
          className={`sidebar-item ${activeTab === "notes" ? "active" : ""}`}
          onClick={() => setActiveTab("notes")}
        >
          <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>
          Secret Notes 📝 ({notesCount})
        </button>

        <button 
          className={`sidebar-item ${activeTab === "favorites" ? "active" : ""}`}
          onClick={() => setActiveTab("favorites")}
        >
          <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>
          Favorites ⭐ ({favoritesCount})
        </button>

        <div style={{ marginTop: 'auto', paddingTop: '1rem', borderTop: '1px solid rgba(255,255,255,0.08)' }}>
          {/* Vault Health Meter Card */}
          <div style={{ background: 'rgba(15, 23, 42, 0.8)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '12px', padding: '0.85rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem', fontSize: '0.75rem' }}>
              <span style={{ fontWeight: 700, color: 'var(--text-secondary)' }}>Security Audit</span>
              <span style={{ fontWeight: 700, color: vaultHealth.color }}>{vaultHealth.label}</span>
            </div>
            <div style={{ height: '6px', width: '100%', background: 'rgba(255,255,255,0.1)', borderRadius: '3px', overflow: 'hidden' }}>
              <div style={{ height: '100%', width: `${vaultHealth.score}%`, background: vaultHealth.color }}></div>
            </div>
            <div style={{ marginTop: '0.5rem', fontSize: '0.7rem', color: '#94a3b8', display: 'flex', justifyContent: 'space-between' }}>
              <span>Weak: {vaultHealth.weakCount}</span>
              <span>Reused: {vaultHealth.reusedCount}</span>
            </div>
          </div>

          <button 
            className="btn btn-secondary" 
            style={{ width: '100%', marginTop: '0.75rem', fontSize: '0.78rem', padding: '0.45rem' }}
            onClick={() => { setShowGenModal(true); handleGenerate(); }}
          >
            ⚡ Password Generator
          </button>
        </div>
      </aside>

      {/* Column 2: Master Item List */}
      <main className="workspace-feed">
        
        {/* Actions Bar */}
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <div className="search-wrapper" style={{ flex: 1 }}>
            <svg className="search-icon" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
            <input 
              type="text" 
              className="search-input" 
              placeholder="Search website, passwords, photos, notes, tags..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <button onClick={() => handleOpenAdd("Logins")} className="btn btn-primary" style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', whiteSpace: 'nowrap' }}>
            <span>➕</span> Add Item
          </button>
        </div>

        {/* Quick Filter Pill Chips */}
        <div style={{ display: 'flex', gap: '0.5rem', overflowX: 'auto', paddingBottom: '0.25rem' }}>
          <button 
            onClick={() => setActiveTab("all")} 
            className="btn" 
            style={{ padding: '0.25rem 0.65rem', fontSize: '0.75rem', borderRadius: '14px', background: activeTab === "all" ? 'linear-gradient(135deg, #06b6d4, #3b82f6)' : 'rgba(30, 41, 59, 0.6)', border: 'none', color: '#fff' }}
          >
            All
          </button>
          <button 
            onClick={() => setActiveTab("websites")} 
            className="btn" 
            style={{ padding: '0.25rem 0.65rem', fontSize: '0.75rem', borderRadius: '14px', background: activeTab === "websites" ? 'linear-gradient(135deg, #06b6d4, #3b82f6)' : 'rgba(30, 41, 59, 0.6)', border: 'none', color: '#fff' }}
          >
            🔑 Passwords
          </button>
          <button 
            onClick={() => setActiveTab("documents")} 
            className="btn" 
            style={{ padding: '0.25rem 0.65rem', fontSize: '0.75rem', borderRadius: '14px', background: activeTab === "documents" ? 'linear-gradient(135deg, #06b6d4, #3b82f6)' : 'rgba(30, 41, 59, 0.6)', border: 'none', color: '#fff' }}
          >
            📄 Docs
          </button>
          <button 
            onClick={() => setActiveTab("photos")} 
            className="btn" 
            style={{ padding: '0.25rem 0.65rem', fontSize: '0.75rem', borderRadius: '14px', background: activeTab === "photos" ? 'linear-gradient(135deg, #06b6d4, #3b82f6)' : 'rgba(30, 41, 59, 0.6)', border: 'none', color: '#fff' }}
          >
            🖼️ Photos
          </button>
          <button 
            onClick={() => setActiveTab("notes")} 
            className="btn" 
            style={{ padding: '0.25rem 0.65rem', fontSize: '0.75rem', borderRadius: '14px', background: activeTab === "notes" ? 'linear-gradient(135deg, #06b6d4, #3b82f6)' : 'rgba(30, 41, 59, 0.6)', border: 'none', color: '#fff' }}
          >
            📝 Notes
          </button>
          <button 
            onClick={() => setActiveTab("favorites")} 
            className="btn" 
            style={{ padding: '0.25rem 0.65rem', fontSize: '0.75rem', borderRadius: '14px', background: activeTab === "favorites" ? 'linear-gradient(135deg, #06b6d4, #3b82f6)' : 'rgba(30, 41, 59, 0.6)', border: 'none', color: '#fff' }}
          >
            ⭐ Favorites
          </button>
        </div>

        {/* Item List */}
        {filteredItems.length === 0 ? (
          <div className="card empty-state">
            <div className="site-icon" style={{ width: '60px', height: '60px', borderRadius: '50%', fontSize: '1.8rem' }}>🔒</div>
            <h2 className="empty-state-title">No vault items found</h2>
            <p className="empty-state-desc">
              {searchQuery ? "No items matched your search query." : "Your zero-knowledge vault is empty. Store passwords, documents, photos, or secret notes safely."}
            </p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
            {filteredItems.map(item => {
              const isSelected = selectedItem && selectedItem.id === item.id;
              const isPhoto = item.category === "Photos" || (item.file_type && item.file_type.startsWith("image/"));

              return (
                <div 
                  key={item.id} 
                  className={`feed-item ${isSelected ? "selected" : ""}`}
                  onClick={() => setSelectedItem(item)}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', overflow: 'hidden' }}>
                    <div style={{ width: '38px', height: '38px', borderRadius: '10px', background: 'rgba(6, 182, 212, 0.12)', border: '1px solid rgba(6, 182, 212, 0.25)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.2rem', flexShrink: 0 }}>
                      {isPhoto ? "🖼️" : item.category === "Certificates" ? "🎓" : item.category === "Documents" ? "📄" : item.category === "Secure Notes" ? "📝" : "🔑"}
                    </div>

                    <div style={{ overflow: 'hidden' }}>
                      <div style={{ fontSize: '0.92rem', fontWeight: 700, color: '#f8fafc', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <span>{item.name || item.title}</span>
                        {item.is_favorite && <span style={{ color: '#f59e0b', fontSize: '0.8rem' }}>★</span>}
                      </div>
                      <div style={{ fontSize: '0.78rem', color: '#94a3b8', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                        {item.username || item.url || item.tag || item.category}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexShrink: 0 }}>
                    {item.tag && (
                      <span style={{ fontSize: '0.68rem', background: 'rgba(59, 130, 246, 0.15)', color: '#60a5fa', padding: '0.1rem 0.4rem', borderRadius: '4px', border: '1px solid rgba(59, 130, 246, 0.3)' }}>
                        🏷️ {item.tag}
                      </span>
                    )}

                    <button 
                      onClick={(e) => handleToggleFavorite(item, e)} 
                      style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '1.1rem', color: item.is_favorite ? '#f59e0b' : '#64748b' }}
                      title={item.is_favorite ? "Starred Favorite" : "Add to Favorites"}
                    >
                      {item.is_favorite ? "★" : "☆"}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </main>

      {/* Column 3: Detail Inspector Panel */}
      <aside className="workspace-inspector">
        {selectedItem ? (
          <>
            {/* Inspector Top Header Card */}
            <div className="inspector-header-card">
              <div style={{ width: '56px', height: '56px', borderRadius: '14px', background: 'linear-gradient(135deg, rgba(6, 182, 212, 0.2), rgba(59, 130, 246, 0.2))', border: '1px solid rgba(6, 182, 212, 0.4)', margin: '0 auto 0.75rem auto', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.8rem', boxShadow: '0 0 20px rgba(6, 182, 212, 0.2)' }}>
                {selectedItem.category === "Photos" || (selectedItem.file_type && selectedItem.file_type.startsWith("image/")) ? "🖼️" : selectedItem.category === "Certificates" ? "🎓" : selectedItem.category === "Documents" ? "📄" : selectedItem.category === "Secure Notes" ? "📝" : "🔑"}
              </div>

              <h2 style={{ margin: 0, fontSize: '1.15rem', fontWeight: 800, color: '#f8fafc' }}>
                {selectedItem.name || selectedItem.title}
              </h2>

              {selectedItem.url && (
                <a 
                  href={selectedItem.url.startsWith("http") ? selectedItem.url : `https://${selectedItem.url}`} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', marginTop: '0.3rem', fontSize: '0.8rem', color: '#38bdf8', textDecoration: 'none', fontWeight: 600 }}
                >
                  Visit {selectedItem.url} ↗
                </a>
              )}
            </div>

            {/* Fields Details */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', flex: 1, overflowY: 'auto' }}>
              
              {/* Username Field */}
              {selectedItem.username && (
                <div className="inspector-field">
                  <span style={{ fontSize: '0.7rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase' }}>Username / Email</span>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: '0.88rem', fontWeight: 600, color: '#f1f5f9' }}>{selectedItem.username}</span>
                    <button className="btn-icon" onClick={() => copyToClipboard(selectedItem.username, "username", "Username")}>
                      <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"></path></svg>
                    </button>
                  </div>
                </div>
              )}

              {/* Password Field */}
              {selectedItem.password && (
                <div className="inspector-field">
                  <span style={{ fontSize: '0.7rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase' }}>Password</span>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: '0.88rem', fontWeight: 600, color: '#f1f5f9', fontFamily: showInspectorPassword ? 'monospace' : 'inherit' }}>
                      {showInspectorPassword ? selectedItem.password : "••••••••••••••••"}
                    </span>
                    <div style={{ display: 'flex', gap: '0.3rem' }}>
                      <button className="btn-icon" onClick={() => setShowInspectorPassword(!showInspectorPassword)}>
                        {showInspectorPassword ? (
                          <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0112 19c-7 0-11-7-11-7a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 7 11 7a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
                        ) : (
                          <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                        )}
                      </button>
                      <button className="btn-icon" onClick={() => copyToClipboard(selectedItem.password, "password", "Password")}>
                        <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"></path></svg>
                      </button>
                    </div>
                  </div>
                  {/* Strength Bar */}
                  {(() => {
                    const ent = calculateEntropy(selectedItem.password);
                    return (
                      <div style={{ marginTop: '0.4rem', display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.68rem', color: ent.color }}>
                        <div style={{ height: '4px', flex: 1, background: 'rgba(255,255,255,0.1)', borderRadius: '2px', overflow: 'hidden' }}>
                          <div style={{ height: '100%', width: `${Math.min(100, (ent.bits / 100) * 100)}%`, background: ent.color }}></div>
                        </div>
                        <span>{ent.strength} ({ent.bits} bits)</span>
                      </div>
                    );
                  })()}
                </div>
              )}

              {/* Photo Preview in Inspector */}
              {selectedItem.file_data && (selectedItem.category === "Photos" || (selectedItem.file_type && selectedItem.file_type.startsWith("image/"))) && (
                <div style={{ borderRadius: '10px', overflow: 'hidden', border: '1px solid rgba(168, 85, 247, 0.4)', background: '#000' }}>
                  <img 
                    src={selectedItem.file_data} 
                    alt={selectedItem.name}
                    style={{ width: '100%', maxHeight: '180px', objectFit: 'cover', display: 'block', cursor: 'pointer' }}
                    onClick={() => setPreviewPhotoItem(selectedItem)}
                  />
                  <button 
                    onClick={() => setPreviewPhotoItem(selectedItem)}
                    className="btn btn-secondary" 
                    style={{ width: '100%', borderRadius: 0, padding: '0.35rem', fontSize: '0.75rem' }}
                  >
                    🔍 View Full Encrypted Photo
                  </button>
                </div>
              )}

              {/* File Attachment in Inspector */}
              {selectedItem.file_data && !(selectedItem.category === "Photos" || (selectedItem.file_type && selectedItem.file_type.startsWith("image/"))) && (
                <div className="inspector-field" style={{ background: 'rgba(59, 130, 246, 0.12)', border: '1px solid rgba(59, 130, 246, 0.3)' }}>
                  <span style={{ fontSize: '0.7rem', fontWeight: 700, color: '#60a5fa' }}>Attached Encrypted File</span>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.2rem' }}>
                    <span style={{ fontSize: '0.8rem', color: '#f1f5f9', fontWeight: 600 }}>{selectedItem.file_name || 'Document File'}</span>
                    <a 
                      href={selectedItem.file_data} 
                      download={selectedItem.file_name || "encrypted_file"}
                      className="btn btn-primary"
                      style={{ padding: '0.25rem 0.6rem', fontSize: '0.72rem', textDecoration: 'none' }}
                    >
                      💾 Download
                    </a>
                  </div>
                </div>
              )}

              {/* Encrypted Notes */}
              {selectedItem.notes && (
                <div className="inspector-field">
                  <span style={{ fontSize: '0.7rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase' }}>Notes & Secrets</span>
                  <p style={{ margin: 0, fontSize: '0.8rem', color: '#cbd5e1', whiteSpace: 'pre-wrap', lineHeight: 1.4 }}>
                    {selectedItem.notes}
                  </p>
                </div>
              )}

            </div>

            {/* Inspector Action Buttons */}
            <div style={{ display: 'flex', gap: '0.5rem', paddingTop: '0.75rem', borderTop: '1px solid rgba(255,255,255,0.08)' }}>
              <button 
                onClick={() => handleOpenEdit(selectedItem)} 
                className="btn btn-secondary" 
                style={{ flex: 1, padding: '0.45rem', fontSize: '0.8rem' }}
              >
                ✏️ Edit
              </button>
              <button 
                onClick={(e) => handleToggleFavorite(selectedItem, e)} 
                className="btn btn-secondary" 
                style={{ flex: 1, padding: '0.45rem', fontSize: '0.8rem', color: selectedItem.is_favorite ? '#f59e0b' : 'inherit' }}
              >
                {selectedItem.is_favorite ? "★ Starred" : "☆ Favorite"}
              </button>
              <button 
                onClick={() => handleDeleteCredential(selectedItem.id)} 
                className="btn btn-danger" 
                style={{ padding: '0.45rem 0.75rem', fontSize: '0.8rem' }}
              >
                🗑️
              </button>
            </div>
          </>
        ) : (
          <div style={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', textAlign: 'center', color: '#64748b', gap: '0.75rem' }}>
            <span style={{ fontSize: '2.5rem' }}>🛡️</span>
            <h3 style={{ fontSize: '1rem', color: '#cbd5e1' }}>No Vault Item Selected</h3>
            <p style={{ fontSize: '0.8rem', maxWidth: '240px' }}>Select any item from the master list to inspect full encrypted details and actions.</p>
          </div>
        )}
      </aside>

      {/* Photo Lightbox Preview Modal */}
      {previewPhotoItem && (
        <div className="modal-overlay" onClick={() => setPreviewPhotoItem(null)}>
          <div className="modal-content" style={{ maxWidth: '650px', background: '#090d16', border: '1px solid rgba(168, 85, 247, 0.4)' }} onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2 className="modal-title" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span>🖼️</span> {previewPhotoItem.name || previewPhotoItem.title || "Encrypted Photo"}
              </h2>
              <button onClick={() => setPreviewPhotoItem(null)} className="btn-icon">
                <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              </button>
            </div>
            <div className="modal-body" style={{ textAlign: 'center' }}>
              <img 
                src={previewPhotoItem.file_data} 
                alt={previewPhotoItem.name} 
                style={{ maxWidth: '100%', maxHeight: '420px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.1)', objectFit: 'contain' }}
              />
              {previewPhotoItem.notes && (
                <p style={{ marginTop: '0.75rem', fontSize: '0.85rem', color: '#cbd5e1', textAlign: 'left', background: 'rgba(255,255,255,0.03)', padding: '0.6rem', borderRadius: '6px' }}>
                  <strong>Notes:</strong> {previewPhotoItem.notes}
                </p>
              )}
            </div>
            <div className="modal-footer" style={{ justifyContent: 'space-between' }}>
              <span style={{ fontSize: '0.75rem', color: '#c084fc' }}>
                🔒 Zero-Knowledge Encrypted Payload ({previewPhotoItem.file_size || 'Decrypted locally'})
              </span>
              <a 
                href={previewPhotoItem.file_data} 
                download={previewPhotoItem.file_name || "encrypted_photo.png"}
                className="btn btn-primary"
                style={{ textDecoration: 'none' }}
              >
                💾 Save Photo
              </a>
            </div>
          </div>
        </div>
      )}

      {/* Add / Edit Modal */}
      {showAddEditModal && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="modal-header">
              <h2 className="modal-title">
                {editingItem ? "Edit Vault Record" : `Add ${category === "Photos" ? "Encrypted Photo" : category === "Documents" ? "Document File" : category === "Secure Notes" ? "Secret Note" : "Website Password"} to Vault`}
              </h2>
              <button onClick={() => setShowAddEditModal(false)} className="btn-icon">
                <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              </button>
            </div>
            
            <form onSubmit={handleSaveCredential}>
              <div className="modal-body">
                
                <div className="form-group">
                  <label className="form-label" htmlFor="item-category">Vault Category *</label>
                  <select 
                    id="item-category"
                    className="select-input"
                    value={category}
                    onChange={(e) => setCategory(e.target.value)}
                  >
                    <option value="Logins">🔑 Website Password</option>
                    <option value="Photos">🖼️ Encrypted Photo / Image</option>
                    <option value="Documents">📄 Encrypted Document / PDF</option>
                    <option value="Certificates">🎓 Student / Professional Certificate</option>
                    <option value="Secure Notes">📝 Secret Note / Confidential Text</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label" htmlFor="site-name">
                    {category === "Photos" ? "Photo Title *" : category === "Certificates" ? "Certificate Name *" : category === "Documents" ? "Document Title *" : category === "Secure Notes" ? "Note Title *" : "Website / App Name *"}
                  </label>
                  <input 
                    id="site-name"
                    type="text" 
                    className="form-input" 
                    placeholder={category === "Photos" ? "e.g. Passport Photo / ID Scan" : category === "Certificates" ? "e.g. Bachelor of Computer Science" : category === "Documents" ? "e.g. Passport / Transcript PDF" : category === "Secure Notes" ? "e.g. Wi-Fi Password / Banking PIN" : "e.g. GitHub / Google / Student Portal"}
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    required
                  />
                </div>

                {/* Photo & File Upload Input */}
                {(category === "Photos" || category === "Documents" || category === "Certificates") && (
                  <div className="form-group" style={{ background: 'rgba(255,255,255,0.02)', padding: '0.85rem', borderRadius: '8px', border: '1px dashed rgba(6, 182, 212, 0.4)' }}>
                    <label className="form-label">
                      {category === "Photos" ? "Upload & Encrypt Photo / Image *" : "Upload & Encrypt Document / File"}
                    </label>
                    <input 
                      type="file" 
                      accept={category === "Photos" ? "image/*" : "*"}
                      onChange={handleFileChange}
                      className="form-input"
                      style={{ padding: '0.4rem' }}
                    />
                    {fileData && (
                      <div style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: '#10b981', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <span>✓ File Loaded ({fileName} - {fileSize})</span>
                      </div>
                    )}
                  </div>
                )}

                {/* Logins Specific Fields */}
                {category === "Logins" && (
                  <>
                    <div className="form-group">
                      <label className="form-label" htmlFor="site-url">Website URL / Domain</label>
                      <input 
                        id="site-url"
                        type="text" 
                        className="form-input" 
                        placeholder="e.g. github.com or https://google.com"
                        value={siteUrl}
                        onChange={(e) => setSiteUrl(e.target.value)}
                        list="existing-websites-list"
                      />
                      {existingWebsitesList.length > 0 && (
                        <datalist id="existing-websites-list">
                          {existingWebsitesList.map(web => (
                            <option key={web} value={web} />
                          ))}
                        </datalist>
                      )}
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

                {/* Organization Folder Tag & Favorite Star */}
                <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1rem', alignItems: 'center' }}>
                  <div className="form-group">
                    <label className="form-label" htmlFor="tag">Folder / Tag</label>
                    <input 
                      id="tag"
                      type="text" 
                      className="form-input" 
                      placeholder="e.g. Work, Personal, School, Banking"
                      value={tag}
                      onChange={(e) => setTag(e.target.value)}
                    />
                  </div>

                  <div className="form-group" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '1.2rem' }}>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', cursor: 'pointer', fontSize: '0.85rem', color: 'var(--text-primary)' }}>
                      <input 
                        type="checkbox"
                        checked={isFavorite}
                        onChange={(e) => setIsFavorite(e.target.checked)}
                        style={{ width: '16px', height: '16px', accentColor: '#06b6d4' }}
                      />
                      Starred Favorite ⭐
                    </label>
                  </div>
                </div>

                {/* Notes */}
                <div className="form-group">
                  <label className="form-label" htmlFor="notes">Encrypted Notes & Details</label>
                  <textarea 
                    id="notes"
                    className="form-input" 
                    rows="3" 
                    placeholder="Additional confidential notes, PINs, or details..."
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                  ></textarea>
                </div>

              </div>
              <div className="modal-footer">
                <button type="button" onClick={() => setShowAddEditModal(false)} className="btn btn-secondary">
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  {editingItem ? "Save Changes" : "Encrypt & Save"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Password Generator Modal */}
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
              <div className="gen-output-box" style={{ background: 'rgba(15, 23, 42, 0.8)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '1rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                <span style={{ fontFamily: 'monospace', fontSize: '1.1rem', letterSpacing: '0.05em', color: '#10B981', wordBreak: 'break-all' }}>
                  {generatedPass || "Click Generate"}
                </span>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button onClick={handleGenerate} className="btn-icon" title="Regenerate">
                    <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M23 4v6h-6"></path><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"></path></svg>
                  </button>
                  <button onClick={() => copyToClipboard(generatedPass, "generated_password", "Generated Password")} className="btn-icon" title="Copy">
                    <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"></path></svg>
                  </button>
                </div>
              </div>

              {/* Entropy & Strength Meter */}
              <div style={{ marginBottom: '1.25rem', padding: '0.75rem 1rem', borderRadius: '8px', background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem', marginBottom: '0.4rem' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Password Entropy:</span>
                  <span style={{ fontWeight: 'bold', color: currentEntropy.color }}>
                    {currentEntropy.bits} bits ({currentEntropy.strength})
                  </span>
                </div>
                <div style={{ height: '6px', width: '100%', background: 'rgba(255,255,255,0.1)', borderRadius: '3px', overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${Math.min(100, (currentEntropy.bits / 100) * 100)}%`, background: currentEntropy.color, transition: 'width 0.3s ease' }}></div>
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Password Length: {genLength}</label>
                <input 
                  type="range" 
                  min="8" 
                  max="64" 
                  value={genLength} 
                  onChange={(e) => { setGenLength(parseInt(e.target.value)); handleGenerate(); }}
                  style={{ width: '100%', accentColor: '#06b6d4' }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginTop: '1rem' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', color: 'var(--text-primary)', cursor: 'pointer' }}>
                  <input type="checkbox" checked={genOptions.uppercase} onChange={(e) => { setGenOptions({...genOptions, uppercase: e.target.checked}); }} style={{ accentColor: '#06b6d4' }} />
                  Uppercase (A-Z)
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', color: 'var(--text-primary)', cursor: 'pointer' }}>
                  <input type="checkbox" checked={genOptions.lowercase} onChange={(e) => { setGenOptions({...genOptions, lowercase: e.target.checked}); }} style={{ accentColor: '#06b6d4' }} />
                  Lowercase (a-z)
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', color: 'var(--text-primary)', cursor: 'pointer' }}>
                  <input type="checkbox" checked={genOptions.numbers} onChange={(e) => { setGenOptions({...genOptions, numbers: e.target.checked}); }} style={{ accentColor: '#06b6d4' }} />
                  Numbers (0-9)
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', color: 'var(--text-primary)', cursor: 'pointer' }}>
                  <input type="checkbox" checked={genOptions.symbols} onChange={(e) => { setGenOptions({...genOptions, symbols: e.target.checked}); }} style={{ accentColor: '#06b6d4' }} />
                  Symbols (!@#$)
                </label>
              </div>
            </div>

            <div className="modal-footer">
              <button onClick={() => setShowGenModal(false)} className="btn btn-secondary">Close</button>
              <button onClick={handleGenerate} className="btn btn-primary">Generate New</button>
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
