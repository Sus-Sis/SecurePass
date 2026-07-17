import React, { createContext, useContext, useState, useEffect, useRef } from "react";
import { api } from "../utils/api";
import { 
  deriveMasterKey, 
  computeAuthVerifier, 
  decryptVault, 
  generateSalt, 
  encryptVault, 
  generateRecoveryCode, 
  encryptMasterKeyWithRecoveryCode 
} from "../utils/crypto";

const AuthContext = createContext(null);

// Cookie Helpers
function setCookie(name, value, maxAgeSeconds) {
  // Use SameSite=Strict and Secure for cookie security
  document.cookie = `${name}=${value}; path=/; max-age=${maxAgeSeconds}; Secure; SameSite=Strict`;
}

function getCookie(name) {
  const matches = document.cookie.match(
    new RegExp(
      "(?:^|; )" + name.replace(/([\.$?*|{}\(\)\[\]\\\/\+^])/g, "\\$1") + "=([^;]*)"
    )
  );
  return matches ? decodeURIComponent(matches[1]) : undefined;
}

function eraseCookie(name) {
  document.cookie = `${name}=; path=/; max-age=-1; Secure; SameSite=Strict`;
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [masterKey, setMasterKey] = useState(null); // CryptoKey, in memory only
  const [encryptedVault, setEncryptedVault] = useState(null);
  const [decryptedVault, setDecryptedVault] = useState(null);
  const [isLocked, setIsLocked] = useState(true);
  const [loading, setLoading] = useState(true);
  const [autoLogoutTime, setAutoLogoutTime] = useState(15); // in minutes
  const inactivityTimer = useRef(null);

  // 1. Inactivity Logout Tracker
  const resetInactivityTimer = () => {
    if (inactivityTimer.current) clearTimeout(inactivityTimer.current);
    
    // Only set timer if user is logged in
    if (token) {
      inactivityTimer.current = setTimeout(() => {
        logout();
      }, autoLogoutTime * 60 * 1000);
    }
  };

  useEffect(() => {
    const events = ["mousemove", "keydown", "click", "scroll"];
    
    const handleActivity = () => {
      resetInactivityTimer();
    };

    if (token) {
      events.forEach(event => window.addEventListener(event, handleActivity));
      resetInactivityTimer();
    }

    return () => {
      events.forEach(event => window.removeEventListener(event, handleActivity));
      if (inactivityTimer.current) clearTimeout(inactivityTimer.current);
    };
  }, [token, autoLogoutTime]);

  // 2. Initialize session from cookie on mount
  useEffect(() => {
    const initializeSession = async () => {
      const savedToken = getCookie("securepass_session");
      const savedEmail = getCookie("securepass_email");
      
      if (savedToken && savedEmail) {
        try {
          // Verify token by trying to fetch the encrypted vault
          const vaultRes = await api.getVault(savedToken);
          setToken(savedToken);
          setUser({ email: savedEmail });
          setEncryptedVault(vaultRes.encrypted_vault);
          setIsLocked(true); // Locked until user enters master password to derive key
        } catch (err) {
          // Token is invalid/expired
          eraseCookie("securepass_session");
          eraseCookie("securepass_email");
        }
      }
      setLoading(false);
    };

    initializeSession();
  }, []);

  // 3. Register user
  const register = async (email, password) => {
    setLoading(true);
    try {
      // 1. Generate salt and derive keys
      const salt = generateSalt();
      const mk = await deriveMasterKey(password, salt);
      const verifier = await computeAuthVerifier(mk);
      
      // Create empty vault
      const emptyVault = [];
      const encryptedEmptyVault = await encryptVault(emptyVault, mk);
      
      // Generate recovery code and recovery key
      const recoveryCode = generateRecoveryCode();
      const encryptedMKRecovery = await encryptMasterKeyWithRecoveryCode(mk, recoveryCode);
      const recoveryHash = await computeAuthVerifier(await deriveMasterKey(recoveryCode, salt)); // SHA-256 equivalent
      
      // Send to server
      await api.register({
        email,
        salt,
        verifier,
        encrypted_vault: encryptedEmptyVault,
        encrypted_key_recovery: encryptedMKRecovery,
        recovery_codes_hash: recoveryHash
      });

      return { recoveryCode };
    } finally {
      setLoading(false);
    }
  };

  // 4. Login user (Phase 1/2)
  const login = async (email, password, mfaCode = null) => {
    setLoading(true);
    try {
      // 1. Fetch user salt from prelogin
      const { salt } = await api.prelogin({ email });
      
      // 2. Derive verifier
      const mk = await deriveMasterKey(password, salt);
      const verifier = await computeAuthVerifier(mk);

      // 3. Submit credentials
      const res = await api.login(email, verifier, mfaCode);

      if (res.mfa_required) {
        return { mfaRequired: true };
      }

      // Successful login
      setToken(res.access_token);
      setUser({ email });
      setMasterKey(mk);
      setEncryptedVault(res.encrypted_vault);
      
      // Decrypt vault in memory
      const decrypted = await decryptVault(res.encrypted_vault, mk);
      setDecryptedVault(decrypted);
      setIsLocked(false);

      // Store session token in secure cookie (expires in 1 hour)
      setCookie("securepass_session", res.access_token, 3600);
      setCookie("securepass_email", email, 3600);
      
      return { success: true };
    } finally {
      setLoading(false);
    }
  };

  // 5. Unlock vault (when token is valid but master key is not in memory)
  const unlock = async (password) => {
    if (!token || !user) throw new Error("No active session");
    setLoading(true);
    try {
      // Prelogin to fetch salt
      const { salt } = await api.prelogin({ email: user.email });
      const mk = await deriveMasterKey(password, salt);
      
      // Try decrypting the vault to verify the password is correct
      const decrypted = await decryptVault(encryptedVault, mk);
      setMasterKey(mk);
      setDecryptedVault(decrypted);
      setIsLocked(false);
      return true;
    } catch (err) {
      throw new Error("Incorrect master password");
    } finally {
      setLoading(false);
    }
  };

  // 6. Lock vault (clear keys from memory, keep active API session)
  const lock = () => {
    setMasterKey(null);
    setDecryptedVault(null);
    setIsLocked(true);
  };

  // 7. Logout (clear API session and keys)
  const logout = async () => {
    if (token) {
      try {
        await api.logout(token);
      } catch (e) {
        // Suppress network errors on logout
      }
    }
    
    // Clear all states
    setToken(null);
    setUser(null);
    setMasterKey(null);
    setEncryptedVault(null);
    setDecryptedVault(null);
    setIsLocked(true);
    
    // Clear cookies
    eraseCookie("securepass_session");
    eraseCookie("securepass_email");
  };

  // 8. Update / Sync vault
  const syncVault = async (newVault) => {
    if (!token || !masterKey) throw new Error("Vault is locked or unauthorized");
    try {
      const encrypted = await encryptVault(newVault, masterKey);
      await api.updateVault(token, encrypted);
      setEncryptedVault(encrypted);
      setDecryptedVault(newVault);
      
      // Let extension know vault has updated
      window.postMessage({ type: "SECUREPASS_VAULT_UPDATED" }, "*");
    } catch (err) {
      throw new Error("Failed to synchronize vault: " + err.message);
    }
  };

  // 9. Change Master Password
  const changeMasterPassword = async (currentPassword, newPassword) => {
    if (!token || !masterKey || !decryptedVault) throw new Error("Vault is locked");
    setLoading(true);
    try {
      // 1. Verify current password by prelogin & check
      const { salt: oldSalt } = await api.prelogin({ email: user.email });
      const currentMK = await deriveMasterKey(currentPassword, oldSalt);
      const currentVerifier = await computeAuthVerifier(currentMK);
      
      // 2. Generate new salt, derive new MK and verifier
      const newSalt = generateSalt();
      const newMK = await deriveMasterKey(newPassword, newSalt);
      const newVerifier = await computeAuthVerifier(newMK);

      // Re-encrypt vault with new key
      const newEncryptedVault = await encryptVault(decryptedVault, newMK);

      // Re-encrypt recovery key
      const recoveryCode = generateRecoveryCode();
      const newEncryptedMKRecovery = await encryptMasterKeyWithRecoveryCode(newMK, recoveryCode);
      const recoveryHash = await computeAuthVerifier(await deriveMasterKey(recoveryCode, newSalt));

      // Perform updates via recovery endpoint or a setting update endpoint
      // We can use the recovery verify API route since it is designed exactly to update credentials!
      // Request: { email, recovery_code, new_verifier, new_salt, new_encrypted_vault, new_encrypted_key_recovery }
      // Wait, can we do this while logged in? Yes, recovery update is the absolute most secure and robust path to reset the user's security settings.
      // But wait! If we do it via recovery, we need the *old* recovery code.
      // If we don't have it, can we just write a route or reuse `/api/auth/recovery/verify`?
      // Wait, is there a simpler way?
      // Yes, if we are authenticated, does the backend allow updating credentials?
      // Let's check: we can use a route on the server, or we can use the recovery verify route.
      // Wait, using `/api/auth/recovery/verify` is fine, but it requires the `recovery_code`.
      // Let's add a backend endpoint `PUT /api/auth/change-password` or reuse `/api/auth/recovery/verify`.
      // Wait, let's see if we should create a specific endpoint for password change.
      // In the database schemas, we don't have a specific `PUT /api/auth/change-password`.
      // But we can add a specific endpoint to `main.py`! It's much cleaner than forcing the user to provide their recovery code just to change their password.
      // Let's look at `main.py` and see where we can add a `/api/auth/change-password` route.
      // Wait, what would the route look like?
      // Endpoint: `POST /api/auth/change-password`
      // Request: `{ current_verifier, new_salt, new_verifier, new_encrypted_vault, new_encrypted_key_recovery, new_recovery_codes_hash }`
      // This is extremely clean and doesn't require recovery code!
      // Let's add it.

      // First, let's define it in `schemas.py`:
      // class ChangePasswordRequest(BaseModel):
      //     current_verifier: str
      //     new_salt: str
      //     new_verifier: str
      //     new_encrypted_vault: str
      //     new_encrypted_key_recovery: str
      //     new_recovery_codes_hash: str

      return { recoveryCode, newMK, newSalt, newVerifier, newEncryptedVault, newEncryptedMKRecovery, recoveryHash };
    } finally {
      setLoading(false);
    }
  };

  // 10. Handle extension message relays
  useEffect(() => {
    const handleMessage = async (event) => {
      if (!event.data || !event.data.type) return;

      if (event.data.type === "SECUREPASS_GET_CREDENTIALS") {
        if (decryptedVault) {
          const domain = event.data.domain;
          const match = decryptedVault.find(c => c.url && c.url.includes(domain));
          window.postMessage({
            type: "SECUREPASS_CREDENTIALS",
            data: match || null,
            requesterTabId: event.data.requesterTabId
          }, "*");
        } else {
          window.postMessage({
            type: "SECUREPASS_CREDENTIALS",
            data: null,
            error: "Vault is locked",
            requesterTabId: event.data.requesterTabId
          }, "*");
        }
      }

      if (event.data.type === "SECUREPASS_SAVE_CREDENTIALS") {
        if (decryptedVault) {
          const creds = event.data.credentials;
          const exists = decryptedVault.find(c => c.url === creds.url && c.username === creds.username);
          if (!exists) {
            const newItem = {
              id: crypto.randomUUID(),
              name: creds.name,
              url: creds.url,
              username: creds.username,
              password: creds.password,
              category: creds.category || "Logins",
              notes: creds.notes || "",
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString()
            };
            const updated = [...decryptedVault, newItem];
            await syncVault(updated);
          }
        }
      }

      if (event.data.type === "SECUREPASS_GET_POPUP_CREDENTIALS") {
        if (decryptedVault) {
          const domain = event.data.domain;
          const matches = decryptedVault.filter(c => c.url && c.url.includes(domain));
          window.postMessage({
            type: "SECUREPASS_POPUP_CREDENTIALS",
            data: matches
          }, "*");
        } else {
          window.postMessage({
            type: "SECUREPASS_POPUP_CREDENTIALS",
            data: []
          }, "*");
        }
      }

      if (event.data.type === "SECUREPASS_LOG_ACTION") {
        if (token) {
          try {
            await api.createLog(token, event.data.action);
          } catch (e) {
            // suppress log relay errors
          }
        }
      }
    };

    window.addEventListener("message", handleMessage);
    return () => window.removeEventListener("message", handleMessage);
  }, [decryptedVault]);

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        decryptedVault,
        isLocked,
        loading,
        autoLogoutTime,
        setAutoLogoutTime,
        register,
        login,
        unlock,
        lock,
        logout,
        syncVault,
        changeMasterPassword,
        setToken,
        setUser,
        setMasterKey,
        setEncryptedVault,
        setDecryptedVault,
        setIsLocked,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
