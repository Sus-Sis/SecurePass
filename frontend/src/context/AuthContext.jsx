import React, { createContext, useContext, useState, useEffect, useRef } from "react";
import { api } from "../utils/api";
import { 
  deriveMasterKey, 
  getRawMasterKeyBytes,
  benchmarkArgon2Parameters,
  generateSrpVerifier,
  generateSrpClientEphemeral,
  computeSrpClientProof,
  computeAuthVerifier,
  decryptVault, 
  generateSalt, 
  encryptVault, 
  generateRecoveryCode, 
  encryptMasterKeyWithRecoveryCode 
} from "../utils/crypto";

const AuthContext = createContext(null);

function setCookie(name, value, maxAgeSeconds) {
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
  const [masterKey, setMasterKey] = useState(null);
  const [encryptedVault, setEncryptedVault] = useState(null);
  const [decryptedVault, setDecryptedVault] = useState(null);
  const [isLocked, setIsLocked] = useState(true);
  const [loading, setLoading] = useState(true);
  const [autoLogoutTime, setAutoLogoutTime] = useState(15);
  const inactivityTimer = useRef(null);

  const resetInactivityTimer = () => {
    if (inactivityTimer.current) clearTimeout(inactivityTimer.current);
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

  useEffect(() => {
    const initializeSession = async () => {
      const savedToken = getCookie("securepass_session");
      const savedEmail = getCookie("securepass_email");
      
      if (savedToken && savedEmail) {
        try {
          const vaultRes = await api.getVault(savedToken);
          setToken(savedToken);
          setUser({ email: savedEmail });
          setEncryptedVault(vaultRes.encrypted_vault);
          setIsLocked(true);
        } catch (err) {
          eraseCookie("securepass_session");
          eraseCookie("securepass_email");
        }
      }
      setLoading(false);
    };

    initializeSession();
  }, []);

  const register = async (email, password) => {
    setLoading(true);
    try {
      const kdfParams = await benchmarkArgon2Parameters(300);
      const salt = generateSalt();
      
      const mk = await deriveMasterKey(password, salt, kdfParams);
      const mkBytes = await getRawMasterKeyBytes(mk);
      
      const srpVerifier = await generateSrpVerifier(salt, mkBytes);
      
      const emptyVault = [];
      const encryptedEmptyVault = await encryptVault(emptyVault, mk);
      
      const recoveryCode = generateRecoveryCode();
      const encryptedMKRecovery = await encryptMasterKeyWithRecoveryCode(mk, recoveryCode);
      const recoveryHash = await computeAuthVerifier(await deriveMasterKey(recoveryCode, salt));
      
      await api.register({
        email,
        salt,
        verifier: srpVerifier,
        kdf_type: "argon2id",
        kdf_params: kdfParams,
        encrypted_vault: encryptedEmptyVault,
        encrypted_key_recovery: encryptedMKRecovery,
        recovery_codes_hash: recoveryHash
      });

      return { recoveryCode };
    } finally {
      setLoading(false);
    }
  };

  const login = async (email, password, mfaCode = null) => {
    setLoading(true);
    try {
      const { aHex, AHex } = generateSrpClientEphemeral();
      const challengeRes = await api.srpChallenge(email, AHex);
      const { salt, server_B, kdf_type, kdf_params } = challengeRes;
      
      // Fallback for legacy accounts created prior to SRP-6a update
      if (!server_B || kdf_type === "pbkdf2") {
        const mk = await deriveMasterKey(password, salt, null);
        const legacyVerifier = await computeAuthVerifier(mk);
        const res = await api.login(email, legacyVerifier, mfaCode);

        if (res.mfa_required) {
          return { mfaRequired: true };
        }

        setToken(res.access_token);
        setUser({ email });
        setMasterKey(mk);
        setEncryptedVault(res.encrypted_vault);
        
        const decrypted = await decryptVault(res.encrypted_vault, mk);
        setDecryptedVault(decrypted);
        setIsLocked(false);

        setCookie("securepass_session", res.access_token, 3600);
        setCookie("securepass_email", email, 3600);
        return { success: true };
      }

      // Modern Argon2id + SRP-6a Zero-Knowledge Flow
      const mk = await deriveMasterKey(password, salt, kdf_params);
      const mkBytes = await getRawMasterKeyBytes(mk);
      
      const { M1Hex, M2Hex } = await computeSrpClientProof(salt, AHex, server_B, aHex, mkBytes);
      const authRes = await api.srpAuthenticate(email, AHex, M1Hex, mfaCode);

      if (authRes.mfa_required) {
        return { mfaRequired: true };
      }

      if (authRes.server_M2 && authRes.server_M2.toLowerCase() !== M2Hex.toLowerCase()) {
        throw new Error("Server authentication proof verification failed (MITM detected)");
      }

      setToken(authRes.access_token);
      setUser({ email });
      setMasterKey(mk);
      setEncryptedVault(authRes.encrypted_vault);
      
      const decrypted = await decryptVault(authRes.encrypted_vault, mk);
      setDecryptedVault(decrypted);
      setIsLocked(false);

      setCookie("securepass_session", authRes.access_token, 3600);
      setCookie("securepass_email", email, 3600);
      
      return { success: true };
    } finally {
      setLoading(false);
    }
  };

  const unlock = async (password) => {
    if (!token || !user) throw new Error("No active session");
    setLoading(true);
    try {
      const preloginRes = await api.prelogin({ email: user.email });
      const mk = await deriveMasterKey(password, preloginRes.salt, preloginRes.kdf_params);
      
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

  const lock = () => {
    setMasterKey(null);
    setDecryptedVault(null);
    setIsLocked(true);
  };

  const logout = async () => {
    if (token) {
      try {
        await api.logout(token);
      } catch (e) {
      }
    }
    
    setToken(null);
    setUser(null);
    setMasterKey(null);
    setEncryptedVault(null);
    setDecryptedVault(null);
    setIsLocked(true);
    
    eraseCookie("securepass_session");
    eraseCookie("securepass_email");
  };

  const syncVault = async (newVault) => {
    if (!token || !masterKey) throw new Error("Vault is locked or unauthorized");
    try {
      const encrypted = await encryptVault(newVault, masterKey);
      await api.updateVault(token, encrypted);
      setEncryptedVault(encrypted);
      setDecryptedVault(newVault);
      
      window.postMessage({ type: "SECUREPASS_VAULT_UPDATED" }, "*");
    } catch (err) {
      throw new Error("Failed to synchronize vault: " + err.message);
    }
  };

  const changeMasterPassword = async (currentPassword, newPassword) => {
    if (!token || !masterKey || !decryptedVault) throw new Error("Vault is locked");
    setLoading(true);
    try {
      const preloginRes = await api.prelogin({ email: user.email });
      const currentMK = await deriveMasterKey(currentPassword, preloginRes.salt, preloginRes.kdf_params);
      const currentMKBytes = await getRawMasterKeyBytes(currentMK);
      const currentVerifier = await generateSrpVerifier(preloginRes.salt, currentMKBytes);
      
      const kdfParams = await benchmarkArgon2Parameters(300);
      const newSalt = generateSalt();
      const newMK = await deriveMasterKey(newPassword, newSalt, kdfParams);
      const newMKBytes = await getRawMasterKeyBytes(newMK);
      const newVerifier = await generateSrpVerifier(newSalt, newMKBytes);

      const newEncryptedVault = await encryptVault(decryptedVault, newMK);
      const recoveryCode = generateRecoveryCode();
      const newEncryptedMKRecovery = await encryptMasterKeyWithRecoveryCode(newMK, recoveryCode);
      const recoveryHash = await computeAuthVerifier(await deriveMasterKey(recoveryCode, newSalt));

      await api.changePassword(token, {
        current_verifier: currentVerifier,
        new_salt: newSalt,
        new_verifier: newVerifier,
        new_kdf_params: kdfParams,
        new_encrypted_vault: newEncryptedVault,
        new_encrypted_key_recovery: newEncryptedMKRecovery,
        new_recovery_codes_hash: recoveryHash
      });

      setMasterKey(newMK);
      setEncryptedVault(newEncryptedVault);
      return { recoveryCode };
    } finally {
      setLoading(false);
    }
  };

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
