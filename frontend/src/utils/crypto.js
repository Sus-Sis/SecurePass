const encoder = new TextEncoder();
const decoder = new TextDecoder();

// Helper to convert array buffer to base64 string
function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Helper to convert base64 string to array buffer
function base64ToBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Helper to convert array buffer to hex string
function bufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// Helper to convert hex string to Uint8Array
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Generate a cryptographically secure random salt (64 bytes)
 */
export function generateSalt() {
  const salt = window.crypto.getRandomValues(new Uint8Array(64));
  return bufferToHex(salt);
}

/**
 * Derive the Master Key from the Master Password and Salt using PBKDF2 (600,000 iterations)
 * @returns {Promise<CryptoKey>} AES-GCM 256 key
 */
export async function deriveMasterKey(password, saltHex) {
  const saltBytes = hexToBytes(saltHex);
  const passwordBytes = encoder.encode(password);

  // Import raw password as a key material
  const baseKey = await window.crypto.subtle.importKey(
    "raw",
    passwordBytes,
    { name: "PBKDF2" },
    false,
    ["deriveKey", "deriveBits"]
  );

  // Derive the Master Key
  return await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: 600000,
      hash: "SHA-256"
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    true, // Keep extractable to allow hashing and recovery backup
    ["encrypt", "decrypt"]
  );
}

/**
 * Compute the Auth Verifier = SHA-256(MasterKey)
 * @param {CryptoKey} masterKey
 * @returns {Promise<string>} Hex representation of SHA-256 verifier
 */
export async function computeAuthVerifier(masterKey) {
  const rawKey = await window.crypto.subtle.exportKey("raw", masterKey);
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", rawKey);
  return bufferToHex(hashBuffer);
}

/**
 * Encrypt the vault payload using AES-256-GCM
 * @param {object|array} vaultData - plaintext JSON serializable vault
 * @param {CryptoKey} masterKey
 * @returns {Promise<string>} Encrypted string format: "iv_base64.ciphertext_base64"
 */
export async function encryptVault(vaultData, masterKey) {
  const jsonString = JSON.stringify(vaultData);
  const plaintextBytes = encoder.encode(jsonString);
  
  // Generate a random 12-byte Initialization Vector (IV)
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  
  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    masterKey,
    plaintextBytes
  );

  const ivB64 = bufferToBase64(iv);
  const ciphertextB64 = bufferToBase64(ciphertextBuffer);

  return `${ivB64}.${ciphertextB64}`;
}

/**
 * Decrypt the vault payload using AES-256-GCM
 * @param {string} encryptedVaultStr - format: "iv_base64.ciphertext_base64"
 * @param {CryptoKey} masterKey
 * @returns {Promise<array>} Decrypted vault array
 */
export async function decryptVault(encryptedVaultStr, masterKey) {
  if (!encryptedVaultStr || encryptedVaultStr === "[]") {
    return [];
  }
  
  const parts = encryptedVaultStr.split(".");
  if (parts.length !== 2) {
    throw new Error("Invalid encrypted vault format");
  }

  const iv = new Uint8Array(base64ToBuffer(parts[0]));
  const ciphertext = base64ToBuffer(parts[1]);

  const decryptedBuffer = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    masterKey,
    ciphertext
  );

  const plaintextStr = decoder.decode(decryptedBuffer);
  return JSON.parse(plaintextStr);
}

/**
 * Generate a cryptographically secure Recovery Code (32-byte hex string formatted)
 */
export function generateRecoveryCode() {
  const codeBytes = window.crypto.getRandomValues(new Uint8Array(32));
  const hex = bufferToHex(codeBytes);
  // Format as 8-8-8-8-8 character chunks for readability (e.g. abcdef01-...)
  const chunks = [];
  for (let i = 0; i < hex.length; i += 8) {
    chunks.push(hex.substring(i, i + 8));
  }
  return chunks.join("-");
}

/**
 * Derive Recovery Master Key (RMK) from Recovery Code
 * @returns {Promise<CryptoKey>}
 */
async function deriveRecoveryMasterKey(recoveryCode) {
  // Strip hyphens
  const rawCode = recoveryCode.replace(/-/g, "");
  const codeBytes = encoder.encode(rawCode);

  // Use SHA-256 hash of recovery code as the key material for AES-GCM
  const rmkBuffer = await window.crypto.subtle.digest("SHA-256", codeBytes);
  
  return await window.crypto.subtle.importKey(
    "raw",
    rmkBuffer,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypt the Master Key (MK) using a Recovery Code
 * @param {CryptoKey} masterKey
 * @param {string} recoveryCode
 * @returns {Promise<string>} Encrypted MK string: "iv_base64.ciphertext_base64"
 */
export async function encryptMasterKeyWithRecoveryCode(masterKey, recoveryCode) {
  const rawMK = await window.crypto.subtle.exportKey("raw", masterKey);
  const rmk = await deriveRecoveryMasterKey(recoveryCode);
  
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encryptedBuffer = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    rmk,
    rawMK
  );

  const ivB64 = bufferToBase64(iv);
  const ciphertextB64 = bufferToBase64(encryptedBuffer);

  return `${ivB64}.${ciphertextB64}`;
}

/**
 * Decrypt the Master Key (MK) using a Recovery Code
 * @param {string} encryptedMKStr - format: "iv_base64.ciphertext_base64"
 * @param {string} recoveryCode
 * @returns {Promise<CryptoKey>} Decrypted Master Key (AES-GCM)
 */
export async function decryptMasterKeyWithRecoveryCode(encryptedMKStr, recoveryCode) {
  const parts = encryptedMKStr.split(".");
  if (parts.length !== 2) {
    throw new Error("Invalid encrypted key format");
  }

  const iv = new Uint8Array(base64ToBuffer(parts[0]));
  const ciphertext = base64ToBuffer(parts[1]);
  
  const rmk = await deriveRecoveryMasterKey(recoveryCode);

  const decryptedRawMK = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    rmk,
    ciphertext
  );

  return await window.crypto.subtle.importKey(
    "raw",
    decryptedRawMK,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

/**
 * Generates a cryptographically secure random password, excluding ambiguous characters: O, 0, I, l, 1
 */
export function generateSecurePassword(length, options = { uppercase: true, lowercase: true, numbers: true, symbols: true }) {
  const uppercase = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // No O, I
  const lowercase = "abcdefghijkmnopqrstuvwxyz"; // No l
  const numbers = "23456789"; // No 0, 1
  const symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";

  let charset = "";
  if (options.uppercase) charset += uppercase;
  if (options.lowercase) charset += lowercase;
  if (options.numbers) charset += numbers;
  if (options.symbols) charset += symbols;

  if (charset === "") {
    charset = lowercase;
  }

  const randomValues = new Uint32Array(length);
  window.crypto.getRandomValues(randomValues);

  let password = "";
  for (let i = 0; i < length; i++) {
    password += charset[randomValues[i] % charset.length];
  }

  return password;
}

