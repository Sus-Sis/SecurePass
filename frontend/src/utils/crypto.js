import { deriveArgon2id, benchmarkArgon2Parameters } from "./argon2.js";
import { 
  generateSrpVerifier, 
  generateSrpClientEphemeral, 
  computeSrpClientProof 
} from "./srp.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function bufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

export function generateSalt() {
  const salt = window.crypto.getRandomValues(new Uint8Array(64));
  return bufferToHex(salt);
}

export async function deriveMasterKey(password, saltHex, kdfParams = null) {
  let rawKeyBytes;

  if (kdfParams && (kdfParams.memoryCost || kdfParams.memory_cost)) {
    const params = {
      memoryCost: kdfParams.memoryCost || kdfParams.memory_cost || 4096,
      timeCost: kdfParams.timeCost || kdfParams.time_cost || 1,
      parallelism: kdfParams.parallelism || 1
    };
    const saltBytes = hexToBytes(saltHex);
    rawKeyBytes = await deriveArgon2id(password, saltBytes, params);
  } else {
    const saltBytes = hexToBytes(saltHex);
    const passwordBytes = encoder.encode(password);
    const baseKey = await window.crypto.subtle.importKey(
      "raw",
      passwordBytes,
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );
    const derivedBits = await window.crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: saltBytes,
        iterations: 600000,
        hash: "SHA-256"
      },
      baseKey,
      256
    );
    rawKeyBytes = new Uint8Array(derivedBits);
  }

  return await window.crypto.subtle.importKey(
    "raw",
    rawKeyBytes,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function getRawMasterKeyBytes(masterKey) {
  const buf = await window.crypto.subtle.exportKey("raw", masterKey);
  return new Uint8Array(buf);
}

export async function computeAuthVerifier(masterKey) {
  const rawKey = await window.crypto.subtle.exportKey("raw", masterKey);
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", rawKey);
  return bufferToHex(hashBuffer);
}

export async function encryptVault(vaultData, masterKey) {
  const jsonString = JSON.stringify(vaultData);
  const plaintextBytes = encoder.encode(jsonString);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  
  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    masterKey,
    plaintextBytes
  );

  return `${bufferToBase64(iv)}.${bufferToBase64(ciphertextBuffer)}`;
}

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
    { name: "AES-GCM", iv: iv },
    masterKey,
    ciphertext
  );

  const plaintextStr = decoder.decode(decryptedBuffer);
  return JSON.parse(plaintextStr);
}

export function generateRecoveryCode() {
  const codeBytes = window.crypto.getRandomValues(new Uint8Array(32));
  const hex = bufferToHex(codeBytes);
  const chunks = [];
  for (let i = 0; i < hex.length; i += 8) {
    chunks.push(hex.substring(i, i + 8));
  }
  return chunks.join("-");
}

async function deriveRecoveryMasterKey(recoveryCode) {
  const rawCode = recoveryCode.replace(/-/g, "");
  const codeBytes = encoder.encode(rawCode);
  const rmkBuffer = await window.crypto.subtle.digest("SHA-256", codeBytes);
  
  return await window.crypto.subtle.importKey(
    "raw",
    rmkBuffer,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptMasterKeyWithRecoveryCode(masterKey, recoveryCode) {
  const rawMK = await window.crypto.subtle.exportKey("raw", masterKey);
  const rmk = await deriveRecoveryMasterKey(recoveryCode);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encryptedBuffer = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    rmk,
    rawMK
  );

  return `${bufferToBase64(iv)}.${bufferToBase64(encryptedBuffer)}`;
}

export async function decryptMasterKeyWithRecoveryCode(encryptedMKStr, recoveryCode) {
  const parts = encryptedMKStr.split(".");
  if (parts.length !== 2) {
    throw new Error("Invalid encrypted key format");
  }

  const iv = new Uint8Array(base64ToBuffer(parts[0]));
  const ciphertext = base64ToBuffer(parts[1]);
  const rmk = await deriveRecoveryMasterKey(recoveryCode);

  const decryptedRawMK = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
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

export function generateSecurePassword(length, options = { uppercase: true, lowercase: true, numbers: true, symbols: true }) {
  const uppercase = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const lowercase = "abcdefghijkmnopqrstuvwxyz";
  const numbers = "23456789";
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

export {
  benchmarkArgon2Parameters,
  generateSrpVerifier,
  generateSrpClientEphemeral,
  computeSrpClientProof
};
