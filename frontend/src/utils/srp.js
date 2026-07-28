/**
 * SRP-6a (Secure Remote Password - PAKE) Client-Side Implementation (RFC 5054 / RFC 2945)
 */

export const SRP_N_HEX = 
  "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
  "A37329CBB4FE29D9C862F2AC7D8725101128093B535D8961353078440A28F27F" +
  "25717D50A41D6086B7E325C05752D22CC6888034515E86E20B0C4776DCD88F28" +
  "562B28B0237553531F2E84A7851608A3DA2E407221DFB5BD551BF1D45070281F" +
  "CDD306C9B0762E404E85C1BE90C5CD710E102E72E77286377197A24FAF92D2F2" +
  "CC427027BCEF07F2D172EBF044810620ED2CC295F72A5A609F3A95E407BF33B4" +
  "9E7C0579979EC027114A51D14EB5E70B7E0041B1F3C4718CD946B04664F35C83" +
  "3C143B80E621C1C85A827F37F159C2479E331405102F3A30BE5EED763321";

export const SRP_G_HEX = "02";
const N_BIGINT = BigInt("0x" + SRP_N_HEX);
const G_BIGINT = 2n;

function modPow(base, exp, mod) {
  let res = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e % 2n === 1n) res = (res * b) % mod;
    b = (b * b) % mod;
    e = e / 2n;
  }
  return res;
}

function hexToBytes(hex) {
  const cleanHex = hex.length % 2 !== 0 ? "0" + hex : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Hex(...inputs) {
  const chunks = [];
  for (const input of inputs) {
    if (typeof input === "string") {
      if (/^[0-9a-fA-F]+$/.test(input) && input.length > 16) {
        chunks.push(hexToBytes(input));
      } else {
        chunks.push(new TextEncoder().encode(input));
      }
    } else if (input instanceof Uint8Array) {
      chunks.push(input);
    } else if (typeof input === "bigint") {
      let hex = input.toString(16);
      if (hex.length % 2 !== 0) hex = "0" + hex;
      chunks.push(hexToBytes(hex));
    }
  }
  
  let totalLength = chunks.reduce((acc, c) => acc + c.length, 0);
  const combined = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.length;
  }
  
  const hashBuf = await window.crypto.subtle.digest("SHA-256", combined);
  return bytesToHex(hashBuf);
}

async function computeK() {
  const kHex = await sha256Hex(SRP_N_HEX, SRP_G_HEX);
  return BigInt("0x" + kHex);
}

export async function computeSrpX(saltHex, masterKeyBytes) {
  const xHex = await sha256Hex(hexToBytes(saltHex), masterKeyBytes);
  return BigInt("0x" + xHex);
}

export async function generateSrpVerifier(saltHex, masterKeyBytes) {
  const x = await computeSrpX(saltHex, masterKeyBytes);
  const v = modPow(G_BIGINT, x, N_BIGINT);
  let vHex = v.toString(16);
  if (vHex.length % 2 !== 0) vHex = "0" + vHex;
  return vHex;
}

export function generateSrpClientEphemeral() {
  const aBytes = new Uint8Array(32);
  window.crypto.getRandomValues(aBytes);
  const aHex = bytesToHex(aBytes);
  const a = BigInt("0x" + aHex);
  const A = modPow(G_BIGINT, a, N_BIGINT);
  let AHex = A.toString(16);
  if (AHex.length % 2 !== 0) AHex = "0" + AHex;
  return {
    aHex,
    AHex
  };
}

export async function computeSrpClientProof(saltHex, AHex, BHex, aHex, masterKeyBytes) {
  const A = BigInt("0x" + AHex);
  const B = BigInt("0x" + BHex);
  const a = BigInt("0x" + aHex);
  
  if (A % N_BIGINT === 0n || B % N_BIGINT === 0n) {
    throw new Error("Invalid SRP ephemeral public keys (modulo N equal to 0)");
  }
  
  const uHex = await sha256Hex(AHex, BHex);
  const u = BigInt("0x" + uHex);
  if (u === 0n) {
    throw new Error("Invalid scramble parameter u");
  }
  
  const k = await computeK();
  const x = await computeSrpX(saltHex, masterKeyBytes);
  const v = modPow(G_BIGINT, x, N_BIGINT);
  
  let base = (B - (k * v) % N_BIGINT) % N_BIGINT;
  if (base < 0n) base += N_BIGINT;
  
  const exp = a + u * x;
  const S = modPow(base, exp, N_BIGINT);
  let SHex = S.toString(16);
  if (SHex.length % 2 !== 0) SHex = "0" + SHex;
  
  const KHex = await sha256Hex(SHex);
  const M1Hex = await sha256Hex(AHex, BHex, KHex);
  const M2Hex = await sha256Hex(AHex, M1Hex, KHex);
  
  return {
    M1Hex,
    M2Hex,
    KHex
  };
}
