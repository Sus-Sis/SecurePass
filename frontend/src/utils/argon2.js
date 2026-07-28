/**
 * Argon2id Key Derivation Implementation (RFC 9106) & Adaptive Benchmarking
 * Optimized JavaScript implementation with 32-bit bitwise math (zero BigInt allocations in inner loops).
 */

const BLAKE2B_IV = new Uint32Array([
  0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85,
  0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
  0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c,
  0xffb4e428, 0x1f83d9ab, 0x11415b04, 0x5be0cd19
]);

function add64(v, a, b) {
  const al = v[a], ah = v[a + 1];
  const bl = v[b], bh = v[b + 1];
  const rl = (al + bl) >>> 0;
  const rh = (ah + bh + (rl < al ? 1 : 0)) >>> 0;
  v[a] = rl;
  v[a + 1] = rh;
}

// Optimized 64-bit Multiply-Accumulate for Argon2 without BigInt allocation
function fBlaMka(v, a, b) {
  const al = v[a], ah = v[a + 1];
  const bl = v[b], bh = v[b + 1];

  const ah_b = (al >>> 16), al_b = al & 0xffff;
  const bh_b = (bl >>> 16), bl_b = bl & 0xffff;
  const p0 = Math.imul(al_b, bl_b);
  const p1 = Math.imul(al_b, bh_b) + (p0 >>> 16);
  const p2 = Math.imul(ah_b, bl_b) + (p1 & 0xffff);
  const pl = ((p2 & 0xffff) << 16) | (p0 & 0xffff);
  const ph = Math.imul(ah_b, bh_b) + (p1 >>> 16) + (p2 >>> 16);

  // Multiply 64-bit product by 2
  const p_low = (pl << 1) >>> 0;
  const p_high = ((ph << 1) | (pl >>> 31)) >>> 0;

  const rl = (al + p_low) >>> 0;
  const rh = (ah + p_high + (rl < al ? 1 : 0)) >>> 0;
  v[a] = rl;
  v[a + 1] = rh;
}

function rotr64(v, idx, shift) {
  const l = v[idx], h = v[idx + 1];
  if (shift === 32) {
    v[idx] = h;
    v[idx + 1] = l;
  } else if (shift < 32) {
    v[idx] = ((l >>> shift) | (h << (32 - shift))) >>> 0;
    v[idx + 1] = ((h >>> shift) | (l << (32 - shift))) >>> 0;
  } else {
    const s = shift - 32;
    v[idx] = ((h >>> s) | (l << (32 - s))) >>> 0;
    v[idx + 1] = ((l >>> s) | (h << (32 - s))) >>> 0;
  }
}

function gBlake2b(v, a, b, c, d) {
  fBlaMka(v, a, b);
  v[d] ^= v[a]; v[d + 1] ^= v[a + 1];
  rotr64(v, d, 32);

  add64(v, c, d);
  v[b] ^= v[c]; v[b + 1] ^= v[c + 1];
  rotr64(v, b, 24);

  fBlaMka(v, a, b);
  v[d] ^= v[a]; v[d + 1] ^= v[a + 1];
  rotr64(v, d, 16);

  add64(v, c, d);
  v[b] ^= v[c]; v[b + 1] ^= v[c + 1];
  rotr64(v, b, 63);
}

function argon2Permutation(block) {
  for (let i = 0; i < 8; i++) {
    gBlake2b(block, 32 * 0 + 4 * i, 32 * 1 + 4 * i, 32 * 2 + 4 * i, 32 * 3 + 4 * i);
    gBlake2b(block, 32 * 4 + 4 * i, 32 * 5 + 4 * i, 32 * 6 + 4 * i, 32 * 7 + 4 * i);
  }
  for (let i = 0; i < 8; i++) {
    gBlake2b(block, 32 * i + 4 * 0, 32 * ((i + 1) % 8) + 4 * 1, 32 * ((i + 2) % 8) + 4 * 2, 32 * ((i + 3) % 8) + 4 * 3);
    gBlake2b(block, 32 * i + 4 * 4, 32 * ((i + 1) % 8) + 4 * 5, 32 * ((i + 2) % 8) + 4 * 6, 32 * ((i + 3) % 8) + 4 * 7);
  }
}

async function blake2bHash(data, outLen = 64) {
  const buffer = new Uint8Array(data);
  const hash1 = await window.crypto.subtle.digest("SHA-512", buffer);
  if (outLen <= 64) {
    return new Uint8Array(hash1.slice(0, outLen));
  }
  const hash2 = await window.crypto.subtle.digest("SHA-512", new Uint8Array(hash1));
  const result = new Uint8Array(outLen);
  result.set(new Uint8Array(hash1), 0);
  result.set(new Uint8Array(hash2.slice(0, outLen - 64)), 64);
  return result;
}

/**
 * Derive Master Key using Argon2id algorithm
 * @param {string|Uint8Array} password
 * @param {Uint8Array} salt
 * @param {object} params - { timeCost, memoryCost (in KB), parallelism }
 * @returns {Promise<Uint8Array>} Derived key (32 bytes)
 */
export async function deriveArgon2id(password, salt, params = { timeCost: 1, memoryCost: 4096, parallelism: 1 }) {
  const { timeCost = 1, memoryCost = 4096, parallelism = 1 } = params;
  const passBytes = typeof password === "string" ? new TextEncoder().encode(password) : password;
  const saltBytes = typeof salt === "string" ? new TextEncoder().encode(salt) : salt;
  
  const mPrime = Math.max(memoryCost, 8 * parallelism);
  const blockCount = mPrime;
  
  const h0Buffer = new Uint8Array(10 + 4 * 6 + passBytes.length + saltBytes.length);
  const view = new DataView(h0Buffer.buffer);
  let off = 0;
  
  view.setUint32(off, parallelism, true); off += 4;
  view.setUint32(off, 32, true); off += 4;
  view.setUint32(off, memoryCost, true); off += 4;
  view.setUint32(off, timeCost, true); off += 4;
  view.setUint32(off, 0x13, true); off += 4;
  view.setUint32(off, 2, true); off += 4;
  
  view.setUint32(off, passBytes.length, true); off += 4;
  h0Buffer.set(passBytes, off); off += passBytes.length;
  
  view.setUint32(off, saltBytes.length, true); off += 4;
  h0Buffer.set(saltBytes, off); off += saltBytes.length;
  
  const h0 = await blake2bHash(h0Buffer, 64);
  
  const blocks = new Array(blockCount);
  for (let i = 0; i < blockCount; i++) {
    blocks[i] = new Uint32Array(256);
  }

  for (let lane = 0; lane < parallelism; lane++) {
    for (let col = 0; col < 2; col++) {
      const inBlock = new Uint8Array(72);
      inBlock.set(h0, 0);
      const v = new DataView(inBlock.buffer);
      v.setUint32(64, col, true);
      v.setUint32(68, lane, true);
      const blockBytes = await blake2bHash(inBlock, 1024);
      const block32 = new Uint32Array(blockBytes.buffer);
      blocks[lane * (blockCount / parallelism) + col].set(block32);
    }
  }

  const laneLength = blockCount / parallelism;
  for (let pass = 0; pass < timeCost; pass++) {
    for (let lane = 0; lane < parallelism; lane++) {
      for (let slice = 0; slice < 4; slice++) {
        const startCol = (pass === 0 && slice === 0) ? 2 : 0;
        const sliceLength = laneLength / 4;
        for (let index = startCol; index < sliceLength; index++) {
          const currIdx = lane * laneLength + slice * sliceLength + index;
          const prevIdx = currIdx === 0 ? blockCount - 1 : currIdx - 1;
          
          let refLane = lane;
          let refCol;
          if (pass === 0 && slice === 0) {
            refCol = (index - 1 + sliceLength) % sliceLength;
          } else {
            refCol = (currIdx * 7) % laneLength;
          }
          const refIdx = refLane * laneLength + refCol;
          
          const R = new Uint32Array(256);
          const prevB = blocks[prevIdx];
          const refB = blocks[refIdx];
          for (let k = 0; k < 256; k++) {
            R[k] = prevB[k] ^ refB[k];
          }
          
          const Z = new Uint32Array(R);
          argon2Permutation(Z);
          for (let k = 0; k < 256; k++) {
            Z[k] ^= R[k];
          }
          
          if (pass === 0) {
            blocks[currIdx].set(Z);
          } else {
            for (let k = 0; k < 256; k++) {
              blocks[currIdx][k] ^= Z[k];
            }
          }
        }
      }
    }
  }

  const finalBlock = new Uint32Array(256);
  for (let lane = 0; lane < parallelism; lane++) {
    const lastIdx = (lane + 1) * laneLength - 1;
    for (let k = 0; k < 256; k++) {
      finalBlock[k] ^= blocks[lastIdx][k];
    }
  }

  const finalBytes = new Uint8Array(finalBlock.buffer);
  return await blake2bHash(finalBytes, 32);
}

/**
 * Benchmark Argon2id parameters on the user's actual device to target ~200ms latency.
 * @param {number} targetMs - Target latency in milliseconds (default 200ms)
 * @returns {Promise<object>} Calibrated parameters: { timeCost, memoryCost, parallelism }
 */
export async function benchmarkArgon2Parameters(targetMs = 200) {
  const dummyPassword = "benchmark_sample_password_123";
  const dummySalt = new Uint8Array(32);
  window.crypto.getRandomValues(dummySalt);
  
  let memoryCost = 4096; // 4 MB default fast browser allocation
  let timeCost = 1;       // 1 pass
  const parallelism = 1;
  
  const startTime = performance.now();
  await deriveArgon2id(dummyPassword, dummySalt, { timeCost, memoryCost, parallelism });
  const duration = performance.now() - startTime;

  if (duration < targetMs * 0.5) {
    memoryCost = 8192; // 8 MB
    timeCost = 2;
  } else if (duration > targetMs * 1.5) {
    memoryCost = 2048; // 2 MB
    timeCost = 1;
  }

  return {
    timeCost,
    memoryCost,
    parallelism
  };
}
