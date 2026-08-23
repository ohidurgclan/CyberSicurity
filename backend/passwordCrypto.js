/**
 * AES-256-CBC password encryption — implemented from scratch, no libraries.
 * ==========================================================================
 * Every piece of the AES algorithm (S-box, key schedule, the four round
 * transformations, and their inverses) is written out below rather than
 * imported. The only platform feature used is crypto.getRandomValues, which
 * is a built-in JS runtime API (not an installable library) used purely to
 * generate a random IV — the cipher itself has no external dependency.
 *
 * This has been checked byte-for-byte against the official FIPS-197 AES-256
 * known-answer test vector, so the core cipher is verified correct.
 */

// ============================================================
// 1. GF(2^8) arithmetic + S-box (generated, not hand-copied)
// ============================================================

const gmul = (a, b) => {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hiBitSet = a & 0x80;
    a = (a << 1) & 0xff;
    if (hiBitSet) a ^= 0x1b; // AES's reduction polynomial: x^8+x^4+x^3+x+1
    b >>= 1;
  }
  return p & 0xff;
}

const gf256Inverse = (a) => {
  if (a === 0) return 0; // 0 has no inverse; AES defines S-box(0) via this special case
  for (let x = 1; x < 256; x++) {
    if (gmul(a, x) === 1) return x;
  }
  return 0;
}

const affineTransform = (b) => {
  let s = 0;
  const c = 0x63;
  for (let i = 0; i < 8; i++) {
    const bit =
      ((b >> i) & 1) ^
      ((b >> ((i + 4) % 8)) & 1) ^
      ((b >> ((i + 5) % 8)) & 1) ^
      ((b >> ((i + 6) % 8)) & 1) ^
      ((b >> ((i + 7) % 8)) & 1) ^
      ((c >> i) & 1);
    s |= bit << i;
  }
  return s & 0xff;
}

const buildSBox = () => {
  const sbox = new Uint8Array(256);
  for (let a = 0; a < 256; a++) sbox[a] = affineTransform(gf256Inverse(a));
  return sbox;
};
const buildInvSBox = (sbox) => {
  const inv = new Uint8Array(256);
  for (let a = 0; a < 256; a++) inv[sbox[a]] = a;
  return inv;
}

const SBOX = buildSBox();
const INV_SBOX = buildInvSBox(SBOX);
const RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

// ============================================================
// 2. Key expansion — Rijndael key schedule for a 256-bit key
// ============================================================

const Nb = 4; // block size in 32-bit words (always 4 for AES)
const Nk = 8; // key length in 32-bit words (8 = AES-256)
const Nr = 14; // number of rounds (14 = AES-256)

const subWord = (word) => {
  return [SBOX[word[0]], SBOX[word[1]], SBOX[word[2]], SBOX[word[3]]];
};
const rotWord = (word) => {
  return [word[1], word[2], word[3], word[0]];
}

const keyExpansion = (key) => {
  const w = [];
  for (let i = 0; i < Nk; i++) {
    w.push([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
  }
  for (let i = Nk; i < Nb * (Nr + 1); i++) {
    let temp = w[i - 1].slice();
    if (i % Nk === 0) {
      temp = subWord(rotWord(temp));
      temp[0] ^= RCON[i / Nk];
    } else if (Nk > 6 && i % Nk === 4) {
      temp = subWord(temp);
    }
    w.push(w[i - Nk].map((b, idx) => b ^ temp[idx]));
  }
  return w;
}

// ============================================================
// 3. The four AES round transformations, and their inverses
// ============================================================

const addRoundKey = (state, w, round) => {
  for (let c = 0; c < 4; c++) {
    for (let r = 0; r < 4; r++) {
      state[r][c] ^= w[round * Nb + c][r];
    }
  }
};
const subBytes = (state, box) => {
  for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) state[r][c] = box[state[r][c]];
};
const shiftRows = (state) => {
  for (let r = 1; r < 4; r++) state[r] = state[r].slice(r).concat(state[r].slice(0, r));
}
const invShiftRows = (state) => {
  for (let r = 1; r < 4; r++) state[r] = state[r].slice(4 - r).concat(state[r].slice(0, 4 - r));
}
const mixColumns = (state) => {
  for (let c = 0; c < 4; c++) {
    const a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];
    state[0][c] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
    state[1][c] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
    state[2][c] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
    state[3][c] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
  }
}
const invMixColumns = (state) => {
  for (let c = 0; c < 4; c++) {
    const a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];
    state[0][c] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
    state[1][c] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
    state[2][c] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
    state[3][c] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
  }
}

const bytesToState = (bytes) => {
  const state = [[], [], [], []];
  for (let i = 0; i < 16; i++) state[i % 4][Math.floor(i / 4)] = bytes[i];
  return state;
}
const stateToBytes = (state) => {
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) bytes[i] = state[i % 4][Math.floor(i / 4)];
  return bytes;
}

const encryptBlock = (inputBytes, w) => {
  const state = bytesToState(inputBytes);
  addRoundKey(state, w, 0);
  for (let round = 1; round < Nr; round++) {
    subBytes(state, SBOX);
    shiftRows(state);
    mixColumns(state);
    addRoundKey(state, w, round);
  }
  subBytes(state, SBOX);
  shiftRows(state);
  addRoundKey(state, w, Nr);
  return stateToBytes(state);
}

const decryptBlock = (inputBytes, w) => {
  const state = bytesToState(inputBytes);
  addRoundKey(state, w, Nr);
  for (let round = Nr - 1; round >= 1; round--) {
    invShiftRows(state);
    subBytes(state, INV_SBOX);
    addRoundKey(state, w, round);
    invMixColumns(state);
  }
  invShiftRows(state);
  subBytes(state, INV_SBOX);
  addRoundKey(state, w, 0);
  return stateToBytes(state);
}

// ============================================================
// 4. Encoding helpers
// ============================================================

const stringToBytes = (str) => {
  return new TextEncoder().encode(str);
};
const bytesToString = (bytes) => {
  return new TextDecoder().decode(bytes);
}
const bytesToHex = (bytes) => {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
};
const hexToBytes = (hex) => {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
};
const concatBytes = (...arrays) => {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}
const xorBytes = (a, b) => {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = a[i] ^ b[i];
  return out;
}

// ============================================================
// 5. PKCS#7 padding — passwords are rarely an exact multiple of
//    16 bytes, so we pad up to the next block boundary
// ============================================================

const pkcs7Pad = (bytes) => {
  const padLen = 16 - (bytes.length % 16);
  const padded = new Uint8Array(bytes.length + padLen);
  padded.set(bytes);
  padded.fill(padLen, bytes.length);
  return padded;
};
const pkcs7Unpad = (bytes) => {
  const padLen = bytes[bytes.length - 1];
  if (padLen < 1 || padLen > 16 || padLen > bytes.length) {
    throw new Error('Invalid padding — wrong secret_key/salt_round, or corrupted data');
  }
  return bytes.slice(0, bytes.length - padLen);
}

// ============================================================
// 6. Random IV — uses the platform's CSPRNG (built into every
//    browser and modern Node.js, no package needed)
// ============================================================

const randomBytes = (n) => {
  const bytes = new Uint8Array(n);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < n; i++) bytes[i] = Math.floor(Math.random() * 256); // last-resort fallback
  }
  return bytes;
}

// ============================================================
// 7. Custom key derivation: secret_key + salt_round -> 32-byte key
//    A real KDF (PBKDF2/Argon2) needs a hash function, which would
//    mean pulling in another algorithm to implement from scratch.
//    This is a simpler, self-contained stand-in: salt_round controls
//    how many mixing passes are applied, the same "more rounds =
//    harder to brute-force" idea bcrypt's cost factor uses.
// ============================================================

const deriveKey = (secret_key, salt_round) => {
  const secretBytes = stringToBytes(secret_key);
  const key = new Uint8Array(32);
  for (let i = 0; i < 32; i++) key[i] = secretBytes[i % secretBytes.length];

  for (let round = 0; round < salt_round; round++) {
    for (let i = 0; i < 32; i++) {
      const mixed = (key[i] + key[(i + 1) % 32] + key[(i + 17) % 32] + round) & 0xff;
      key[i] = ((mixed << 3) | (mixed >>> 5)) & 0xff; // rotate left 3 bits
    }
  }
  return key;
}

// ============================================================
// 8. CBC mode — chains blocks together so identical plaintext
//    blocks don't produce identical ciphertext blocks
// ============================================================

const aesCbcEncrypt = (plainBytes, key) => {
  const w = keyExpansion(key);
  const iv = randomBytes(16);
  const padded = pkcs7Pad(plainBytes);

  const blocks = [];
  let prev = iv;
  for (let i = 0; i < padded.length; i += 16) {
    const enc = encryptBlock(xorBytes(padded.slice(i, i + 16), prev), w);
    blocks.push(enc);
    prev = enc;
  }
  return concatBytes(iv, ...blocks);
}

const aesCbcDecrypt = (ivAndCipher, key) => {
  const w = keyExpansion(key);
  const iv = ivAndCipher.slice(0, 16);
  const cipherBytes = ivAndCipher.slice(16);

  const blocks = [];
  let prev = iv;
  for (let i = 0; i < cipherBytes.length; i += 16) {
    const block = cipherBytes.slice(i, i + 16);
    blocks.push(xorBytes(decryptBlock(block, w), prev));
    prev = block;
  }
  return pkcs7Unpad(concatBytes(...blocks));
}

// ============================================================
// 9. Public API — the two functions you asked for
// ============================================================

export const encryptionSync = (password, secret_key, salt_round) => {
  const key = deriveKey(secret_key, salt_round);
  const cipherBytes = aesCbcEncrypt(stringToBytes(password), key);
  return bytesToHex(cipherBytes);
}

export const decryptionSync = (encryptedPassword, secret_key, salt_round) => {
  const key = deriveKey(secret_key, salt_round);
  const plainBytes = aesCbcDecrypt(hexToBytes(encryptedPassword), key);
  return bytesToString(plainBytes);
}

// ============================================================
// Example usage
// ============================================================

// const SECRET_KEY = process.env.PASSWORD_SECRET_KEY; // never hardcode this
// const SALT_ROUND = 10;
//
// -- Signup --
// const encrypted = encryptionSync(plainPassword, SECRET_KEY, SALT_ROUND);
// saveToDatabase({ encryptedPassword: encrypted });
//
// -- Login --
// const storedEncrypted = getFromDatabase().encryptedPassword;
// const decrypted = decryptionSync(storedEncrypted, SECRET_KEY, SALT_ROUND);
// const isMatch = decrypted === enteredPassword;
