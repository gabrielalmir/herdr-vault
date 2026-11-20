// Adapted from the herdr-music-mod credential vault. See THIRD-PARTY.txt.
import { randomBytes, webcrypto } from "crypto";
import { gcm, pbkdf2, sha256 } from "./vault-crypto.js";

// Herdr exposes indexed bytes, but its Buffer base64 conversion can return "".
export function url64(bytes) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let result = "", bits = 0, pending = 0;
  for (const byte of bytes) {
    pending = (pending << 8) | byte;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      result += alphabet[(pending >>> bits) & 63];
    }
  }
  if (bits) result += alphabet[(pending << (6 - bits)) & 63];
  return result;
}
export function generateVaultCode() {
  const code = url64(randomBytes(24));
  if (code.length !== 32) throw new Error("Secure random generation unavailable.");
  return code;
}
export const vaultIterations = generated => generated ? 1 : 600000;
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2,"0")).join("");
function fromHex(value) {
  if (typeof value !== "string" || !/^(?:[a-f0-9]{2})+$/.test(value)) throw Error("Invalid vault data.");
  return Uint8Array.from(value.match(/../g), b => parseInt(b,16));
}
function utf8(value) {
  const bytes=[];
  for (const part of encodeURIComponent(value).match(/%[A-F0-9]{2}|./g) || [])
    bytes.push(part.length===3 ? parseInt(part.slice(1),16) : part.charCodeAt(0));
  return Uint8Array.from(bytes);
}
export class VaultState {
  key = undefined;
  salt = undefined;
  closed = false;

  close() {
    this.key?.fill(0);
    this.key = undefined;
    this.salt = undefined;
    this.closed = true;
  }
}

function check(schedule, state) {
  schedule?.check?.();
  if (state?.closed) throw Error("Vault is closed.");
}

export async function keyFor(password, salt, iterations, schedule) {
  check(schedule);
  const bytes = utf8(password);
  let key;
  try {
    if (iterations > 1) {
      if (schedule?.derive) {
        key = await schedule.derive(bytes, salt, iterations);
      } else {
        try {
          const subtle = webcrypto?.subtle;
          if (subtle) {
            const material = await subtle.importKey("raw", bytes, "PBKDF2", false, ["deriveBits"]);
            const bits = await subtle.deriveBits({
              name: "PBKDF2", hash: "SHA-256", salt, iterations,
            }, material, 256);
            if (bits.byteLength === 32) key = new Uint8Array(bits);
          }
        } catch {
          // Some Herdr versions expose only part of Web Crypto.
        }
      }
    }
    check(schedule);
    if (!key) {
      const steps = pbkdf2(sha256, bytes, salt, { c: iterations, dkLen: 32 });
      const run = schedule?.steps ?? (typeof schedule === "function" ? schedule : undefined);
      if (run) {
        key = await run(steps);
      } else {
        let step = steps.next();
        while (!step.done) step = steps.next();
        key = step.value;
      }
    }
    check(schedule);
    if (key.length !== 32) throw Error("Invalid derived key.");
    return key;
  } catch (error) {
    key?.fill(0);
    throw error;
  } finally {
    bytes.fill(0);
  }
}

export async function seal(password, token, iterations = 600000, schedule, state) {
  check(schedule, state);
  const salt = state?.salt ?? Uint8Array.from(randomBytes(16));
  const iv = Uint8Array.from(randomBytes(12));
  const existing = state?.key;
  const key = existing ?? await keyFor(password, salt, iterations, schedule);
  try {
    check(schedule, state);
    const record = { version: 2, salt: hex(salt), iv: hex(iv), data: hex(gcm(key, iv).encrypt(utf8(token))) };
    if (state) Object.assign(state, { salt, key });
    return record;
  } finally {
    if (!existing && state?.key !== key) key.fill(0);
  }
}

function legacyBytes(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw Error("Invalid vault data.");
  }
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const bytes = [];
  let bits = 0;
  let pending = 0;
  for (const char of value.split("=")[0]) {
    pending = (pending << 6) | alphabet.indexOf(char);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((pending >>> bits) & 255);
    }
  }
  return Uint8Array.from(bytes);
}

export async function unseal(password, record, iterations = 600000, schedule, state, { legacy = false } = {}) {
  check(schedule, state);
  const decode = record?.version === 2 ? fromHex : legacy ? legacyBytes : undefined;
  if (!decode) throw Error("Invalid vault format.");
  const salt = decode(record.salt);
  const iv = decode(record.iv);
  const data = decode(record.data);
  if (salt.length !== 16 || iv.length !== 12 || data.length < 16) throw Error("Invalid vault format.");
  const key = await keyFor(password, salt, iterations, schedule);
  try {
    check(schedule, state);
    let value;
    try {
      const bytes = gcm(key, iv).decrypt(data);
      value = decodeURIComponent(Array.from(bytes, byte => "%" + byte.toString(16).padStart(2, "0")).join(""));
    } catch {
      throw Error("Incorrect password or damaged vault.");
    }
    if (state) {
      state.key?.fill(0);
      Object.assign(state, { salt, key });
    }
    return value;
  } finally {
    if (state?.key !== key) key.fill(0);
  }
}
export async function probe() {
  try {
    const sample = await seal("probe","ok",2);
    if (await unseal("probe",sample,2) !== "ok") return false;
    try { await unseal("wrong",sample,2); return false; } catch { return true; }
  } catch { return false; }
}

export function scheduleKey(cx, steps, onProgress, operation) {
  return new Promise((resolve, reject) => {
    const timer = cx.timer.every(1, tick => {
      try {
        operation?.check();
        const step = steps.next();
        if (step.done) {
          timer.cancel();
          timeout.cancel();
          resolve(step.value);
        } else {
          onProgress?.(step.value, tick);
        }
      } catch (error) {
        timer.cancel();
        timeout.cancel();
        reject(error);
      }
    });
    const timeout = cx.timer.after(120000, () => {
      timer.cancel();
      reject(new Error("Vault key derivation timed out. Try again or use a generated unlock code."));
    });
  });
}
