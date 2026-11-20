type Sha256 = (bytes: Uint8Array) => Uint8Array;

export const sha256: Sha256;

export function pbkdf2(
  hash: Sha256,
  password: Uint8Array,
  salt: Uint8Array,
  options: { c: number; dkLen: number },
): Generator<unknown, Uint8Array>;

export function gcm(key: Uint8Array, iv: Uint8Array): {
  encrypt(bytes: Uint8Array): Uint8Array;
  decrypt(bytes: Uint8Array): Uint8Array;
};
