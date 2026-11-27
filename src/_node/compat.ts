// biome-ignore-all lint/suspicious/noExplicitAny: hide type error
import {
  type CipherGCM,
  createCipheriv,
  createDecipheriv,
  type DecipherGCM,
} from "node:crypto";
import { type Cipher, concatBytes } from "@noble/ciphers/utils";

const AEAD_TAG_LENGTH = 16;

// noble's isBytes (@noble/ciphers 1.3.0, utils.js:39-41), which utils exports only from 1.3.0:
// a Buffer passes, and so does a Uint8Array from another realm
const isBytes = (a: unknown): a is Uint8Array =>
  a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array");

/**
 * reject a key or nonce that isn't a Uint8Array, as noble does: `node:crypto` would read a string
 * as UTF-8, and xchacha20 would read a string's letters as zero bytes.
 */
export const _checkBytes = (key: Uint8Array, nonce: Uint8Array): void => {
  if (!isBytes(key)) {
    throw new Error("key must be a Uint8Array");
  }
  if (!isBytes(nonce)) {
    throw new Error("nonce must be a Uint8Array");
  }
};

/**
 * let a cipher encrypt once, as noble does: a second message under the same key and nonce
 * would reuse the keystream, or for cbc show whether the two start alike. Like noble, the
 * first call uses the cipher up even if it throws.
 */
export const _encryptOnce = (
  encrypt: (plainText: Uint8Array) => Uint8Array
): ((plainText: Uint8Array) => Uint8Array) => {
  let encrypted = false;
  return (plainText: Uint8Array) => {
    if (encrypted) {
      throw new Error("cannot encrypt() twice with the same key and nonce");
    }
    encrypted = true;
    return encrypt(plainText);
  };
};

/**
 * make `node:crypto`'s ciphers compatible with `@noble/ciphers`.
 *
 * `Cipher`'s interface is the same for both `aes-256-gcm` and `chacha20-poly1305`,
 * albeit the latter is one of `CipherCCMTypes`.
 * Interestingly, whether to set `plaintextLength` or not, or which value to set, has no actual effect.
 */
export const _compat = (
  algorithm: "aes-256-gcm" | "aes-256-cbc" | "chacha20-poly1305",
  key: Uint8Array,
  nonce: Uint8Array,
  AAD?: Uint8Array
): Cipher => {
  _checkBytes(key, nonce);
  const isAEAD = algorithm === "aes-256-gcm" || algorithm === "chacha20-poly1305";
  const authTagLength = isAEAD ? AEAD_TAG_LENGTH : 0;
  // authTagLength is necessary for `chacha20-poly1305` before Node v16.17
  const options = isAEAD ? { authTagLength } : undefined;

  const encrypt = (plainText: Uint8Array) => {
    const cipher = createCipheriv(algorithm, key, nonce, options as any);
    if (isAEAD && AAD !== undefined) {
      (cipher as CipherGCM).setAAD(AAD);
    }

    const updated = cipher.update(plainText);
    const finalized = cipher.final();
    const tag = isAEAD ? (cipher as CipherGCM).getAuthTag() : new Uint8Array(0);
    return concatBytes(updated, finalized, tag);
  };

  const decrypt = (cipherText: Uint8Array) => {
    const rawCipherText = cipherText.subarray(0, cipherText.length - authTagLength);
    const tag = cipherText.subarray(cipherText.length - authTagLength);

    const decipher = createDecipheriv(algorithm, key, nonce, options as any);
    if (isAEAD) {
      if (AAD !== undefined) {
        (decipher as DecipherGCM).setAAD(AAD);
      }
      (decipher as DecipherGCM).setAuthTag(tag);
    }

    // node:crypto's Buffers hold the plaintext, or the unauthenticated plaintext when final()
    // throws: wipe them once copied, since the caller can only wipe the copy it gets back.
    // Only the views are wiped, since runtimes pool small Buffers and the memory past a view
    // may belong to another. Bun 1.2.21's aes-256-cbc update() leaves up to a block of
    // plaintext there; Bun 1.4.5's doesn't.
    const updated = decipher.update(rawCipherText);
    let finalized: Uint8Array | undefined;
    try {
      finalized = decipher.final();
      return concatBytes(updated, finalized);
    } finally {
      updated.fill(0);
      finalized?.fill(0);
    }
  };

  return {
    encrypt: _encryptOnce(encrypt),
    decrypt,
  };
};
