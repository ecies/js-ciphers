import { Cipher, concatBytes } from "@noble/ciphers/utils";
import { CipherGCM, createCipheriv, createDecipheriv, DecipherGCM } from "node:crypto";

const AEAD_TAG_LENGTH = 16;

// make `node:crypto`'s aes compatible with `@noble/ciphers`
const _compat = (
  algorithm: "aes-256-gcm" | "aes-256-cbc",
  key: Uint8Array,
  nonce: Uint8Array,
  AAD?: Uint8Array
): Cipher => {
  const isAEAD = algorithm === "aes-256-gcm";
  const tagLength = isAEAD ? AEAD_TAG_LENGTH : 0;

  const encrypt = (plainText: Uint8Array) => {
    const cipher = createCipheriv(algorithm, key, nonce);
    if (isAEAD && AAD) {
      (cipher as CipherGCM).setAAD(AAD);
    }

    const updated = cipher.update(plainText);
    const finalized = cipher.final();
    if (isAEAD) {
      return concatBytes(updated, finalized, (cipher as CipherGCM).getAuthTag());
    }
    return concatBytes(updated, finalized);
  };

  const decrypt = (cipherText: Uint8Array) => {
    const encrypted = cipherText.subarray(0, cipherText.length - tagLength);
    const tag = cipherText.subarray(cipherText.length - tagLength);

    const decipher = createDecipheriv(algorithm, key, nonce);
    if (isAEAD) {
      if (AAD) {
        (decipher as DecipherGCM).setAAD(AAD);
      }
      (decipher as DecipherGCM).setAuthTag(tag);
    }
    const updated = decipher.update(encrypted);
    const finalized = decipher.final();
    return concatBytes(updated, finalized);
  };

  return {
    encrypt,
    decrypt,
  };
};

export const aes256gcm = (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): Cipher =>
  _compat("aes-256-gcm", key, nonce, AAD);

export const aes256cbc = (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): Cipher =>
  _compat("aes-256-cbc", key, nonce);
