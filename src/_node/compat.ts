import { Cipher, concatBytes } from "@noble/ciphers/utils";
import { CipherGCM, createCipheriv, createDecipheriv, DecipherGCM } from "node:crypto";

const AEAD_TAG_LENGTH = 16;

// @ts-ignore: only necessary for deno
const IS_DENO = globalThis.Deno !== undefined;

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

    /* v8 ignore next 3 */
    if (!isAEAD && IS_DENO) {
      decipher.setAutoPadding(false); // See: https://github.com/denoland/deno/issues/28381
    }

    const updated = decipher.update(rawCipherText);
    const finalized = decipher.final();
    return concatBytes(updated, finalized);
  };

  return {
    encrypt,
    decrypt,
  };
};
