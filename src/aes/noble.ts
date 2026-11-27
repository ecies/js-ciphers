import { cbc, gcm } from "@noble/ciphers/aes";
import type { Cipher, CipherWithOutput } from "@noble/ciphers/utils";

// noble's gcm and cbc take a 16- or 24-byte key too, and run AES-128 or AES-192 with it; like
// node:crypto's aes-256, these take only 32 bytes. Like both, each call checks the key's length,
// since a view over a resizable or detached buffer can change length after construction.
const only256 = (name: string, key: Uint8Array, cipher: Cipher): Cipher => {
  const checkKey = () => {
    if (key.length !== 32) {
      throw new Error(`${name}'s key must be 32 bytes`);
    }
  };
  // noble marks its cipher used before it checks the key's length, so a call that checkKey
  // refuses, before noble's own guard runs, uses the cipher up too
  let encrypted = false;
  // noble's cbc writes into an output buffer, if given one, and its gcm refuses one
  return {
    encrypt: (plainText: Uint8Array, output?: Uint8Array) => {
      if (encrypted) {
        throw new Error("cannot encrypt() twice with same key + nonce");
      }
      encrypted = true;
      checkKey();
      return (cipher as CipherWithOutput).encrypt(plainText, output);
    },
    decrypt: (cipherText: Uint8Array, output?: Uint8Array) => {
      checkKey();
      return (cipher as CipherWithOutput).decrypt(cipherText, output);
    },
  };
};

export const aes256gcm = (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): Cipher =>
  only256("aes256gcm", key, gcm(key, nonce, AAD));

export const aes256cbc = (key: Uint8Array, nonce: Uint8Array, _AAD?: Uint8Array): Cipher =>
  only256("aes256cbc", key, cbc(key, nonce));
