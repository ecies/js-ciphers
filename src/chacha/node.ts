import { type Cipher, u8, u32 } from "@noble/ciphers/utils";

import { _compat } from "../_node/compat.js";
import { _hchacha20 } from "../_node/hchacha.js";

export const xchacha20 = (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): Cipher => {
  if (nonce.length !== 24) {
    throw new Error("xchacha20's nonce must be 24 bytes");
  }
  const subNonce = new Uint8Array(12);
  subNonce.set([0, 0, 0, 0]);
  subNonce.set(nonce.subarray(16), 4);

  // the subkey decrypts the message on its own, so each call derives one and wipes it once the
  // cipher is done with it
  const withSubKey = <T>(use: (cipher: Cipher) => T): T => {
    const constants = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]); // "expand 32-byte k"
    const subKey = new Uint32Array(8);
    _hchacha20(constants, u32(key), u32(nonce.subarray(0, 16)), subKey);
    try {
      return use(_compat("chacha20-poly1305", u8(subKey), subNonce, AAD));
    } finally {
      subKey.fill(0);
    }
  };

  return {
    encrypt: (plainText: Uint8Array) => withSubKey((cipher) => cipher.encrypt(plainText)),
    decrypt: (cipherText: Uint8Array) => withSubKey((cipher) => cipher.decrypt(cipherText)),
  };
};

export const chacha20 = (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): Cipher => {
  if (nonce.length !== 12) {
    throw new Error("chacha20's nonce must be 12 bytes");
  }
  return _compat("chacha20-poly1305", key, nonce, AAD);
};
