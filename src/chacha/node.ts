import { type Cipher, u8, u32 } from "@noble/ciphers/utils";

import { _checkAAD, _checkBytes, _compat, _encryptOnce } from "../_node/compat.js";
import { _hchacha20 } from "../_node/hchacha.js";

export const xchacha20 = (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): Cipher => {
  _checkBytes(key, nonce);
  if (nonce.length !== 24) {
    throw new Error("xchacha20's nonce must be 24 bytes");
  }
  _checkAAD(AAD); // here, since _compat, which checks the data too, runs only at each call
  // the subkey decrypts the message on its own, so each call derives one and wipes it once the
  // cipher is done with it; like noble, each call checks and reads the key and the whole nonce
  // afresh, since a view over a resizable or detached buffer can change length after construction
  const withSubKey = <T>(use: (cipher: Cipher) => T): T => {
    if (key.length !== 32) {
      throw new Error("xchacha20's key must be 32 bytes");
    }
    if (nonce.length !== 24) {
      throw new Error("xchacha20's nonce must be 24 bytes");
    }
    const constants = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]); // "expand 32-byte k"
    const subKey = new Uint32Array(8);
    try {
      // u32 views need a byteOffset that's a multiple of 4, so the key and the nonce are copied
      // into arrays of their own; as in noble, _hchacha20 reads the key before it writes the
      // subkey over it
      u8(subKey).set(key);
      _hchacha20(constants, subKey, u32(Uint8Array.from(nonce.subarray(0, 16))), subKey);
      const subNonce = new Uint8Array(12); // 4 zero bytes, then the nonce's last 8
      subNonce.set(nonce.subarray(16), 4);
      return use(_compat("chacha20-poly1305", u8(subKey), subNonce, AAD));
    } finally {
      subKey.fill(0);
    }
  };

  // each call makes a chacha20 cipher of its own, so the guard goes here
  return {
    encrypt: _encryptOnce((plainText) => withSubKey((cipher) => cipher.encrypt(plainText))),
    decrypt: (cipherText: Uint8Array) => withSubKey((cipher) => cipher.decrypt(cipherText)),
  };
};

export const chacha20 = (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): Cipher => {
  _checkBytes(key, nonce); // before reading the nonce's length, as noble does
  if (nonce.length !== 12) {
    throw new Error("chacha20's nonce must be 12 bytes");
  }
  return _compat("chacha20-poly1305", key, nonce, AAD);
};
