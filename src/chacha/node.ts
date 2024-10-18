import { Cipher, u32, u8 } from "@noble/ciphers/utils";

import { _compat } from "../_node/compat";
import { _hchacha } from "../_node/hchacha";

export const xchacha20 = (
  key: Uint8Array,
  nonce: Uint8Array,
  AAD?: Uint8Array
): Cipher => {
  if (nonce.length !== 24) {
    throw new Error("xchacha20's nonce must be 24 bytes");
  }
  const constants = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]); // "expand 32-byte k"
  const subKey = new Uint32Array(8);

  _hchacha(constants, u32(key), u32(nonce.subarray(0, 16)), subKey);

  const subNonce = new Uint8Array(12);
  subNonce.set([0, 0, 0, 0]);
  subNonce.set(nonce.subarray(16), 4);
  return _compat("chacha20-poly1305", u8(subKey), subNonce, AAD);
};
