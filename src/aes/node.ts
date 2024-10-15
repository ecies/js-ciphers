import { Cipher } from "@noble/ciphers/utils";

import { _compat } from "../_node/compat";

export const aes256gcm = (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): Cipher =>
  _compat("aes-256-gcm", key, nonce, AAD);

export const aes256cbc = (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): Cipher =>
  _compat("aes-256-cbc", key, nonce);
