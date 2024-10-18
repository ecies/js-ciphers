import { cbc, gcm } from "@noble/ciphers/aes";
import { Cipher } from "@noble/ciphers/utils";

export const aes256gcm = (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): Cipher =>
  gcm(key, nonce, AAD);

export const aes256cbc = (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): Cipher =>
  cbc(key, nonce);
