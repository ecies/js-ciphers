import { chacha20poly1305, xchacha20poly1305 } from "@noble/ciphers/chacha";
import { Cipher } from "@noble/ciphers/utils";

export const xchacha20 = (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): Cipher =>
  xchacha20poly1305(key, nonce, AAD);

export const chacha20 = (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array): Cipher =>
  chacha20poly1305(key, nonce, AAD);
