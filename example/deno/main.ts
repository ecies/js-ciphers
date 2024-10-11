import { aes256gcm } from "@ecies/ciphers";
import { randomBytes } from "@noble/ciphers/webcrypto";

const TEXT = "helloworld🌍";
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const msg = encoder.encode(TEXT);

const key = randomBytes();
const nonce = randomBytes(16);
const cipher = aes256gcm(key, nonce);
console.log("decrypted:", decoder.decode(cipher.decrypt(cipher.encrypt(msg))));
