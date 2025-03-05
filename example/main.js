import { aes256cbc, aes256gcm } from "@ecies/ciphers/aes";
import { xchacha20 } from "@ecies/ciphers/chacha";

import { randomBytes } from "@noble/ciphers/webcrypto";

const TEXT = "hello world🌍!";
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const msg = encoder.encode(TEXT);

const ciphers = [
  {
    keyLength: 32,
    nonceLength: 16,
    callback: aes256gcm,
    aad: randomBytes(16),
  },
  {
    keyLength: 32,
    nonceLength: 12,
    callback: aes256gcm,
    aad: randomBytes(16),
  },
  {
    keyLength: 32,
    nonceLength: 16,
    callback: aes256cbc,
    aad: undefined,
  },
  {
    keyLength: 32,
    nonceLength: 24,
    callback: xchacha20,
    aad: randomBytes(16),
  },
];

for (const { keyLength, nonceLength, callback, aad } of ciphers) {
  const key = randomBytes(keyLength);
  const nonce = randomBytes(nonceLength);
  console.log(`${callback.name} (nonce length ${nonce.length}) decrypted:`);
  const cipher = callback(key, nonce, aad);
  console.log(decoder.decode(cipher.decrypt(cipher.encrypt(msg))));
}
