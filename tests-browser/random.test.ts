import { aes256cbc, aes256gcm } from "@ecies/ciphers/aes";
import { xchacha20 } from "@ecies/ciphers/chacha";
import { randomBytes } from "@noble/ciphers/webcrypto";

import { describe, expect, it } from "vitest";

const TEXT = "hello browser🌍!";
const encoder = new TextEncoder();
const data = encoder.encode(TEXT);

describe("test random", () => {
  function checkCipher(
    callback: typeof aes256gcm | typeof aes256cbc | typeof xchacha20,
    key: Uint8Array,
    nonce: Uint8Array,
    aad?: Uint8Array
  ) {
    const cipher = callback(key, nonce, aad);
    expect(cipher.decrypt(cipher.encrypt(data))).toStrictEqual(data);
  }

  it("tests aes gcm", () => {
    checkCipher(aes256gcm, randomBytes(32), randomBytes(16), randomBytes(8));
    checkCipher(aes256gcm, randomBytes(32), randomBytes(12), randomBytes(8));
  });

  it("tests aes cbc", () => {
    const key = randomBytes();
    const nonce = randomBytes(16);
    checkCipher(aes256cbc, key, nonce);
  });

  it("tests xchacha20", () => {
    const key = randomBytes();
    const nonce = randomBytes(24);
    const aad = randomBytes(8);
    checkCipher(xchacha20, key, nonce, aad);
  });
});
