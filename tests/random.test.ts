import { describe, expect, it } from "vitest";

import { Cipher } from "@noble/ciphers/utils";
import { randomBytes } from "@noble/ciphers/webcrypto";

import { aes256cbc as _aes256cbc, aes256gcm as _aes256gcm } from "../src/noble";
import { aes256cbc, aes256gcm } from "../src/node";

const TEXT = "helloworld🌍";
const encoder = new TextEncoder();

describe("test random", () => {
  const msg = encoder.encode(TEXT);

  function testCipher(noble: Cipher, compat: Cipher) {
    // same encryption
    expect(noble.encrypt(msg)).toStrictEqual(compat.encrypt(msg));
    // noble encrypts, compat decrypts
    expect(compat.decrypt(noble.encrypt(msg))).toStrictEqual(msg);
    // noble decrypts, compat encrypts
    expect(noble.decrypt(compat.encrypt(msg))).toStrictEqual(msg);
  }

  function testGcm(aad?: Uint8Array) {
    const key = randomBytes();
    const nonce = randomBytes(16);
    const noble = _aes256gcm(key, nonce, aad);
    const compat = aes256gcm(key, nonce, aad);
    testCipher(noble, compat);
  }

  function testCbc() {
    const key = randomBytes();
    const nonce = randomBytes(16);
    const noble = _aes256cbc(key, nonce);
    const compat = aes256cbc(key, nonce);
    testCipher(noble, compat);
  }

  it("tests gcm", () => {
    testGcm();
    testGcm(randomBytes(8));
    testGcm(randomBytes(16));
  });

  it("tests cbc", () => {
    testCbc();
  });
});
