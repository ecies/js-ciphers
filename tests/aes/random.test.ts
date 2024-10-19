import { describe, it } from "vitest";

import { randomBytes } from "@noble/ciphers/webcrypto";

import { aes256cbc as _aes256cbc, aes256gcm as _aes256gcm } from "../../src/aes/noble";
import { aes256cbc, aes256gcm } from "../../src/aes/node";
import { hello, testRandom } from "../common";

describe("test random", () => {
  function testGcm(nonceLength: number, aad?: Uint8Array) {
    const key = randomBytes();
    const nonce = randomBytes(nonceLength);
    const noble = _aes256gcm(key, nonce, aad);
    const compat = aes256gcm(key, nonce, aad);
    testRandom(hello, noble, compat);
  }

  function testCbc() {
    const key = randomBytes();
    const nonce = randomBytes(16);
    const noble = _aes256cbc(key, nonce);
    const compat = aes256cbc(key, nonce);
    testRandom(hello, noble, compat);
  }

  it("tests gcm", () => {
    testGcm(16);
    testGcm(16, randomBytes(8));
    testGcm(16, randomBytes(16));

    testGcm(12);
    testGcm(12, randomBytes(8));
    testGcm(12, randomBytes(16));
  });

  it("tests cbc", () => {
    testCbc();
  });
});
