import { describe, expect, it } from "vitest";

import { randomBytes } from "@noble/ciphers/webcrypto";

import { xchacha20 as _xchacha20 } from "../../src/chacha/noble";
import { xchacha20 } from "../../src/chacha/node";
import { hello, testRandom } from "../common";

describe("test random", () => {
  function testXChacha20(aad?: Uint8Array) {
    const key = randomBytes();
    const nonce = randomBytes(24);
    const noble = _xchacha20(key, nonce, aad);
    const compat = xchacha20(key, nonce, aad);
    testRandom(hello, noble, compat);
  }

  function testXChacha20Error() {
    const key = randomBytes();
    expect(() => xchacha20(key, randomBytes(12))).toThrowError(
      "xchacha20's nonce must be 24 bytes"
    );
  }

  it("tests xchacha20", () => {
    testXChacha20();
    testXChacha20(randomBytes(8));
    testXChacha20(randomBytes(16));
    testXChacha20Error();
  });
});
