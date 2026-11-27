import { Buffer } from "node:buffer";

import { randomBytes } from "@noble/ciphers/webcrypto";
import { describe, expect, it } from "vitest";

import { chacha20 as _chacha20, xchacha20 as _xchacha20 } from "../../src/chacha/noble";
import { chacha20, xchacha20 } from "../../src/chacha/node";
import { hello, ResizableArrayBuffer, type ResizableBuffer, testRandom } from "../common";

describe("test random", () => {
  function test(
    nobleFunc: typeof _chacha20 | typeof _xchacha20,
    compatFunc: typeof chacha20 | typeof xchacha20,
    nonceLength: number,
    aad?: Uint8Array
  ) {
    const key = randomBytes();
    const nonce = randomBytes(nonceLength);
    const noble = nobleFunc(key, nonce, aad);
    const compat = compatFunc(key, nonce, aad);
    testRandom(hello, noble, compat);
  }

  function testError(
    compatFunc: typeof chacha20 | typeof xchacha20,
    nonceLength: number,
    expectedError: string
  ) {
    const key = randomBytes();
    const nonce = randomBytes(nonceLength);
    expect(() => compatFunc(key, nonce)).toThrowError(expectedError);
  }

  function testChacha20(aad?: Uint8Array) {
    test(_chacha20, chacha20, 12, aad);
  }

  function testXChacha20(aad?: Uint8Array) {
    test(_xchacha20, xchacha20, 24, aad);
  }

  it("tests chacha20", () => {
    testChacha20();
    testChacha20(randomBytes(8));
    testChacha20(randomBytes(16));

    testError(chacha20, 24, "chacha20's nonce must be 12 bytes");
  });

  it("tests xchacha20", () => {
    testXChacha20();
    testXChacha20(randomBytes(8));
    testXChacha20(randomBytes(16));

    testError(xchacha20, 12, "xchacha20's nonce must be 24 bytes");
  });

  it("reads xchacha20's key and nonce at each call, as noble does", () => {
    const key = randomBytes();
    const nonce = randomBytes(24);
    const noble = _xchacha20(key, nonce);
    const compat = xchacha20(key, nonce);

    // both halves of the nonce: the first 16 bytes go into the subkey, the last 8 into the
    // chacha20 nonce
    key.set(randomBytes());
    nonce.set(randomBytes(24));
    expect(compat.encrypt(hello)).toStrictEqual(noble.encrypt(hello));
  });

  it("rejects an xchacha20 key that isn't 32 bytes at each call, as noble does (#15)", () => {
    const nonce = randomBytes(24);
    const sealed = xchacha20(randomBytes(), nonce).encrypt(hello);
    for (const length of [0, 16, 31, 33, 64]) {
      const key = randomBytes(length);
      const noble = _xchacha20(key, nonce);
      const compat = xchacha20(key, nonce);
      expect(() => compat.encrypt(hello)).toThrowError("xchacha20's key must be 32 bytes");
      expect(() => compat.decrypt(sealed)).toThrowError("xchacha20's key must be 32 bytes");
      expect(() => noble.encrypt(hello)).toThrowError("invalid 32-byte key");
    }
  });

  it("rejects an xchacha20 nonce that is no longer 24 bytes at each call, as noble does (#21)", () => {
    const key = randomBytes();
    const sealed = xchacha20(key, randomBytes(24)).encrypt(hello);
    const error = "xchacha20's nonce must be 24 bytes";
    const changes = [
      (buffer: ResizableBuffer) => buffer.resize(20),
      (buffer: ResizableBuffer) => buffer.resize(0),
      (buffer: ResizableBuffer) => buffer.resize(28),
      (buffer: ResizableBuffer) => buffer.transfer(), // detaches it
    ];
    for (const change of changes) {
      const buffer = new ResizableArrayBuffer(24, { maxByteLength: 28 });
      const nonce = new Uint8Array(buffer); // 24 bytes at construction, then whatever the buffer holds
      nonce.set(randomBytes(24));
      const noble = _xchacha20(key, nonce);
      const compat = xchacha20(key, nonce);
      change(buffer);
      expect(() => compat.encrypt(hello)).toThrowError(error);
      expect(() => compat.decrypt(sealed)).toThrowError(error);
      expect(() => noble.encrypt(hello)).toThrowError("extended nonce must be 24 bytes");
    }
  });

  it("takes an xchacha20 key and nonce at any byteOffset, as noble does (#16)", () => {
    // as when both are sliced out of a larger buffer, such as a payload
    for (let keyOffset = 0; keyOffset <= 4; keyOffset++) {
      for (let nonceOffset = 0; nonceOffset <= 4; nonceOffset++) {
        const key = randomBytes(keyOffset + 32).subarray(keyOffset);
        const nonce = randomBytes(nonceOffset + 24).subarray(nonceOffset);
        testRandom(hello, _xchacha20(key, nonce), xchacha20(key, nonce));
      }
    }
  });

  it("takes xchacha20 Buffers at any byteOffset, as Node callers pass them (#16)", () => {
    // a Buffer's slice() returns a view, not a copy, so aligning by slice() would still throw here
    for (let keyOffset = 0; keyOffset <= 4; keyOffset++) {
      for (let nonceOffset = 0; nonceOffset <= 4; nonceOffset++) {
        const key = Buffer.from(randomBytes(keyOffset + 32)).subarray(keyOffset);
        const nonce = Buffer.from(randomBytes(nonceOffset + 24)).subarray(nonceOffset);
        testRandom(hello, _xchacha20(key, nonce), xchacha20(key, nonce));
      }
    }
  });
});
