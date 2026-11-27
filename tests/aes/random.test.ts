import { runInNewContext } from "node:vm";

import type { CipherWithOutput } from "@noble/ciphers/utils";
import { randomBytes } from "@noble/ciphers/webcrypto";
import { describe, expect, it } from "vitest";

import { aes256cbc as _aes256cbc, aes256gcm as _aes256gcm } from "../../src/aes/noble";
import { aes256cbc, aes256gcm } from "../../src/aes/node";
import { hello, ResizableArrayBuffer, type ResizableBuffer, testRandom } from "../common";

const ciphers = [
  { name: "aes256gcm", noble: _aes256gcm, node: aes256gcm, nonceLength: 12 },
  { name: "aes256cbc", noble: _aes256cbc, node: aes256cbc, nonceLength: 16 },
];

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

  it("hands noble an output buffer: cbc writes into it, gcm refuses it", () => {
    // in browsers and React Native; node:crypto's ciphers take no output buffer
    const key = randomBytes(32);
    const nonce = randomBytes(16);
    const sealed = new Uint8Array(32); // 16 bytes of hello, then a block of padding
    const cbc = _aes256cbc(key, nonce) as CipherWithOutput;
    expect(cbc.encrypt(hello, sealed)).toBe(sealed);
    expect(aes256cbc(key, nonce).decrypt(sealed)).toStrictEqual(hello);
    const opened = new Uint8Array(32);
    const plainText = cbc.decrypt(sealed, opened);
    expect(plainText.buffer).toBe(opened.buffer);
    expect(plainText).toStrictEqual(hello);
    const gcm = _aes256gcm(key, randomBytes(12)) as CipherWithOutput;
    expect(() => gcm.encrypt(hello, new Uint8Array(32))).toThrowError(
      "cipher output not supported"
    );
  });
});

// noble's gcm and cbc take a 16-, 24- or 32-byte key and run AES-128, AES-192 or AES-256 with it
// (@noble/ciphers 1.3.0, aes.js:99-103); node:crypto's aes-256 takes only 32 bytes
describe("takes only a 32-byte key, wherever it runs (#25)", () => {
  it.each(ciphers)("$name refuses a 16- or 24-byte key at each call", (c) => {
    const nonce = randomBytes(c.nonceLength);
    const sealed = c.node(randomBytes(32), nonce).encrypt(hello);
    for (const length of [16, 24]) {
      const key = randomBytes(length);
      const noble = c.noble(key, nonce);
      const compat = c.node(key, nonce);
      const error = `${c.name}'s key must be 32 bytes`;
      expect(() => noble.encrypt(hello), `a ${length}-byte key`).toThrowError(error);
      expect(() => noble.decrypt(sealed), `a ${length}-byte key`).toThrowError(error);
      expect(() => compat.encrypt(hello), `a ${length}-byte key`).toThrowError(
        "Invalid key length"
      );
      expect(() => compat.decrypt(sealed), `a ${length}-byte key`).toThrowError(
        "Invalid key length"
      );
    }
  });

  it.each(ciphers)("$name refuses a key that is no longer 32 bytes at each call", (c) => {
    const nonce = randomBytes(c.nonceLength);
    const changes = [
      (buffer: ResizableBuffer) => buffer.resize(16),
      (buffer: ResizableBuffer) => buffer.resize(24),
      (buffer: ResizableBuffer) => buffer.resize(0),
      (buffer: ResizableBuffer) => buffer.transfer(), // detaches it
    ];
    for (const change of changes) {
      const buffer = new ResizableArrayBuffer(32, { maxByteLength: 32 });
      const key = new Uint8Array(buffer); // 32 bytes at construction, then whatever the buffer holds
      key.set(randomBytes(32));
      const noble = c.noble(key, nonce);
      const compat = c.node(key, nonce);
      change(buffer);
      expect(() => noble.encrypt(hello), `${key.length} bytes`).toThrowError(
        `${c.name}'s key must be 32 bytes`
      );
      expect(() => compat.encrypt(hello), `${key.length} bytes`).toThrowError(
        "Invalid key length"
      );
    }
  });
});

// a view over a buffer that has shrunk below it reads its length and byteOffset as 0, so noble's
// gcm and cbc read no bytes and seal an empty message (@noble/ciphers 1.3.0, utils.js:90-92
// and :367-369); cbc throws only for a view that starts past the buffer's new end
describe("refuses a detached or out-of-bounds plaintext, wherever it runs (#29)", () => {
  // a copy of hello at offset in a buffer of its own, then cut
  const cutView = (offset: number, cut: (buffer: ResizableBuffer) => void): Uint8Array => {
    const length = offset + hello.length;
    const buffer = new ResizableArrayBuffer(length, { maxByteLength: length });
    const view = new Uint8Array(buffer, offset, hello.length);
    view.set(hello);
    cut(buffer);
    return view;
  };
  const shrinkTo = (length: number) => (buffer: ResizableBuffer) => buffer.resize(length);

  it.each(ciphers)("$name refuses it, and is used up", (c) => {
    const views: [string, () => Uint8Array][] = [
      ["a view over a buffer shrunk to 0", () => cutView(0, shrinkTo(0))],
      ["a view at offset 3, over a buffer shrunk to 3", () => cutView(3, shrinkTo(3))],
      ["a view at offset 4, over a buffer shrunk to 2", () => cutView(4, shrinkTo(2))],
      [
        "one whose own values() and byteLength don't tell, as a subclass's needn't",
        () => {
          const view = cutView(0, shrinkTo(0));
          Object.defineProperty(view, "values", { value: () => [].values() });
          Object.defineProperty(view, "byteLength", { get: () => hello.length });
          return view;
        },
      ],
      [
        "one from another realm, which isn't an instance of this realm's Uint8Array",
        () =>
          runInNewContext(`const buffer = new ArrayBuffer(5, { maxByteLength: 5 });
            const view = new Uint8Array(buffer, 0, 5);
            buffer.resize(0);
            view;`),
      ],
      // which noble refused already, with an engine error
      ["a detached view", () => cutView(0, (buffer) => buffer.transfer())],
    ];
    for (const [label, view] of views) {
      const key = randomBytes(32);
      const nonce = randomBytes(c.nonceLength);
      const noble = c.noble(key, nonce);
      const compat = c.node(key, nonce);
      const plainText = view();
      const error = "plaintext is detached or out of bounds";
      expect(() => noble.encrypt(plainText), label).toThrowError(error);
      expect(() => compat.encrypt(plainText), label).toThrowError(error);
      // and uses the cipher up, as noble does
      expect(() => noble.encrypt(hello), label).toThrowError(
        "cannot encrypt() twice with same key + nonce"
      );
    }
  });
});
