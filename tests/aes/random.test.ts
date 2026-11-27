import { gcm } from "@noble/ciphers/aes";
import type { Cipher, CipherWithOutput } from "@noble/ciphers/utils";
import { randomBytes } from "@noble/ciphers/webcrypto";
import { describe, expect, it } from "vitest";

import { aes256cbc as _aes256cbc, aes256gcm as _aes256gcm } from "../../src/aes/noble";
import { aes256cbc, aes256gcm } from "../../src/aes/node";
import { hello, testRandom } from "../common";

// ES2024's resizable ArrayBuffer, which the es2021 lib in tsconfig.json doesn't declare
type ResizableBuffer = ArrayBuffer & {
  resize(byteLength: number): void;
  transfer(): ArrayBuffer;
};
const ResizableArrayBuffer = ArrayBuffer as unknown as new (
  byteLength: number,
  options: { maxByteLength: number }
) => ResizableBuffer;

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

  it("hands noble an output buffer: cbc writes into it, gcm does what noble's does", () => {
    // in browsers and React Native; node:crypto's ciphers take no output buffer
    const key = randomBytes(32);
    const nonce = randomBytes(16);
    const sealed = new Uint8Array(32); // 16 bytes of hello, then a block of padding
    const cbc = _aes256cbc(key, nonce) as CipherWithOutput;
    const returned = cbc.encrypt(hello, sealed);
    // noble's cbc returns the output buffer, except 1.1.1's, which returns a view of it
    expect(returned.buffer).toBe(sealed.buffer);
    expect(returned).toStrictEqual(sealed);
    expect(aes256cbc(key, nonce).decrypt(sealed)).toStrictEqual(hello);
    const opened = new Uint8Array(32);
    const plainText = cbc.decrypt(sealed, opened);
    expect(plainText.buffer).toBe(opened.buffer);
    expect(plainText).toStrictEqual(hello);
    // noble's gcm refuses an output buffer from 1.1.2 on, and 1.1.0's and 1.1.1's ignore it
    const gcmNonce = randomBytes(12);
    const sealInto = (cipher: Cipher) => {
      try {
        return (cipher as CipherWithOutput).encrypt(hello, new Uint8Array(32));
      } catch (error) {
        return error;
      }
    };
    expect(sealInto(_aes256gcm(key, gcmNonce))).toStrictEqual(sealInto(gcm(key, gcmNonce)));
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
