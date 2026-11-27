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

  type Resizable = ArrayBuffer & { resize(byteLength: number): void; transfer(): ArrayBuffer };
  const Resizable = ArrayBuffer as unknown as new (
    byteLength: number,
    options: { maxByteLength: number }
  ) => Resizable;
  const aes = [
    [aes256gcm, 12],
    [aes256cbc, 16],
  ] as const;

  // a view over a buffer that has shrunk below it reads as 0 bytes, and noble's aes sealed it
  // as an empty message (#29)
  it("refuses a detached or out-of-bounds aes plaintext", () => {
    const cuts: [string, (buffer: Resizable) => void][] = [
      ["out of bounds", (buffer) => buffer.resize(0)],
      ["detached", (buffer) => buffer.transfer()],
    ];
    for (const [callback, nonceLength] of aes) {
      for (const [label, cut] of cuts) {
        const buffer = new Resizable(data.length, { maxByteLength: data.length });
        const plainText = new Uint8Array(buffer, 0, data.length);
        plainText.set(data);
        cut(buffer);
        const cipher = callback(randomBytes(32), randomBytes(nonceLength));
        expect(() => cipher.encrypt(plainText), label).toThrowError(
          "plaintext is detached or out of bounds"
        );
      }
    }
  });

  // JavaScriptCore's JIT stopped refusing an out-of-bounds view in values() alone once the
  // check had run a few hundred times, and the plaintext was sealed as empty again
  it("refuses an out-of-bounds aes plaintext after many ordinary ones", () => {
    const plainTexts = [new Uint8Array(0), randomBytes(5), data];
    for (const [callback, nonceLength] of aes) {
      for (let i = 0; i < 3000; i++) {
        callback(randomBytes(32), randomBytes(nonceLength)).encrypt(plainTexts[i % 3]);
      }
      const buffer = new Resizable(data.length, { maxByteLength: data.length });
      const plainText = new Uint8Array(buffer, 0, data.length);
      plainText.set(data);
      buffer.resize(0);
      const cipher = callback(randomBytes(32), randomBytes(nonceLength));
      expect(() => cipher.encrypt(plainText), callback.name).toThrowError(
        "plaintext is detached or out of bounds"
      );
    }
  });

  it("takes an in-bounds empty aes plaintext", () => {
    const shrunk = new Resizable(8, { maxByteLength: 8 });
    const tracking = new Uint8Array(shrunk); // as long as its buffer, whatever that is
    shrunk.resize(0);
    const empties: [string, Uint8Array][] = [
      ["an empty Uint8Array", new Uint8Array(0)],
      ["an empty view at the end of its buffer", new Uint8Array(8).subarray(8)],
      ["a length-tracking view whose buffer has shrunk to 0", tracking],
    ];
    for (const [callback, nonceLength] of aes) {
      for (const [label, empty] of empties) {
        const key = randomBytes(32);
        const nonce = randomBytes(nonceLength);
        const sealed = callback(key, nonce).encrypt(empty);
        expect(callback(key, nonce).decrypt(sealed), label).toStrictEqual(new Uint8Array(0));
      }
    }
  });
});
