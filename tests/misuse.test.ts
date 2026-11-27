// The keys, nonces, AADs and data noble refuses, and a second encrypt(), the node:crypto ciphers
// refuse too. noble does it in wrapCipher (@noble/ciphers 1.3.0, utils.js:277-330), which
// browsers, React Native and Bun's chacha get.
import { Buffer } from "node:buffer";
import { runInNewContext } from "node:vm";

import type { Cipher } from "@noble/ciphers/utils";
import { randomBytes } from "@noble/ciphers/webcrypto";
import { describe, expect, it } from "vitest";

import * as nobleAes from "../src/aes/noble";
import * as nodeAes from "../src/aes/node";
import * as nobleChacha from "../src/chacha/noble";
import * as nodeChacha from "../src/chacha/node";
import { hello, ResizableArrayBuffer, type ResizableBuffer, testRandom } from "./common";

type Make = (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array) => Cipher;
type Case = { name: string; node: Make; noble: Make; nonceLength: number; AEAD: boolean };

const cases: Case[] = [
  {
    name: "aes256gcm",
    node: nodeAes.aes256gcm,
    noble: nobleAes.aes256gcm,
    nonceLength: 12,
    AEAD: true,
  },
  {
    name: "aes256cbc",
    node: nodeAes.aes256cbc,
    noble: nobleAes.aes256cbc,
    nonceLength: 16,
    AEAD: false, // takes no AAD
  },
  {
    name: "chacha20",
    node: nodeChacha.chacha20,
    noble: nobleChacha.chacha20,
    nonceLength: 12,
    AEAD: true,
  },
  {
    name: "xchacha20",
    node: nodeChacha.xchacha20,
    noble: nobleChacha.xchacha20,
    nonceLength: 24,
    AEAD: true,
  },
];

// what a JavaScript caller, or a cast, can pass where the types say Uint8Array; each holds
// `length` bytes, and all but the DataView and the Uint16Array have `length` elements too
const notBytes = (length: number): [string, Uint8Array][] =>
  (
    [
      ["a string", "k".repeat(length)],
      ["an array of numbers", Array.from(randomBytes(length))],
      ["a DataView", new DataView(randomBytes(length).buffer)],
      ["a Uint8ClampedArray", new Uint8ClampedArray(randomBytes(length))],
      ["a Uint16Array", new Uint16Array(length / 2)],
    ] as [string, unknown][]
  ).map(([label, value]) => [label, value as Uint8Array]);

// a Uint8Array made in another realm, such as an iframe or a vm context, isn't an instance of
// this realm's Uint8Array
const fromOtherRealm = (bytes: Uint8Array): Uint8Array => {
  const copy = runInNewContext(`new Uint8Array(${bytes.length})`) as Uint8Array;
  copy.set(bytes);
  return copy;
};

// a copy of bytes in a view over a buffer of its own, which a cut below can take away
const cuttable = (bytes: Uint8Array): [Uint8Array, ResizableBuffer] => {
  const buffer = new ResizableArrayBuffer(bytes.length, { maxByteLength: bytes.length });
  const view = new Uint8Array(buffer, 0, bytes.length);
  view.set(bytes);
  return [view, buffer];
};

// what leaves such a view reading as 0 bytes, though it's still a Uint8Array, and whether
// noble refuses it as a plaintext: its aes takes an out-of-bounds one as empty
const cuts: [string, (buffer: ResizableBuffer) => void, boolean][] = [
  // as postMessage(data, [data.buffer]) to a worker does too
  ["a detached", (buffer) => buffer.transfer(), true],
  ["an out-of-bounds", (buffer) => buffer.resize(0), false],
];

const encryptTwice = "cannot encrypt() twice with the same key and nonce";

describe("rejects a key or nonce that isn't a Uint8Array, as noble does (#20)", () => {
  it.each(cases)("$name", ({ node, noble, nonceLength }) => {
    for (const [label, key] of notBytes(32)) {
      const nonce = randomBytes(nonceLength);
      expect(() => node(key, nonce), `${label} as the key`).toThrowError(
        "key must be a Uint8Array"
      );
      expect(() => noble(key, nonce), `${label} as the key`).toThrowError(
        "Uint8Array expected"
      );
    }
    for (const [label, nonce] of notBytes(nonceLength)) {
      const key = randomBytes(32);
      expect(() => node(key, nonce), `${label} as the nonce`).toThrowError(
        "nonce must be a Uint8Array"
      );
      expect(() => noble(key, nonce), `${label} as the nonce`).toThrowError(
        "Uint8Array expected"
      );
    }
  });

  it.each(cases)("$name takes a Buffer, and a Uint8Array from another realm", (c) => {
    const key = randomBytes(32);
    const nonce = randomBytes(c.nonceLength);
    const inputs: [Uint8Array, Uint8Array][] = [
      [Buffer.from(key), fromOtherRealm(nonce)],
      [fromOtherRealm(key), Buffer.from(nonce)],
    ];
    for (const [k, n] of inputs) {
      testRandom(hello, c.noble(k, n), c.node(k, n));
    }
  });
});

describe("rejects a plaintext, ciphertext or AAD that isn't a Uint8Array, as noble does (#24)", () => {
  it.each(cases)("$name", (c) => {
    const key = randomBytes(32);
    const nonce = randomBytes(c.nonceLength);
    for (const [label, data] of notBytes(16)) {
      const asPlainText = `${label} as the plaintext`;
      const asCipherText = `${label} as the ciphertext`;
      expect(() => c.node(key, nonce).encrypt(data), asPlainText).toThrowError(
        "plaintext must be a Uint8Array"
      );
      expect(() => c.noble(key, nonce).encrypt(data), asPlainText).toThrowError(
        "Uint8Array expected"
      );
      expect(() => c.node(key, nonce).decrypt(data), asCipherText).toThrowError(
        "ciphertext must be a Uint8Array"
      );
      expect(() => c.noble(key, nonce).decrypt(data), asCipherText).toThrowError(
        "Uint8Array expected"
      );
      if (c.AEAD) {
        // when the cipher is made
        expect(() => c.node(key, nonce, data), `${label} as the AAD`).toThrowError(
          "AAD must be a Uint8Array"
        );
        expect(() => c.noble(key, nonce, data), `${label} as the AAD`).toThrowError(
          "Uint8Array expected"
        );
      }
    }
    // checked as types before anything else reads them
    for (const data of [null, undefined] as unknown as Uint8Array[]) {
      expect(() => c.node(key, nonce).encrypt(data)).toThrowError(
        "plaintext must be a Uint8Array"
      );
      expect(() => c.noble(key, nonce).encrypt(data)).toThrowError("Uint8Array expected");
      expect(() => c.node(key, nonce).decrypt(data)).toThrowError(
        "ciphertext must be a Uint8Array"
      );
      expect(() => c.noble(key, nonce).decrypt(data)).toThrowError("Uint8Array expected");
    }
    if (c.AEAD) {
      // noble checks any AAD but undefined
      const AAD = null as unknown as Uint8Array;
      expect(() => c.node(key, nonce, AAD)).toThrowError("AAD must be a Uint8Array");
      expect(() => c.noble(key, nonce, AAD)).toThrowError("Uint8Array expected");
    }
  });

  it.each(cases)("$name takes a Buffer, or a Uint8Array from another realm", (c) => {
    const key = randomBytes(32);
    const nonce = randomBytes(c.nonceLength);
    const AAD = c.AEAD ? randomBytes(8) : undefined;
    const sealed = c.noble(key, nonce, AAD).encrypt(hello);
    const wraps = [(bytes: Uint8Array) => Buffer.from(bytes), fromOtherRealm];
    for (const wrap of wraps) {
      const wrappedAAD = AAD && wrap(AAD);
      expect(c.node(key, nonce, wrappedAAD).encrypt(wrap(hello))).toStrictEqual(sealed);
      expect(c.node(key, nonce, wrappedAAD).decrypt(wrap(sealed))).toStrictEqual(hello);
      expect(c.noble(key, nonce, wrappedAAD).encrypt(wrap(hello))).toStrictEqual(sealed);
      expect(c.noble(key, nonce, wrappedAAD).decrypt(wrap(sealed))).toStrictEqual(hello);
    }
  });

  it("aes256cbc ignores its AAD, as noble's cbc takes none", () => {
    const key = randomBytes(32);
    const nonce = randomBytes(16);
    const notAAD = "not bytes" as unknown as Uint8Array;
    const sealed = nobleAes.aes256cbc(key, nonce, notAAD).encrypt(hello);
    expect(nodeAes.aes256cbc(key, nonce, notAAD).encrypt(hello)).toStrictEqual(sealed);
    expect(nodeAes.aes256cbc(key, nonce, notAAD).decrypt(sealed)).toStrictEqual(hello);
  });
});

describe("rejects a detached or out-of-bounds plaintext, ciphertext or AAD (#27)", () => {
  it.each(cases)("$name", (c) => {
    for (const [label, cut, nobleRefusesPlainText] of cuts) {
      const key = randomBytes(32);
      const nonce = randomBytes(c.nonceLength);

      // node:crypto sealed an empty message
      const [plainText, plainTextBuffer] = cuttable(hello);
      cut(plainTextBuffer);
      const compat = c.node(key, nonce);
      expect(() => compat.encrypt(plainText), `${label} plaintext`).toThrowError(
        "plaintext is detached or out of bounds"
      );
      // and uses the cipher up, as noble does
      expect(() => compat.encrypt(hello), `${label} plaintext`).toThrowError(encryptTwice);
      if (nobleRefusesPlainText) {
        expect(() => c.noble(key, nonce).encrypt(plainText)).toThrowError(/detached/);
      }
      // even one whose own values() and byteLength don't tell, as a subclass's needn't
      const [lax, laxBuffer] = cuttable(hello);
      Object.defineProperty(lax, "values", { value: () => [].values() });
      Object.defineProperty(lax, "byteLength", { get: () => hello.length });
      cut(laxBuffer);
      expect(() => c.node(key, nonce).encrypt(lax), `${label} plaintext`).toThrowError(
        "plaintext is detached or out of bounds"
      );

      const [cipherText, cipherTextBuffer] = cuttable(c.noble(key, nonce).encrypt(hello));
      cut(cipherTextBuffer);
      const asCipherText = `${label} ciphertext`;
      expect(() => c.node(key, nonce).decrypt(cipherText), asCipherText).toThrowError(
        "ciphertext is detached or out of bounds"
      );
      expect(() => c.noble(key, nonce).decrypt(cipherText), asCipherText).toThrowError();

      if (c.AEAD) {
        // node:crypto took it as no AAD: it sealed under none, and opened what was sealed under
        // none. Each call reads it, so one cipher is made before the cut and one after.
        const sealedWithoutAAD = c.noble(key, nonce).encrypt(hello);
        const [AAD, AADBuffer] = cuttable(randomBytes(8));
        const madeBefore = c.node(key, nonce, AAD);
        cut(AADBuffer);
        const madeAfter = c.node(key, nonce, AAD);
        const asAAD = `${label} AAD`;
        const outOfBounds = "AAD is detached or out of bounds";
        expect(() => madeBefore.encrypt(hello), asAAD).toThrowError(outOfBounds);
        // and uses the cipher up, as noble does
        expect(() => madeBefore.encrypt(hello), asAAD).toThrowError(encryptTwice);
        expect(() => madeBefore.decrypt(sealedWithoutAAD), asAAD).toThrowError(outOfBounds);
        expect(() => madeAfter.encrypt(hello), asAAD).toThrowError(outOfBounds);
        const noble = c.noble(key, nonce, AAD);
        expect(() => noble.encrypt(hello), asAAD).toThrowError(/detached/);
        expect(() => noble.decrypt(sealedWithoutAAD), asAAD).toThrowError(/detached/);
      }
    }
  });

  it.each(cases)("$name takes an in-bounds empty plaintext and AAD, as noble does", (c) => {
    const key = randomBytes(32);
    const nonce = randomBytes(c.nonceLength);
    const buffer = new ResizableArrayBuffer(8, { maxByteLength: 8 });
    const tracking = new Uint8Array(buffer); // as long as its buffer, whatever that is
    buffer.resize(0);
    const empties: [string, Uint8Array][] = [
      ["an empty Uint8Array", new Uint8Array(0)],
      ["an empty view at the end of its buffer", new Uint8Array(8).subarray(8)],
      ["a length-tracking view whose buffer has shrunk to 0", tracking],
    ];
    for (const [label, empty] of empties) {
      const AAD = c.AEAD ? empty : undefined;
      const [noble, compat] = [c.noble(key, nonce, AAD), c.node(key, nonce, AAD)];
      expect(() => testRandom(empty, noble, compat), label).not.toThrow();
    }
  });
});

describe("encrypts once per cipher, as noble does (#22)", () => {
  it.each(cases)("$name refuses a second encrypt(), and keeps decrypting", (c) => {
    const key = randomBytes(32);
    const nonce = randomBytes(c.nonceLength);
    const compat = c.node(key, nonce);
    const noble = c.noble(key, nonce);

    const sealed = compat.encrypt(hello);
    expect(noble.encrypt(hello)).toStrictEqual(sealed);
    // a second message under the same key and nonce reuses the keystream, or for cbc, shows
    // whether the two messages start alike
    expect(() => compat.encrypt(hello)).toThrowError(encryptTwice);
    expect(() => compat.encrypt(randomBytes(16))).toThrowError(encryptTwice);
    expect(() => noble.encrypt(hello)).toThrowError(
      "cannot encrypt() twice with same key + nonce"
    );

    expect(compat.decrypt(sealed)).toStrictEqual(hello);
    expect(compat.decrypt(sealed)).toStrictEqual(hello);
  });

  it.each(cases)("$name counts an encrypt() that throws, as noble does", (c) => {
    // noble marks the cipher used before it checks the data (utils.js:311-313 in 1.3.0); here
    // node:crypto, or xchacha20's own check, refuses the 16-byte key, and in browsers aes's
    // checkKey or noble's chacha does
    const compat = c.node(randomBytes(16), randomBytes(c.nonceLength));
    expect(() => compat.encrypt(hello)).toThrowError(
      /Invalid key length|key must be 32 bytes/
    );
    expect(() => compat.encrypt(hello)).toThrowError(encryptTwice);
    const noble = c.noble(randomBytes(16), randomBytes(c.nonceLength));
    expect(() => noble.encrypt(hello)).toThrowError(
      /key must be 32 bytes|invalid 32-byte key/
    );
    expect(() => noble.encrypt(hello)).toThrowError(
      "cannot encrypt() twice with same key + nonce"
    );
  });

  it.each(cases)("$name counts an encrypt() whose plaintext isn't a Uint8Array", (c) => {
    // noble checks the data after it marks the cipher used (utils.js:311-314 in 1.3.0)
    const key = randomBytes(32);
    const nonce = randomBytes(c.nonceLength);
    const compat = c.node(key, nonce);
    const noble = c.noble(key, nonce);
    const notPlainText = "hello" as unknown as Uint8Array;
    expect(() => compat.encrypt(notPlainText)).toThrowError(
      "plaintext must be a Uint8Array"
    );
    expect(() => compat.encrypt(hello)).toThrowError(encryptTwice);
    expect(() => noble.encrypt(notPlainText)).toThrowError("Uint8Array expected");
    expect(() => noble.encrypt(hello)).toThrowError(
      "cannot encrypt() twice with same key + nonce"
    );
  });
});
