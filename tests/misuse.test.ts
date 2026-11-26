// The keys and nonces noble refuses, and a second encrypt(), the node:crypto ciphers refuse
// too. noble does it in wrapCipher (@noble/ciphers 1.3.0, utils.js:277-330), which browsers,
// React Native and Bun's chacha get.
import { Buffer } from "node:buffer";
import { runInNewContext } from "node:vm";

import type { Cipher } from "@noble/ciphers/utils";
import { randomBytes } from "@noble/ciphers/webcrypto";
import { describe, expect, it } from "vitest";

import * as nobleAes from "../src/aes/noble";
import * as nodeAes from "../src/aes/node";
import * as nobleChacha from "../src/chacha/noble";
import * as nodeChacha from "../src/chacha/node";
import { hello, testRandom } from "./common";

type Make = (key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array) => Cipher;
type Case = { name: string; node: Make; noble: Make; nonceLength: number };

const cases: Case[] = [
  {
    name: "aes256gcm",
    node: nodeAes.aes256gcm,
    noble: nobleAes.aes256gcm,
    nonceLength: 12,
  },
  {
    name: "aes256cbc",
    node: nodeAes.aes256cbc,
    noble: nobleAes.aes256cbc,
    nonceLength: 16,
  },
  {
    name: "chacha20",
    node: nodeChacha.chacha20,
    noble: nobleChacha.chacha20,
    nonceLength: 12,
  },
  {
    name: "xchacha20",
    node: nodeChacha.xchacha20,
    noble: nobleChacha.xchacha20,
    nonceLength: 24,
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

describe("encrypts once per cipher, as noble does (#22)", () => {
  const encryptTwice = "cannot encrypt() twice with the same key and nonce";

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
    // node:crypto, or xchacha20's own check, refuses the 16-byte key
    const compat = c.node(randomBytes(16), randomBytes(c.nonceLength));
    expect(() => compat.encrypt(hello)).toThrowError(
      /Invalid key length|key must be 32 bytes/
    );
    expect(() => compat.encrypt(hello)).toThrowError(encryptTwice);
  });
});
