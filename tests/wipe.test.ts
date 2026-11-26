// What decrypt and xchacha20 leave behind can only be seen where they meet node:crypto,
// so this file records the keys node:crypto is given and the Buffers it hands back.
import { bytesToHex, type Cipher, concatBytes, hexToBytes } from "@noble/ciphers/utils";
import { randomBytes } from "@noble/ciphers/webcrypto";
import { describe, expect, it, vi } from "vitest";

import { aes256cbc, aes256gcm } from "../src/aes/node";
import { chacha20, xchacha20 } from "../src/chacha/node";

type Recorded = { live: Uint8Array; atTheTime: Uint8Array };

const { keys, plainTexts } = vi.hoisted(() => ({
  keys: [] as Recorded[], // given to createCipheriv and createDecipheriv
  plainTexts: [] as Recorded[], // returned by a decipher's update() and final()
}));

vi.mock("node:crypto", async (importOriginal) => {
  const crypto = await importOriginal<typeof import("node:crypto")>();
  const record = <T extends Uint8Array>(list: Recorded[], bytes: T): T => {
    list.push({ live: bytes, atTheTime: Uint8Array.from(bytes) });
    return bytes;
  };
  return {
    ...crypto,
    createCipheriv: (...args: Parameters<typeof crypto.createCipheriv>) => {
      record(keys, args[1] as Uint8Array);
      return crypto.createCipheriv(...args);
    },
    createDecipheriv: (...args: Parameters<typeof crypto.createDecipheriv>) => {
      record(keys, args[1] as Uint8Array);
      const decipher = crypto.createDecipheriv(...args);
      const update = decipher.update.bind(decipher);
      const final = decipher.final.bind(decipher);
      decipher.update = ((data: Uint8Array) =>
        record(plainTexts, update(data))) as typeof decipher.update;
      decipher.final = (() => record(plainTexts, final())) as typeof decipher.final;
      return decipher;
    },
  };
});

const zeroed = (list: Recorded[]) => list.map(({ live }) => "00".repeat(live.length));
const hex = (list: Recorded[], when: keyof Recorded) =>
  list.map((recorded) => bytesToHex(recorded[when]));

// 33 bytes: aes-256-cbc's final() returns the last byte, and a corrupted message still
// decrypts its first block in update()
const message = new TextEncoder().encode("thirty-three bytes of secret text");

type Case = {
  name: string;
  cipher: (key: Uint8Array, nonce: Uint8Array) => Cipher;
  nonceLength: number;
  // where to flip a bit so that final() throws, and what it throws
  flip: number;
  error: RegExp;
};

// Node 16 to 22 report a tag mismatch as the first, and Node 24.22 as the second
const tagMismatch = /unable to authenticate data|bad decrypt/;

const cases: Case[] = [
  {
    name: "aes-256-gcm",
    cipher: aes256gcm,
    nonceLength: 12,
    flip: -1, // the tag
    error: tagMismatch,
  },
  {
    name: "aes-256-cbc",
    cipher: aes256cbc,
    nonceLength: 16,
    flip: -17, // the second block's last byte, which flips the padding's last byte
    error: /bad decrypt/,
  },
  {
    name: "chacha20",
    cipher: chacha20,
    nonceLength: 12,
    flip: -1,
    error: tagMismatch,
  },
  {
    name: "xchacha20",
    cipher: xchacha20,
    nonceLength: 24,
    flip: -1,
    error: tagMismatch,
  },
];

describe("decrypt wipes node:crypto's copies of the plaintext (#13)", () => {
  it.each(cases)("$name", ({ cipher, nonceLength }) => {
    const key = randomBytes(32);
    const nonce = randomBytes(nonceLength);
    const sealed = cipher(key, nonce).encrypt(message);

    plainTexts.length = 0;
    expect(cipher(key, nonce).decrypt(sealed)).toStrictEqual(message);

    expect(concatBytes(...plainTexts.map(({ atTheTime }) => atTheTime))).toStrictEqual(
      message
    );
    expect(hex(plainTexts, "live")).toEqual(zeroed(plainTexts));
  });

  it.each(cases)("$name, when final() throws", ({ cipher, nonceLength, flip, error }) => {
    const key = randomBytes(32);
    const nonce = randomBytes(nonceLength);
    const sealed = cipher(key, nonce).encrypt(message);
    sealed[sealed.length + flip] ^= 1;

    plainTexts.length = 0;
    expect(() => cipher(key, nonce).decrypt(sealed)).toThrow(error);

    // update() handed back the unauthenticated plaintext before final() threw
    expect(plainTexts).toHaveLength(1);
    expect(plainTexts[0].atTheTime.subarray(0, 16)).toStrictEqual(message.subarray(0, 16));
    expect(hex(plainTexts, "live")).toEqual(zeroed(plainTexts));
  });
});

describe("xchacha20 wipes its subkey after each call (#13)", () => {
  it("derives the subkey for each call and wipes it once node:crypto has copied it", () => {
    // HChaCha20's test vector: the key, and the nonce's first 16 bytes; the last 8 are
    // xchacha20's own
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#section-2.2.1
    const key = hexToBytes(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    );
    const nonce = hexToBytes("000000090000004a00000000314159270001020304050607");
    const subKey = "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc";

    const cipher = xchacha20(key, nonce);
    keys.length = 0;
    const sealed = cipher.encrypt(message);
    expect(cipher.decrypt(sealed)).toStrictEqual(message);
    // a cipher encrypts once (#22), and the refusal gives node:crypto no key
    expect(() => cipher.encrypt(message)).toThrow("cannot encrypt() twice");
    expect(cipher.decrypt(sealed)).toStrictEqual(message);
    // and when the tag check fails
    const forged = sealed.slice();
    forged[forged.length - 1] ^= 1;
    expect(() => cipher.decrypt(forged)).toThrow(tagMismatch);

    expect(hex(keys, "atTheTime")).toEqual([subKey, subKey, subKey, subKey]);
    expect(hex(keys, "live")).toEqual(zeroed(keys));
  });
});

describe("the caller's key and ciphertext stay as they are", () => {
  it.each(cases)("$name", ({ cipher, nonceLength }) => {
    const key = randomBytes(32);
    const keyBefore = key.slice();
    const nonce = randomBytes(nonceLength);
    const instance = cipher(key, nonce);

    const sealed = instance.encrypt(message);
    const sealedBefore = sealed.slice();
    expect(instance.decrypt(sealed)).toStrictEqual(message);
    expect(key).toStrictEqual(keyBefore);
    expect(sealed).toStrictEqual(sealedBefore);

    expect(instance.decrypt(sealed)).toStrictEqual(message);
  });
});
