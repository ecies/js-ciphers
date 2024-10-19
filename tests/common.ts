import { expect } from "vitest";

import { Cipher } from "@noble/ciphers/utils";

const TEXT = "hello world🌍!";
const encoder = new TextEncoder();
export const hello = encoder.encode(TEXT);

export function testRandom(data: Uint8Array, noble: Cipher, compat: Cipher) {
  // same encryption
  expect(noble.encrypt(data)).toStrictEqual(compat.encrypt(data));
  // noble encrypts, compat decrypts
  expect(compat.decrypt(noble.encrypt(data))).toStrictEqual(data);
  // noble decrypts, compat encrypts
  expect(noble.decrypt(compat.encrypt(data))).toStrictEqual(data);
}

export function testKnown(
  data: Uint8Array,
  encrypted: Uint8Array,
  noble: Cipher,
  compat: Cipher
) {
  // same encryption
  expect(compat.encrypt(data)).toStrictEqual(encrypted);
  expect(noble.encrypt(data)).toStrictEqual(encrypted);
  // same decryption
  expect(compat.decrypt(encrypted)).toStrictEqual(data);
  expect(noble.decrypt(encrypted)).toStrictEqual(data);
}