import type { Cipher } from "@noble/ciphers/utils";
import { expect } from "vitest";

const TEXT = "hello world🌍!";
const encoder = new TextEncoder();
export const hello = encoder.encode(TEXT);

// ES2024's resizable ArrayBuffer, which the es2021 lib in tsconfig.json doesn't declare
export type ResizableBuffer = ArrayBuffer & {
  resize(byteLength: number): void;
  transfer(): ArrayBuffer;
};
export const ResizableArrayBuffer = ArrayBuffer as unknown as new (
  byteLength: number,
  options: { maxByteLength: number }
) => ResizableBuffer;

export function testRandom(data: Uint8Array, noble: Cipher, compat: Cipher) {
  const encrypted = noble.encrypt(data);
  const compatEncrypted = compat.encrypt(data);
  // same encryption
  expect(encrypted).toStrictEqual(compatEncrypted);
  // noble encrypts, compat decrypts
  expect(compat.decrypt(encrypted)).toStrictEqual(data);
  // noble decrypts, compat encrypts
  expect(noble.decrypt(compatEncrypted)).toStrictEqual(data);
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
