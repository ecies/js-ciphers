import { randomBytes } from "@noble/ciphers/webcrypto";
import { expect, it } from "vitest";

import { aes256cbc as _aes256cbc, aes256gcm as _aes256gcm } from "../../src/aes/noble";
import { aes256cbc, aes256gcm } from "../../src/aes/node";
import { hello, ResizableArrayBuffer } from "../common";

// JavaScriptCore's JIT stopped refusing an out-of-bounds view in values() alone once the check
// had run a few hundred times, and the plaintext was sealed as empty again (#29). Bun runs both
// paths on it, so CI runs this file there, on its own: after the other aes tests, values()
// alone kept refusing on Bun 1.2.21, so this test couldn't fail there

const ciphers = [
  { name: "aes256gcm", noble: _aes256gcm, node: aes256gcm, nonceLength: 12 },
  { name: "aes256cbc", noble: _aes256cbc, node: aes256cbc, nonceLength: 16 },
];

it.each(ciphers)("$name refuses an out-of-bounds plaintext after many encrypts", (c) => {
  const plainTexts = [new Uint8Array(0), randomBytes(5), hello];
  for (const [path, make] of [
    ["noble", c.noble],
    ["node:crypto", c.node],
  ] as const) {
    for (let i = 0; i < 3000; i++) {
      make(randomBytes(32), randomBytes(c.nonceLength)).encrypt(plainTexts[i % 3]);
    }
    const buffer = new ResizableArrayBuffer(hello.length, { maxByteLength: hello.length });
    const plainText = new Uint8Array(buffer, 0, hello.length);
    plainText.set(hello);
    buffer.resize(0);
    expect(
      () => make(randomBytes(32), randomBytes(c.nonceLength)).encrypt(plainText),
      path
    ).toThrowError("plaintext is detached or out of bounds");
  }
});

// the node:crypto path checks the AAD at each call too; noble refuses such an AAD itself
it("aes256gcm refuses an out-of-bounds AAD after many encrypts", () => {
  const AADs = [new Uint8Array(0), randomBytes(5), hello];
  for (let i = 0; i < 3000; i++) {
    aes256gcm(randomBytes(32), randomBytes(12), AADs[i % 3]).encrypt(hello);
  }
  const buffer = new ResizableArrayBuffer(hello.length, { maxByteLength: hello.length });
  const AAD = new Uint8Array(buffer, 0, hello.length);
  buffer.resize(0);
  expect(() =>
    aes256gcm(randomBytes(32), randomBytes(12), AAD).encrypt(hello)
  ).toThrowError("AAD is detached or out of bounds");
});
