import { describe, expect, it } from "vitest";

import { concatBytes, hexToBytes } from "@noble/ciphers/utils";

import { aes256gcm as _aes256gcm } from "../src/noble";
import { aes256gcm } from "../src/node";

const encoder = new TextEncoder();

describe("test known", () => {
  it("tests gcm", async () => {
    const key = hexToBytes(
      "0000000000000000000000000000000000000000000000000000000000000000"
    );
    const nonce = hexToBytes("f3e1ba810d2c8900b11312b7c725565f");
    const tag = hexToBytes("ec3b71e17c11dbe31484da9450edcf6c");
    const encrypted = hexToBytes("02d2ffed93b856f148b9");
    const known = concatBytes(encrypted, tag);
    const msg = encoder.encode("helloworld");
    const aad = Uint8Array.from([]);

    const noble = _aes256gcm(key, nonce, aad);
    const compat = aes256gcm(key, nonce, aad);
    expect(compat.decrypt(known)).toStrictEqual(msg);
    expect(noble.decrypt(known)).toStrictEqual(msg);
  });
});
