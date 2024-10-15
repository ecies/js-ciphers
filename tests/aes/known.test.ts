import { describe, it } from "vitest";

import { concatBytes, hexToBytes } from "@noble/ciphers/utils";

import { aes256gcm as _aes256gcm } from "../../src/aes/noble";
import { aes256gcm } from "../../src/aes/node";
import { testKnown } from "../common";

const encoder = new TextEncoder();

describe("test known", () => {
  it("tests gcm", async () => {
    const key = hexToBytes(
      "0000000000000000000000000000000000000000000000000000000000000000"
    );
    const nonce = hexToBytes("f3e1ba810d2c8900b11312b7c725565f");
    const aad = Uint8Array.from([]);
    const noble = _aes256gcm(key, nonce, aad);
    const compat = aes256gcm(key, nonce, aad);

    const cipherText = hexToBytes("02d2ffed93b856f148b9");
    const tag = hexToBytes("ec3b71e17c11dbe31484da9450edcf6c");
    const encrypted = concatBytes(cipherText, tag);

    const plainText = encoder.encode("helloworld");

    testKnown(plainText, encrypted, noble, compat);
  });
});
