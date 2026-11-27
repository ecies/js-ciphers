# Release Notes

## 0.2.7

- Bump dependencies
- Wipe the plaintext Buffers `node:crypto` returns on decryption, and xchacha20's subkey after each call
- Read xchacha20's key and nonce at each call on Node and Deno, as noble and the other ciphers do, instead of once at construction
- Reject an xchacha20 key that isn't 32 bytes on Node and Deno, as noble does
- Reject an xchacha20 nonce that has stopped being 24 bytes since construction on Node and Deno, as noble does
- Accept an xchacha20 key or nonce at any byteOffset on Node and Deno
- Reject a key or nonce that isn't a `Uint8Array` wherever `node:crypto` is used, as noble does
- Refuse a second `encrypt()` on one cipher wherever `node:crypto` is used, as noble does from 1.1.0
- Require `@noble/ciphers` 1.1.0 or later, so that every runtime refuses a second `encrypt()`

## 0.2.6

- Bump dependencies
- Bump emitted JavaScript target to es2021
- Use `node:crypto`'s chacha20-poly1305 implementation on deno (>=2.7.10)

## 0.2.5

- Bump dependencies
- Prepare for ESM

## 0.2.4

- Bump dependencies
- Revamp documentation: deno support

## 0.2.3

- Use `node:crypto`'s aes implementation on deno
- Bump dependencies
- Revamp documentation

## 0.2.2

- Add `chacha20-poly1305` support
- Bump dependencies
- Add minimum supported node (16.0.0) runtime check in CI

## 0.2.1

- Add React Native package exports

## 0.2.0

- Add `xchacha20-poly1305` support

## 0.1.0

- First beta version release with `aes-256-gcm` and `aes-256-cbc` support
