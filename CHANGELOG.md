# Release Notes

## 0.2.7

- Bump dependencies
- Wipe the plaintext Buffers `node:crypto` returns on decryption, and xchacha20's subkey after each call

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
