// checks for both paths, so this imports nothing: the browser and React Native path can't load
// node:crypto

/**
 * noble's isBytes (@noble/ciphers 1.3.0, utils.js:39-41), which utils exports only from 1.3.0:
 * a Buffer passes, and so does a Uint8Array from another realm
 */
export const _isBytes = (a: unknown): a is Uint8Array =>
  a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array");

/**
 * refuse a view whose buffer has been detached, by a transfer to a worker say, or has shrunk
 * below it. Such a view reads as 0 bytes, so `node:crypto` would take it as empty, and so would
 * noble's aes an out-of-bounds one. The typed arrays' own iterator throws on such a view, and on
 * no other, when values() makes it and when it's stepped. It's stepped too: once this has run a
 * few hundred times, JavaScriptCore's JIT stops refusing an out-of-bounds view in values() alone.
 * It's called directly, and on every view, since a subclass may override values() or byteLength.
 */
export const _checkInBounds = (value: Uint8Array, name: string): void => {
  try {
    Uint8Array.prototype.values.call(value).next();
  } catch {
    throw new Error(`${name} is detached or out of bounds`);
  }
};
