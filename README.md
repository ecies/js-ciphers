# @ecies/ciphers

Node/Pure js symmetric ciphers adapter.

On browsers (or deno), it'll use `@noble/ciphers`'s implementation.

On node (or bun), it'll use `node:crypto`'s implementation.

Check the [example](./example/) folder for the bun/deno usage.
