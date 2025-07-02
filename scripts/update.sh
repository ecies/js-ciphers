#!/bin/sh
pnpm update
cd tests-browser && pnpm update && cd ../example
pnpm update && cd ..
