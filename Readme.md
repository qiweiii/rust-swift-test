Testing calling bandersnatch-spec rust function from swift

branch `main`: swfit-bridge (not working yet)

branch `c-binding`: cbindgen (works)
  - run with `./deps.sh`, then `CARGO_MANIFEST_DIR=./ RING_SIZE=6 swift test`
  - or  `rm -rf .build/ && ./deps.sh && CARGO_MANIFEST_DIR=./ RING_SIZE=6 swift test`
