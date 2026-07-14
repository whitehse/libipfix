# TODO.md — libipfix

## Short-term

- [x] Message header, template set, data set parsing
- [x] Options template + options data
- [x] Template withdrawal
- [x] Stream reassembly (`ipfix_feed_input`)
- [x] Smoke / dialectic / error tests
- [x] Example + fuzz harness + man page
- [ ] Variable-length field end-to-end test with multi-byte length prefix
- [ ] Sequence-number gap helper (optional, still syscall-free)

## Medium-term

- [ ] NetFlow v9 shim (separate set-ID/layout rules) or sibling library
- [ ] Template persistence helpers (serialize/deserialize cache)
- [ ] More IANA IE names and typed convenience fields (AS numbers, interfaces)
- [ ] Structured logging hook via event only (no stderr in library)

## Long-term

- [ ] Exporter / encoder path (`IPFIX_ROLE_EXPORTER`)
- [ ] SCTP association notes in docs
- [ ] WASM build target verification
