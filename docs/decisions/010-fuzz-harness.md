# ADR-010: Fuzz Harness

## Status

Accepted

## Context

IPFIX parsers face untrusted network input and are a high-value crash target.

## Decision

Ship `fuzz/ipfix_fuzz.c` for libFuzzer (`-DBUILD_FUZZ=ON`), feeding both `ipfix_feed_input` and `ipfix_feed_message` and draining all events.

## Consequences

- Continuous fuzzing can be wired into CI where clang is available
- Parser must not abort on any byte sequence (errors become events or return codes)
