# ADR-010: Fuzz Harness

## Status

Accepted

## Context

IPFIX parsers face untrusted network input and are a high-value crash target.

## Decision

Ship `fuzz/ipfix_fuzz.c` for libFuzzer (`-DBUILD_FUZZ=ON`), feeding both `ipfix_feed_input` (chunked) and `ipfix_feed_message`, draining events, and exercising field/template/enterprise helpers under **ASan + UBSan**. When `BUILD_FUZZ` is on, the `ipfix` static library is also instrumented (`-fsanitize=fuzzer-no-link,address,undefined`).

Seeds live in `fuzz/seed_corpus/`; see `fuzz/README.md` for the run recipe.

## Consequences

- Continuous fuzzing can be wired into CI where clang is available
- Parser must not abort on any byte sequence (errors become events or return codes)
- Evolved corpora and crash artifacts stay local (gitignored under `fuzz/corpus/`, `fuzz/artifacts/`)
