# AGENTS.md — libipfix

## What this is

**libipfix** is a pure C IPFIX (IP Flow Information Export, RFC 7011) receiver.

- **Language:** C11
- **Build:** CMake ≥ 3.14
- **Tests:** ctest (smoke, dialectic, errors)
- **License:** MIT

## Key properties

- **Syscall-free** — no sockets, no file I/O, no timers. The caller owns transport (UDP/TCP via io_uring, epoll, etc.).
- **Callback-free** — all output via pull-based event queue (`ipfix_next_event`).
- **Streaming input** — `ipfix_feed_input` reassembles TCP-framed messages; `ipfix_feed_message` accepts a complete datagram.
- **Bounded memory** — fixed-size event ring and template cache sized at creation.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md).

## Build & test

```bash
cmake -B build -S .
cmake --build build
ctest --test-dir build
```

## Session startup

1. `pwd` and confirm you are in `libipfix`
2. Read this file and [ARCHITECTURE.md](ARCHITECTURE.md)
3. `cmake --build build && ctest --test-dir build` as a smoke check

## Directives

- **Must** keep the library free of syscalls and blocking I/O
- **Must** emit parse results only through the event queue (no callbacks)
- **Must** treat untrusted wire input as hostile (fuzz-friendly parsing)
- **Never** allocate on the per-message hot path after `ipfix_create*`
- **Prefer** extending IANA IE convenience fields over growing the event union ad hoc
- **Prefer** static enterprise IE tables (ADR-013) over runtime registries or convenience fields for vendor IEs
- **Avoid** linking external dependencies

## Definition of done

- [ ] `cmake --build build` succeeds with `-Werror`
- [ ] `ctest --test-dir build` passes (smoke, dialectic, errors)
- [ ] New public API is documented in `include/ipfix.h` and linked from docs/
- [ ] Significant design choices have an ADR under `docs/decisions/`

## ADR references

| ADR | Topic |
|-----|-------|
| 001 | Pure C choice |
| 002 | Collector-only scope (v0.1) |
| 003 | Ring-buffer event queue |
| 004 | No callbacks |
| 005 | No syscalls / I/O offload |
| 006 | Streaming reassembly vs datagram feed |
| 007 | Template cache semantics |
| 008 | Field value representation |
| 009 | Strict compiler warnings |
| 010 | Fuzz harness |
| 011 | Man page conventions |
| 012 | Agent-ready documentation |
| 013 | Static enterprise IE registry (Calix PEN 6321) |

## API surface (quick)

| Function | Purpose |
|----------|---------|
| `ipfix_create` / `ipfix_create_with_config` | Lifecycle |
| `ipfix_feed_input` / `ipfix_feed_message` | Ingest wire bytes |
| `ipfix_next_event` | Pull decoded events |
| `ipfix_get_template` | Inspect learned templates |
| `ipfix_record_find_field` | Look up IANA IE in a record |
| `ipfix_record_find_enterprise_field` | Look up vendor IE (PEN + id) |
| `ipfix_enterprise_ie_name` / `_datatype` | Static registry lookup |
