# ARCHITECTURE.md — libipfix

## Overview

libipfix receives IPFIX messages (RFC 7011) from caller-supplied byte buffers, maintains a template cache, and emits structured events for templates, data records, options, and errors. It does **not** open sockets, block on I/O, or schedule timers.

## Codemap

| Path | Role |
|------|------|
| `include/ipfix.h` | Public API: config, events, field types, lifecycle |
| `include/ipfix_enterprise_calix.h` | Calix PEN 6321 IE id macros (generated) |
| `src/ipfix.c` | Parser, template cache, event ring, enterprise registry |
| `src/enterprise_calix.inc` | Calix name/datatype table (generated) |
| `enterprises/` | Vendor IE CSVs + generators |
| `tests/ipfix_smoke.c` | Happy-path: header, template, 5-tuple data record |
| `tests/ipfix_dialectic.c` | Multi-message flows, options, withdraw, enterprise IEs |
| `tests/ipfix_errors.c` | Malformed input and configuration edge cases |
| `examples/ipfix_example.c` | Synthetic flow printout (no real network) |
| `fuzz/ipfix_fuzz.c` | libFuzzer entry point |
| `docs/DOMAIN.md` | IPFIX protocol domain knowledge |
| `docs/decisions/` | Architecture Decision Records |

## Design approach

### Feed / event (pull) model

```
UDP datagram / TCP chunk
        │
        ▼
ipfix_feed_input()  or  ipfix_feed_message()
        │
        ├─ (feed_input) append to reassembly buffer
        │              extract complete messages by Length
        ▼
parse_message()
        ├─ validate version=10, length
        ├─ emit MESSAGE
        ├─ for each Set:
        │     Template Set     → learn/replace/withdraw → emit TEMPLATE
        │     Options Template → learn → emit OPTIONS_TEMPLATE
        │     Data Set         → decode via template → emit DATA_RECORD
        │                        (or OPTIONS_DATA)
        └─ emit SET_END / ERROR as needed
        │
        ▼
ipfix_next_event()  ◄── caller drains ring buffer
```

### Template cache

Templates (and options templates) are stored in a fixed-capacity array keyed by Template ID. Data Sets reference templates by Set ID == Template ID. Withdrawal is signalled by a Template Record with `field_count == 0`.

`ipfix_reset()` clears the event queue and reassembly buffer but **retains** templates (exporters rarely retransmit them). Use `ipfix_clear_templates()` to drop the cache.

### Field decoding

Each data-record field is classified into a value kind:

| Kind | Use |
|------|-----|
| `UINT` | Unsigned integers ≤ 8 bytes (ports, counters, timestamps) |
| `INT` | Signed integers ≤ 8 bytes (optical power, temperature) |
| `FLOAT` | IEEE 754 binary32/64 (promoted to `double`) |
| `IPV4` / `IPV6` | Address IEs |
| `MAC` | MAC address IEs |
| `STRING` | Text IEs (IANA or enterprise) |
| `RAW` | Everything else (truncated to max) |

IANA classification uses well-known element IDs. Enterprise fields consult a
**static per-PEN registry** (currently Calix PEN 6321) for datatype and name;
unknown enterprise IEs fall back to “≤ 8 bytes → UINT, else RAW”.

Common flow IEs are also copied into convenience members on `ipfix_data_record_t` (`src_ipv4`, `dst_port`, `octet_delta`, …) so callers can avoid a field scan for the 5-tuple path. Enterprise/PON fields are accessed via
`ipfix_record_find_enterprise_field` rather than bloating the convenience block.

### Memory model

All buffers (event ring, template array, reassembly) are allocated once in `ipfix_create*`. Per-message parsing does not call `malloc`/`free`.

## Invariants

1. No syscalls, no threads, no callbacks in library code.
2. Event queue capacity is fixed at creation; overflow drops the oldest event and emits `QUEUE_OVERFLOW`.
3. Wire multi-byte integers are big-endian (network order); IPv4 convenience fields are host-order `uint32_t`.
4. Template IDs and Data Set IDs for data are always ≥ 256.
5. Untrusted input never causes out-of-bounds reads; truncated messages emit `ERROR` and stop that message.

## Deliberate absences

| What | Why |
|------|-----|
| Sockets / `recvfrom` | Caller provides bytes (io_uring, epoll, …) |
| TLS / DTLS | Transport security is outside IPFIX framing |
| NetFlow v5/v9 | Separate protocol family; IPFIX only (version 10) |
| SCTP transport | Same feed API works if caller frames messages |
| Exporter / encoder | Reserved role; not implemented in v0.1 |
| Callbacks | Pull queue keeps reentrancy simple |
| Dynamic / runtime IE registry | Static IANA table + compiled enterprise tables (ADR-013) |

## Boundaries

- **Public:** everything in `include/ipfix.h`
- **Internal:** all static helpers in `src/ipfix.c`
- **Caller owns:** UDP/TCP sockets, timers for template refresh policy, persistence of templates across process restarts, fan-out to ClickHouse/Vector/etc.

## Application consumers

- **`~/apps/netforensics`** — core IPFIX ingest and flow-key correlation (design: `~/new_design3.txt`).
  Uses `ipfix_record_flow_key`, 5-tuple helpers, and BGP/next-hop convenience fields.
  ClickHouse persistence and Vector fan-in stay in the app.
