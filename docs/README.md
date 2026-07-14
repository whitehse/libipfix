# docs/README.md — libipfix Documentation

## Overview

libipfix is a pure C library for receiving and parsing IPFIX (RFC 7011) messages. It is designed for high-rate collectors where the application owns sockets and event loops (io_uring, epoll, libuv, …).

## Purpose

Core routers and probes export flow telemetry as IPFIX. A collector must learn templates, decode data records, and hand structured fields to storage or analytics. libipfix isolates the protocol machinery from I/O so it can sit inside any event-driven pipeline without blocking.

## Contents

- [DOMAIN.md](DOMAIN.md) — IPFIX protocol concepts, IEs, transport
- [decisions/](decisions/) — Architecture Decision Records (ADRs 001–012)

## Quick start

```c
#include <ipfix.h>

ipfix_ctx_t *ctx = ipfix_create();
ipfix_feed_message(ctx, datagram, datagram_len);

ipfix_event_t ev;
while (ipfix_next_event(ctx, &ev) == 1) {
    if (ev.type == IPFIX_EVENT_DATA_RECORD) {
        /* use ev.data.record.src_ipv4, dst_port, ... */
    }
}
ipfix_destroy(ctx);
```

## API summary

| Function | Purpose |
|----------|---------|
| `ipfix_create` / `ipfix_create_with_config` | Create collector context |
| `ipfix_destroy` | Free resources |
| `ipfix_reset` | Clear queue/reassembly; keep templates |
| `ipfix_clear_templates` | Drop template cache |
| `ipfix_feed_input` | Stream chunks (TCP reassembly) |
| `ipfix_feed_message` | One complete message (UDP) |
| `ipfix_next_event` | Dequeue next event |
| `ipfix_get_template` | Look up learned template |
| `ipfix_record_find_field` | Find IE in a data record |

## Integration sketch (io_uring / event loop)

1. Application binds UDP socket and submits `recv` (or `recvmsg`) via io_uring.
2. On completion, call `ipfix_feed_message(ctx, buf, n)`.
3. Drain `ipfix_next_event` until empty; enqueue DB writes or hand to Vector/ClickHouse.
4. Never call `recv`/`read` from inside libipfix — it has no I/O.
