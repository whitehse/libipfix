# ADR-003: Ring-Buffer Event Queue

## Status

Accepted

## Context

Parsed templates and data records must be delivered to the caller without unbounded memory growth under load.

## Decision

Use a fixed-size ring buffer allocated at creation. On overflow, drop the oldest event, increment `ipfix_dropped_count`, and emit `IPFIX_EVENT_QUEUE_OVERFLOW`.

## Consequences

- Bounded memory after `ipfix_create*`
- Caller must drain promptly under high flow rates
- Queue size is configurable via `ipfix_config_t.event_queue_size`

## Alternatives considered

- Unbounded linked list — rejected (OOM risk)
- Callbacks per record — rejected (see ADR-004)
