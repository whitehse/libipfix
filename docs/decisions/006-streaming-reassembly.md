# ADR-006: Streaming Reassembly vs Datagram Feed

## Status

Accepted

## Context

IPFIX runs over UDP (datagram-aligned messages) and TCP (byte stream with Length framing).

## Decision

Provide two entry points:

- `ipfix_feed_message` — one complete message (typical UDP path)
- `ipfix_feed_input` — append to an internal buffer and extract messages by the Length field (TCP / partial reads)

## Consequences

- UDP path avoids unnecessary copies when the datagram is already a full message
- TCP path works with arbitrary chunk sizes from the event loop
- Reassembly buffer size is capped by `max_input_buffer`

## Alternatives considered

- Single feed API always copying — simpler but slower for UDP
- Caller-only framing — shifts TCP Length parsing onto every application
