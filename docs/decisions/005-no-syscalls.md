# ADR-005: No Syscalls / I/O Offload

## Status

Accepted

## Context

High-performance collectors use io_uring, epoll, or DPDK. Embedding `recvfrom` inside the library would force a threading or blocking model and break sandbox/WASM targets.

## Decision

libipfix performs **no** syscalls: no sockets, files, clocks, or dynamic loading. Allocation uses only `malloc`/`calloc`/`free` at create/destroy. The caller feeds wire bytes and drains events.

## Consequences

- Fully portable and testable with synthetic buffers
- UDP bind, TCP accept, and timers live in the application
- Documentation must show the integration sketch clearly

## Alternatives considered

- Optional built-in UDP listener — rejected; violates the sibling-library contract
