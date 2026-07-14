# ADR-001: Pure C Choice

## Status

Accepted

## Context

The library must embed in C and C++ collectors, OpenWrt-class devices, and high-performance io_uring services alongside sibling libraries (libnetdiag, libharness, libslack).

## Decision

Implement libipfix in pure C11 with no external dependencies beyond the C standard library.

## Consequences

- Maximum portability and trivial static linking
- No C++ runtime requirement
- Callers manage higher-level memory and concurrency patterns

## Alternatives considered

- C++17 with std::span — rejected for ABI and dependency reasons across the sibling set
- Rust crate with C FFI — rejected for consistency with existing pure-C libraries
