# ADR-004: No Callbacks

## Status

Accepted

## Context

Callback APIs complicate reentrancy, lifetime of nested state, and integration with cooperative event loops.

## Decision

All output is consumed via `ipfix_next_event`. No function-pointer registration.

## Consequences

- Simple, uniform API matching libjsparse / libcdp / libslack
- Caller controls pacing
- No callback context lifetime bugs

## Alternatives considered

- Per-record callback with user pointer — rejected for consistency with sibling libraries
