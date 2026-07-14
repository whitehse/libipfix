# ADR-009: Strict Compiler Warnings

## Status

Accepted

## Context

Sibling libraries compile with `-Wall -Wextra -Wpedantic -Werror` and related flags.

## Decision

Enable the same strict warning set in CMake for libipfix. Treat warnings as errors.

## Consequences

- Cleaner code and fewer accidental integer conversions
- Slightly more verbose casts in wire parsing (intentional)
