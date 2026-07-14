# ADR-011: Man Page Conventions

## Status

Accepted

## Context

Sibling libraries install section 3 man pages for primary entry points.

## Decision

Provide `man/man3/ipfix_create.3` covering lifecycle and pointing to feed/event functions. Install via CMake GNUInstallDirs.

## Consequences

- System `man ipfix_create` works after install
- Full API remains documented in `ipfix.h` and docs/
