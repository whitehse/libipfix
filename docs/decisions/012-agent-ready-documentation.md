# ADR-012: Agent-Ready Documentation

## Status

Accepted

## Date

2026-07-14

## Context

This codebase is prepared for AI agent work using the same progressive-disclosure structure as libjsparse, libslack, and other sibling libraries.

## Decision

Adopt:

- `AGENTS.md` as the concise entry point (~100 lines) with directives and ADR index
- `CLAUDE.md` as a symlink to `AGENTS.md`
- `ARCHITECTURE.md` as codemap, invariants, and deliberate absences
- `docs/DOMAIN.md` for IPFIX protocol knowledge
- `docs/decisions/` for ADRs
- `docs/README.md` as documentation index

## Consequences

- Agents orient quickly without loading the full implementation
- Design decisions are reviewable and durable
- Documentation changes should be reviewed like code

## Alternatives considered

- Single large README — rejected; crowds context and rots
- Docs only in headers — rejected; agents need navigational structure
