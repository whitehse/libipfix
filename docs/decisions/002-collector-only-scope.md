# ADR-002: Collector-Only Scope (v0.1)

## Status

Accepted

## Context

IPFIX defines both Exporting and Collecting Processes. Encoding exporters adds template generation, MTU packing, and rate control complexity.

## Decision

v0.1 implements **collector** parsing only. `IPFIX_ROLE_EXPORTER` is reserved in the API but not implemented.

## Consequences

- Smaller, auditable parser focused on untrusted input
- Exporters can be added later without breaking collector API
- Callers that need to generate IPFIX must use another tool for now

## Alternatives considered

- Full codec in v0.1 — deferred to keep the first release focused
