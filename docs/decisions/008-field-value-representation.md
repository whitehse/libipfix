# ADR-008: Field Value Representation

## Status

Accepted

## Context

Information Elements vary in type and length. Callers need both generic access and a fast path for the common 5-tuple flow keys.

## Decision

- Each field is an `ipfix_field_t` with a `kind` discriminant (`UINT`, `INT`, `FLOAT`, `IPV4`, `IPV6`, `MAC`, `STRING`, `RAW`)
- Common IANA IEs are also mirrored into convenience members on `ipfix_data_record_t`
- IPv4 convenience values are **host byte order** `uint32_t`
- Enterprise IEs use a static registry (ADR-013) to choose kind; unknown PENs use length heuristics
- Unknown / oversized values are truncated into `RAW`

## Consequences

- One allocation-free representation for all IEs
- Fast path for forensics-style 5-tuple extraction
- Enterprise IEs remain accessible via `ipfix_record_find_enterprise_field`
- Signed optical / temperature vendor fields decode as `IPFIX_VALUE_INT`

## Alternatives considered

- Only raw byte slices — too much work for every caller
- Fully dynamic typed heap objects — conflicts with no-alloc-after-create
