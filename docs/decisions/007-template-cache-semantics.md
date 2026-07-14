# ADR-007: Template Cache Semantics

## Status

Accepted

## Context

Data Sets are meaningless without prior Template Records. Exporters may send templates once and data for a long time. Process restarts lose in-memory templates.

## Decision

- Store templates in a fixed-capacity array (`max_templates`)
- Replace on redefinition of the same Template ID
- Withdraw on `field_count == 0`
- `ipfix_reset` **retains** templates; `ipfix_clear_templates` drops them
- Unknown Data Set IDs emit `UNKNOWN_TEMPLATE` unless `drop_unknown_sets` is set

## Consequences

- Matches operational IPFIX practice
- Callers that fork workers must share or re-learn templates
- Cache exhaustion emits `TOO_MANY_TEMPLATES`

## Alternatives considered

- Discard templates on reset — rejected; breaks multi-message sessions in tests and long-lived collectors
