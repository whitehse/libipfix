# ADR-013: Static Enterprise IE Registry

## Status

Accepted

## Context

IPFIX Information Elements may be IANA-registered (enterprise number 0) or
vendor-specific (enterprise bit set + Private Enterprise Number). Calix E7/AXOS
OLTs export Fiber PON, ONT optical, and BNG metrics under PEN **6321** with
hundreds of IEs (`enterprises/enterprise_calix_ipfix.csv`).

The library already stored enterprise numbers on field specs and decoded short
enterprise values as unsigned integers. That was insufficient for:

- **Strings** (hostname, port, ONT id, AIDs) misclassified when ≤ 8 bytes
- **Signed** optical power / temperature values (negative dBm)
- **Discovery** of human-readable names without an external dictionary

A fully dynamic, runtime-loaded IE registry would need heap growth, file I/O,
or callbacks — all outside the library’s syscall-free, fixed-memory model.

## Decision

1. Ship **static** per-PEN lookup tables compiled into the library (binary search
   by element ID).
2. First table: **Calix PEN 6321**, generated from
   `enterprises/enterprise_calix_ipfix.csv` via
   `enterprises/gen_calix_ies.py` into:
   - `include/ipfix_enterprise_calix.h` — `IPFIX_PEN_CALIX`, `IPFIX_CALIX_IE_*`
   - `src/enterprise_calix.inc` — name + abstract datatype per IE
3. Extend value kinds with `IPFIX_VALUE_INT` and `IPFIX_VALUE_FLOAT`.
4. Expose `ipfix_enterprise_ie_name()` and `ipfix_enterprise_ie_datatype()`.
5. Unknown enterprise IEs keep the previous heuristic (≤ 8 bytes → UINT, else RAW).

## Consequences

- Calix Fiber PON records decode with correct STRING / UINT / INT / FLOAT kinds
- Callers can print and filter by name without embedding the CSV
- Adding another vendor is a new generated table + a branch in the lookup switch
- Regenerating the table after CSV updates is a deliberate build step (not runtime)

## Alternatives considered

- **Runtime CSV load** — requires file I/O and allocation; rejected (ADR-005)
- **Only raw enterprise bytes** — forces every caller to re-implement Calix types
- **Grow `ipfix_data_record_t` convenience fields for every Calix IE** — bloated
  event size; prefer `ipfix_record_find_enterprise_field` (ADR-008)
