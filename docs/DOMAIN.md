# DOMAIN.md — IPFIX (IP Flow Information Export)

## What IPFIX is

IPFIX is an IETF protocol (RFC 7011) for exporting flow and metering information from network devices (routers, switches, probes) to collectors. It is the standardized successor to Cisco NetFlow.

In the sibling network-forensics design, core routers export IPFIX flow logs that are correlated with CPE NAT/conntrack and BGP state.

## Roles

| Role | Description |
|------|-------------|
| **Exporting Process** | Device that meters traffic and sends IPFIX messages |
| **Collecting Process** | Receiver that parses templates and data records (this library) |
| **Observation Domain** | Scope identifier (`observationDomainId`) grouping metering points |

libipfix implements the **Collecting Process** protocol state (parse + template cache). It does not implement metering.

## Message structure

```
IPFIX Message
├── Message Header (16 bytes)
│     version=10, length, exportTime, sequenceNumber, observationDomainId
└── one or more Sets
      ├── Template Set (Set ID = 2)
      ├── Options Template Set (Set ID = 3)
      └── Data Sets (Set ID = Template ID ≥ 256)
```

### Message header fields

| Field | Meaning |
|-------|---------|
| Version | Always 10 for IPFIX |
| Length | Total message size including header |
| Export Time | Seconds since Unix epoch at export |
| Sequence Number | Incremental counter for loss detection |
| Observation Domain ID | Identifies the observation domain |

### Templates

A **Template Record** describes the layout of subsequent Data Records: an ordered list of Information Elements (IEs), each with an element ID, length, and optional enterprise number.

- Template ID ∈ [256, 65535]
- `field_count == 0` means **template withdrawal**
- Options Templates add a **scope** field count; scope fields identify what the options apply to

### Information Elements (IEs)

IEs are registered with IANA (enterprise number 0) or are vendor-specific (enterprise bit set + enterprise number).

### Enterprise (vendor) IEs

When the high bit of the template field’s element ID is set, the next four
bytes are a **Private Enterprise Number (PEN)**. libipfix stores the stripped
element ID and the PEN on every field, and looks up known PENs in a static
registry for name and abstract datatype.

| PEN | Vendor | Coverage in libipfix |
|-----|--------|---------------------|
| 6321 | Calix | Full E7/AXOS table from `enterprises/enterprise_calix_ipfix.csv` (Fiber PON, ONT optical, Ethernet, BNG, …) |

Calix Fiber PON records typically mix IANA flow IEs (if any) with enterprise
identity and counters, for example:

| Calix IE id | Name | Type | Role |
|-------------|------|------|------|
| 1 | hostname | string | OLT host |
| 2 / 3 | shelf / slot | uint8 | Chassis location |
| 4 | port | string | PON / eth port |
| 7 | ont-id | string | Optical Network Terminal |
| 8 / 9 | svlan / cvlan | uint16 | VLAN tags |
| 231 | rx-opticalpower2 | int32 | Received optical power |
| 208 / 209 | upstream/downstream-octets | uint64 | Bin counters |

Use `ipfix_record_find_enterprise_field(rec, IPFIX_PEN_CALIX, IPFIX_CALIX_IE_…)`
and `ipfix_enterprise_ie_name()` when processing these records.

Common flow IEs used in network forensics:

| ID | Name | Typical use |
|----|------|-------------|
| 1 | octetDeltaCount | Bytes in the flow interval |
| 2 | packetDeltaCount | Packets in the flow interval |
| 4 | protocolIdentifier | IP protocol (6=TCP, 17=UDP, …) |
| 7 | sourceTransportPort | Source L4 port |
| 8 | sourceIPv4Address | Source IPv4 |
| 11 | destinationTransportPort | Destination L4 port |
| 12 | destinationIPv4Address | Destination IPv4 |
| 10 / 14 | ingress/egressInterface | Interface indices |
| 16 / 17 | bgpSource/DestinationAsNumber | BGP AS path context |
| 27 / 28 | source/destinationIPv6Address | IPv6 endpoints |
| 152 / 153 | flowStart/EndMilliseconds | High-resolution flow timing |

Variable-length IEs use length 65535 in the template; the data record prefixes the value with a 1-byte length (0–254) or `0xFF` + 2-byte length.

## Transport

| Transport | Framing |
|-----------|---------|
| **UDP** | One (or more complete) IPFIX message(s) per datagram — use `ipfix_feed_message` |
| **TCP** | Stream of messages; Length field provides framing — use `ipfix_feed_input` |
| **SCTP** | Similar to TCP from the library's perspective |

The library never opens sockets. The collector application binds UDP 4739 (or a site-specific port), reads datagrams, and feeds them in.

## What the library does **not** do

- Detect export loss beyond exposing `sequenceNumber` on MESSAGE events (caller tracks gaps)
- Persist templates across process restarts (caller may serialize `ipfix_get_template` results)
- Interpret sampling algorithms beyond exposing option fields
- Validate IE semantic constraints (e.g. port range); it decodes wire layout only
- Speak NetFlow v5 or v9

## Glossary

| Term | Definition |
|------|------------|
| Flow | Set of packets sharing key fields (e.g. 5-tuple) over a time interval |
| Metering Process | Component that creates flow records from packet observation |
| Template | Schema mapping Data Record bytes to named IEs |
| Observation Point | Location in the network where packets are observed |
| Collector | Receiving process (libipfix + caller I/O) |
