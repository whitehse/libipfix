#!/usr/bin/env python3
"""Generate Calix enterprise IE header and lookup table from CSV.

Usage (from repo root):
    python3 enterprises/gen_calix_ies.py

Reads:  enterprises/enterprise_calix_ipfix.csv
Writes: include/ipfix_enterprise_calix.h
        src/enterprise_calix.inc
"""
from __future__ import annotations

import csv
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = Path(__file__).resolve().parent / "enterprise_calix_ipfix.csv"
HDR_PATH = ROOT / "include" / "ipfix_enterprise_calix.h"
INC_PATH = ROOT / "src" / "enterprise_calix.inc"

# CSV typos use 6421 for two rows; Calix IANA PEN is 6321.
CALIX_PEN = 6321


def sanitize(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_]", "_", name.strip())
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        s = "unnamed"
    if s[0].isdigit():
        s = "ie_" + s
    return s


def map_type(dt: str) -> str:
    dt = dt.split(".")[0].strip().lower()
    if dt in ("uint8", "uint16", "uint32", "uint64", "packets"):
        return "IPFIX_IE_DT_UNSIGNED"
    if dt in ("int8", "int16", "int32", "int64"):
        return "IPFIX_IE_DT_SIGNED"
    if dt in ("float", "float32", "float64", "double"):
        return "IPFIX_IE_DT_FLOAT"
    if dt == "string":
        return "IPFIX_IE_DT_STRING"
    return "IPFIX_IE_DT_UNKNOWN"


def main() -> None:
    by_id: dict[int, tuple[int, str, str, str]] = {}
    with CSV_PATH.open(newline="") as f:
        for row in csv.DictReader(f):
            eid = int(row["ie-id"])
            pen = int(row["ieenterprise-id"])
            if pen == 6421:
                pen = CALIX_PEN
            name = row["field name"].strip()
            dt = row["Element Data Type"].strip()
            if eid not in by_id:
                by_id[eid] = (eid, name, dt, map_type(dt))

    entries = sorted(by_id.values(), key=lambda x: x[0])

    used: dict[str, int] = {}
    defines: list[tuple[str, int, str]] = []
    for eid, name, _dt, _mapped in entries:
        base = sanitize(name)
        key = base if base not in used else f"{base}_{eid}"
        used[key] = eid
        defines.append((key, eid, name))

    hdr_lines = [
        "/*",
        " * Auto-generated from enterprises/enterprise_calix_ipfix.csv",
        " * Do not edit by hand — re-run: python3 enterprises/gen_calix_ies.py",
        " */",
        "",
        "#ifndef IPFIX_ENTERPRISE_CALIX_H",
        "#define IPFIX_ENTERPRISE_CALIX_H",
        "",
        "/** Calix Private Enterprise Number (IANA PEN). */",
        f"#define IPFIX_PEN_CALIX {CALIX_PEN}u",
        "",
        "/* Calix E7 / AXOS Information Element IDs (enterprise IPFIX_PEN_CALIX). */",
    ]
    for key, eid, name in defines:
        hdr_lines.append(
            f"#define IPFIX_CALIX_IE_{key:40s} {eid}u  /* {name} */"
        )
    hdr_lines += ["", "#endif /* IPFIX_ENTERPRISE_CALIX_H */", ""]
    HDR_PATH.write_text("\n".join(hdr_lines))

    inc_lines = [
        "/* Auto-generated from enterprises/enterprise_calix_ipfix.csv — do not edit. */",
        "static const ipfix_enterprise_ie_desc_t ipfix_calix_ies[] = {",
    ]
    for eid, name, _dt, mapped in entries:
        cname = name.replace("\\", "\\\\").replace('"', '\\"')
        inc_lines.append(f'    {{ {eid}u, {mapped}, "{cname}" }},')
    inc_lines += [
        "};",
        f"static const size_t ipfix_calix_ies_count = {len(entries)}u;",
        "",
    ]
    INC_PATH.write_text("\n".join(inc_lines))

    print(f"Wrote {HDR_PATH.relative_to(ROOT)} ({len(entries)} IEs)")
    print(f"Wrote {INC_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
