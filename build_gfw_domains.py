#!/usr/bin/env python3
"""Build a deduplicated registrable-domain list from gfwlist."""

from __future__ import annotations

import base64
import ipaddress
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen

from publicsuffix2 import get_sld


SOURCE_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/refs/heads/master/gfwlist.txt"
OUTPUT_FILE = Path("gfw_domains.txt")

DOMAIN_RE = re.compile(r"^[a-z0-9.-]+$")


@dataclass
class Stats:
    raw_lines: int = 0
    candidate_hosts: int = 0
    output_domains: int = 0


def fetch_text(url: str) -> str:
    with urlopen(url, timeout=30) as response:  # nosec B310
        return response.read().decode("utf-8", errors="replace")


def decode_gfwlist(encoded: str) -> str:
    payload = "".join(line.strip() for line in encoded.splitlines() if line.strip())
    decoded = base64.b64decode(payload, validate=False)
    return decoded.decode("utf-8", errors="replace")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_rule_to_host(rule: str) -> str | None:
    item = rule.strip().lower()
    if not item:
        return None
    if item.startswith(("!", "[")):
        return None
    if item.startswith("@@"):
        return None
    if item.startswith("/") and item.endswith("/"):
        return None

    item = item.lstrip("|")

    if "://" in item:
        host = urlsplit(item).hostname
        if not host:
            return None
    else:
        for sep in ("/", "^", "?"):
            if sep in item:
                item = item.split(sep, 1)[0]
        host = item

    host = host.strip().strip(".")
    if host.startswith("*."):
        host = host[2:]

    if ":" in host and not host.startswith("["):
        host = host.split(":", 1)[0]

    if not host or "*" in host:
        return None
    if not DOMAIN_RE.fullmatch(host):
        return None
    if is_ip(host):
        return None
    if "." not in host:
        return None
    return host


def extract_domains(decoded_text: str, stats: Stats) -> list[str]:
    domains: set[str] = set()
    for line in decoded_text.splitlines():
        stats.raw_lines += 1
        host = normalize_rule_to_host(line)
        if not host:
            continue
        stats.candidate_hosts += 1
        sld = get_sld(host)
        if not sld or "." not in sld:
            continue
        domains.add(sld)

    result = sorted(domains)
    stats.output_domains = len(result)
    return result


def write_output(domains: list[str], path: Path) -> None:
    path.write_text("\n".join(domains) + "\n", encoding="utf-8")


def main() -> int:
    stats = Stats()
    encoded = fetch_text(SOURCE_URL)
    decoded = decode_gfwlist(encoded)
    domains = extract_domains(decoded, stats)
    write_output(domains, OUTPUT_FILE)

    print(f"source: {SOURCE_URL}")
    print(f"raw lines: {stats.raw_lines}")
    print(f"candidate hosts: {stats.candidate_hosts}")
    print(f"output domains: {stats.output_domains}")
    print(f"written: {OUTPUT_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
