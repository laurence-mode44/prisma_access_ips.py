#!/usr/bin/env python3
# Mode44 – Prisma Access IP Retriever
# Version: 0.1
#
# Copyright (c) 2025 Mode44 Ltd
#
# Licensed under the MIT License – see the LICENSE file in the project root
# for full license text.
#
# This tool uses the public Prisma Access IP API documented by Palo Alto
# Networks at:
#   https://pan.dev/prisma-access/docs/get-prisma-access-ip-api
#
# This project is independent from Palo Alto Networks and carries no warranty.
# Use at your own risk and validate outputs before using in production.

"""
Mode44 – Prisma Access IP Retriever
-----------------------------------

Secure helper to retrieve Prisma Access external / infrastructure IP
addresses via the official Prisma Access IP API.

Security design:
  - No credentials hard-coded.
  - API key is read from an environment variable: PRISMA_IP_API_KEY.
  - API URL can be overridden via PRISMA_IP_API_URL (for prod6, etc.).
  - Minimal logging of sensitive data; API key is never echoed.

Usage examples:

  # Basic: all services, all locations
  PRISMA_IP_API_KEY=... python3 prisma_access_ips.py

  # GP gateway addresses only, deployed locations:
  PRISMA_IP_API_KEY=... python3 prisma_access_ips.py \\
      --service-type gp_gateway --location deployed

  # Debug: show raw JSON from the API
  PRISMA_IP_API_KEY=... python3 prisma_access_ips.py --raw-json
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
from typing import Any, Dict, List

import requests

DEFAULT_API_URL = os.getenv(
    "PRISMA_IP_API_URL",
    "https://api.prod.datapath.prismaaccess.com/getPrismaAccessIP/v2",
)
API_KEY_ENV_VAR = "PRISMA_IP_API_KEY"


class PrismaAccessIPError(Exception):
    """Custom exception for Prisma Access IP retrieval issues."""


def get_api_key(env_var: str = API_KEY_ENV_VAR) -> str:
    api_key = os.getenv(env_var)
    if not api_key:
        raise PrismaAccessIPError(
            f"Missing API key. Set the environment variable {env_var} with your Prisma Access IP API key."
        )
    return api_key


def build_payload(service_type: str, addr_type: str, location: str) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "serviceType": service_type,
        "addrType": addr_type,
        "location": location,
    }
    return payload


def call_prisma_ip_api(
    api_key: str,
    payload: Dict[str, Any],
    api_url: str = DEFAULT_API_URL,
    timeout: tuple = (5, 30),
) -> Dict[str, Any]:
    headers = {
        "header-api-key": api_key,
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(api_url, headers=headers, json=payload, timeout=timeout)
    except requests.RequestException as exc:
        raise PrismaAccessIPError(f"HTTP error calling Prisma Access IP API: {exc}") from exc

    if resp.status_code != 200:
        raise PrismaAccessIPError(
            f"Non-200 response from Prisma Access IP API: {resp.status_code} – {resp.text[:200]}"
        )

    try:
        data = resp.json()
    except json.JSONDecodeError as exc:
        raise PrismaAccessIPError("Failed to decode JSON response from Prisma Access IP API") from exc

    if data.get("status") != "success":
        raise PrismaAccessIPError(
            f"API returned non-success status: {data.get('status')}, detail: {data}"
        )

    return data


def epoch_to_utc(ts: int | None) -> str:
    if ts is None:
        return "-"
    try:
        return datetime.datetime.utcfromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OSError):
        return "-"


def flatten_results(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Flatten the 'result' structure into a list of simple rows:
    zone, address, serviceType, addressType, allow_listed, create_time
    """
    results = data.get("result", [])
    rows: List[Dict[str, Any]] = []

    for loc in results:
        zone = loc.get("zone", "UNKNOWN")
        addr_details = loc.get("address_details", [])

        # IPv4 address details
        for detail in addr_details:
            rows.append(
                {
                    "zone": zone,
                    "address": detail.get("address", ""),
                    "serviceType": detail.get("serviceType", ""),
                    "addressType": detail.get("addressType", ""),
                    "allow_listed": detail.get("allow_listed", False),
                    "created": epoch_to_utc(detail.get("create_time")),
                    "ip_version": "v4",
                }
            )

        # IPv6 address details (if present)
        addr_details_v6 = loc.get("address_details_v6", [])
        for detail in addr_details_v6:
            rows.append(
                {
                    "zone": zone,
                    "address": detail.get("address", ""),
                    "serviceType": detail.get("serviceType", ""),
                    "addressType": detail.get("addressType", ""),
                    "allow_listed": detail.get("allow_listed", False),
                    "created": "-",  # create_time not always present for v6
                    "ip_version": "v6",
                }
            )

    return rows


def print_table(rows: List[Dict[str, Any]]) -> None:
    if not rows:
        print("No IP addresses returned for the given filters.")
        return

    headers = ["Zone", "IP Address", "Ver", "Service Type", "Address Type", "Allow-Listed", "Created (UTC)"]
    cols = ["zone", "address", "ip_version", "serviceType", "addressType", "allow_listed", "created"]

    col_widths = [len(h) for h in headers]
    for row in rows:
        for idx, key in enumerate(cols):
            val = str(row.get(key, ""))
            if len(val) > col_widths[idx]:
                col_widths[idx] = len(val)

    def fmt_row(values: List[str]) -> str:
        parts = []
        for idx, v in enumerate(values):
            parts.append(v.ljust(col_widths[idx]))
        return "  ".join(parts)

    print()
    print(fmt_row(headers))
    print(fmt_row(["-" * w for w in col_widths]))

    for row in rows:
        values = [str(row.get(k, "")) for k in cols]
        print(fmt_row(values))

    print()


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Retrieve Prisma Access external/infrastructure IP addresses via the Prisma Access IP API."
    )

    parser.add_argument(
        "--service-type",
        "-s",
        default="all",
        choices=[
            "all",
            "remote_network",
            "gp_gateway",
            "gp_portal",
            "clean_pipe",
            "swg_proxy",
            "rbi",
        ],
        help="Prisma Access service type to query (default: all).",
    )

    parser.add_argument(
        "--addr-type",
        "-a",
        default="all",
        choices=["all", "active", "service_ip", "auth_cache_service", "network_load_balancer"],
        help="Address type filter (default: all).",
    )

    parser.add_argument(
        "--location",
        "-l",
        default="all",
        choices=["all", "deployed"],
        help="Location filter (default: all). 'deployed' is mainly for mobile user deployments.",
    )

    parser.add_argument(
        "--raw-json",
        action="store_true",
        help="Print raw JSON response instead of a formatted table.",
    )

    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)

    try:
        api_key = get_api_key()
        payload = build_payload(
            service_type=args.service_type,
            addr_type=args.addr_type,
            location=args.location,
        )
        data = call_prisma_ip_api(api_key=api_key, payload=payload)
    except PrismaAccessIPError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    if args.raw_json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0

    rows = flatten_results(data)
    print_table(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
