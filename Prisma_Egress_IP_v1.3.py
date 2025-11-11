#!/usr/bin/env python3
# Mode44 – Prisma Access IP Retriever (Interactive)
# Version: 0.6
#
# Copyright (c) 2025 Mode44 Ltd
#
# Licensed under the MIT License – see the LICENSE file in the project root
# for full license text.
#
# References:
#   Prisma Access IP API (egress IP listing)
#   https://pan.dev/prisma-access/docs/get-prisma-access-ip-api
#
# Security notes:
#   - No secrets are hard-coded.
#   - API key is requested at runtime via a secure prompt (getpass).
#   - The key is only held in memory and never written to disk.
#   - SSL certificate validation is ENABLED by default.
#   - You can disable SSL verification for debugging, but this is insecure
#     and must be explicitly chosen in the menu.
#   - API URL is validated to ensure HTTPS and a trusted Palo Alto domain
#     unless you explicitly relax this in Advanced options.
#   - Response bodies are not logged by default to avoid leaking data.

from __future__ import annotations

import argparse
import datetime
import getpass
import json
import logging
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Tuple, TypeVar
from urllib.parse import urlparse

import requests

LOG = logging.getLogger("mode44.prisma_access_ips")

# Default Prisma Access IP API endpoint (can be changed interactively)
DEFAULT_API_URL = "https://api.prod.datapath.prismaaccess.com/getPrismaAccessIP/v2"

# Only send keys to these domains by default
TRUSTED_API_DOMAINS = (
    "prismaaccess.com",
    "paloaltonetworks.com",
)


class PrismaAccessIPError(Exception):
    """Custom exception for Prisma Access IP retrieval issues."""


@dataclass
class QuerySettings:
    service_type: str = "all"
    addr_type: str = "all"
    location: str = "all"
    api_url: str = DEFAULT_API_URL
    verify_ssl: bool = True
    allow_external_api_url: bool = False


# ---------------------------------------------------------------------------
# Logging & basic helpers
# ---------------------------------------------------------------------------

def configure_logging(level: str) -> None:
    """Configure root logging with a simple format and requested level."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )
    LOG.debug("Logging initialised at level %s", level.upper())


def validate_api_url(api_url: str, allow_external: bool = False) -> str:
    """
    Validate the API URL before we send secrets to it.

    - Must be HTTPS.
    - Host must end with a trusted Palo Alto domain, unless allow_external is True.
    """
    parsed = urlparse(api_url)

    if parsed.scheme != "https":
        raise PrismaAccessIPError(
            f"Insecure API URL scheme '{parsed.scheme}'. HTTPS is required."
        )

    host = parsed.hostname or ""
    if not allow_external and not host.endswith(TRUSTED_API_DOMAINS):
        raise PrismaAccessIPError(
            f"Refusing to send Prisma API key to non-Palo Alto domain '{host}'. "
            "If you are absolutely sure this is safe, enable 'Allow external API URL' "
            "in Advanced options."
        )

    return api_url


def epoch_to_utc(ts: int | None) -> str:
    if ts is None:
        return "-"
    try:
        return datetime.datetime.utcfromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OSError, OverflowError):
        return "-"


# ---------------------------------------------------------------------------
# Core API interaction
# ---------------------------------------------------------------------------

def build_payload(service_type: str, addr_type: str, location: str) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "serviceType": service_type,
        "addrType": addr_type,
        "location": location,
    }
    return payload


def call_prisma_ip_api(
    session: requests.Session,
    api_key: str,
    payload: Dict[str, Any],
    api_url: str,
    verify_ssl: bool,
    timeout: Tuple[int, int] = (5, 30),
) -> Dict[str, Any]:
    """
    Call the Prisma Access IP API and return the parsed JSON payload.

    - Uses a requests.Session for connection reuse.
    - Uses safe timeouts (connect, read).
    - Avoids logging response bodies at INFO level.
    """
    headers = {
        "header-api-key": api_key,
        "Content-Type": "application/json",
        "User-Agent": "Mode44-PrismaAccessIP/0.6 (Python requests)",
    }

    LOG.debug(
        "Calling Prisma IP API at %s with payload %s (verify_ssl=%s)",
        api_url,
        payload,
        verify_ssl,
    )

    try:
        resp = session.post(
            api_url,
            headers=headers,
            json=payload,
            timeout=timeout,
            verify=verify_ssl,
        )
    except requests.RequestException as exc:
        raise PrismaAccessIPError(f"HTTP error calling Prisma Access IP API: {exc}") from exc

    LOG.debug("Prisma IP API HTTP status: %s", resp.status_code)

    if resp.status_code != 200:
        # Do NOT log resp.text here to avoid leaking any content.
        raise PrismaAccessIPError(
            f"Non-200 response from Prisma Access IP API: {resp.status_code} "
            f"(response body length {len(resp.text)} bytes)"
        )

    try:
        data = resp.json()
    except json.JSONDecodeError as exc:
        raise PrismaAccessIPError("Failed to decode JSON response from Prisma Access IP API") from exc

    status = data.get("status")
    if status != "success":
        LOG.debug("API returned non-success status payload: %s", data)
        raise PrismaAccessIPError(
            f"API returned non-success status: {status or 'UNKNOWN'}"
        )

    return data


def flatten_results(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Flatten and aggregate the 'result' structure into unique rows.

    Aggregation key:
      (zone, address, ip_version)

    For each key we aggregate:
      - serviceType   -> comma-separated list of distinct values
      - addressType   -> comma-separated list of distinct values
      - allow_listed  -> True if any record is True
      - created       -> earliest non-null create_time (or "-" if none)
    """
    results = data.get("result", [])
    aggregated: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    for loc in results:
        zone = loc.get("zone", "UNKNOWN")

        # IPv4 address details
        addr_details = loc.get("address_details", []) or []
        for detail in addr_details:
            address = detail.get("address", "")
            if not address:
                continue
            key = (zone, address, "v4")

            record = aggregated.setdefault(
                key,
                {
                    "zone": zone,
                    "address": address,
                    "ip_version": "v4",
                    "service_types": set(),
                    "address_types": set(),
                    "allow_listed": False,
                    "created_ts": None,  # earliest epoch
                },
            )

            svc = detail.get("serviceType")
            if svc:
                record["service_types"].add(str(svc))

            addr_type = detail.get("addressType")
            if addr_type:
                record["address_types"].add(str(addr_type))

            if detail.get("allow_listed"):
                record["allow_listed"] = True

            ct = detail.get("create_time")
            if isinstance(ct, (int, float, str)):
                try:
                    ts = int(ct)
                except (ValueError, TypeError):
                    ts = None
                if ts is not None:
                    current = record["created_ts"]
                    if current is None or ts < current:
                        record["created_ts"] = ts

        # IPv6 address details, if present
        addr_details_v6 = loc.get("address_details_v6", []) or []
        for detail in addr_details_v6:
            address = detail.get("address", "")
            if not address:
                continue
            key = (zone, address, "v6")

            record = aggregated.setdefault(
                key,
                {
                    "zone": zone,
                    "address": address,
                    "ip_version": "v6",
                    "service_types": set(),
                    "address_types": set(),
                    "allow_listed": False,
                    "created_ts": None,
                },
            )

            svc = detail.get("serviceType")
            if svc:
                record["service_types"].add(str(svc))

            addr_type = detail.get("addressType")
            if addr_type:
                record["address_types"].add(str(addr_type))

            if detail.get("allow_listed"):
                record["allow_listed"] = True

            # IPv6 create_time may not be present; ignore if missing
            ct = detail.get("create_time")
            if isinstance(ct, (int, float, str)):
                try:
                    ts = int(ct)
                except (ValueError, TypeError):
                    ts = None
                if ts is not None:
                    current = record["created_ts"]
                    if current is None or ts < current:
                        record["created_ts"] = ts

    rows: List[Dict[str, Any]] = []

    for (zone, address, ip_version), rec in aggregated.items():
        created_str = epoch_to_utc(rec["created_ts"]) if rec["created_ts"] is not None else "-"
        rows.append(
            {
                "zone": zone,
                "address": address,
                "ip_version": ip_version,
                "serviceType": ", ".join(sorted(rec["service_types"])) if rec["service_types"] else "",
                "addressType": ", ".join(sorted(rec["address_types"])) if rec["address_types"] else "",
                "allow_listed": rec["allow_listed"],
                "created": created_str,
            }
        )

    # Optional: sort rows for stable output (zone, then address, then ver)
    rows.sort(key=lambda r: (r["zone"], r["address"], r["ip_version"]))
    return rows


def print_table(rows: List[Dict[str, Any]]) -> None:
    """Print a simple, human-readable table to stdout."""
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


# ---------------------------------------------------------------------------
# Public library entrypoint
# ---------------------------------------------------------------------------

def fetch_prisma_ips(
    api_key: str,
    settings: QuerySettings,
) -> List[Dict[str, Any]]:
    """
    High-level helper: validate URL, call API, return flattened rows.

    This is the function other Mode44 tools can import.
    """
    safe_url = validate_api_url(settings.api_url, allow_external=settings.allow_external_api_url)

    with requests.Session() as session:
        data = call_prisma_ip_api(
            session=session,
            api_key=api_key,
            payload=build_payload(settings.service_type, settings.addr_type, settings.location),
            api_url=safe_url,
            verify_ssl=settings.verify_ssl,
        )

    rows = flatten_results(data)
    return rows


# ---------------------------------------------------------------------------
# Spinner helper (status bar)
# ---------------------------------------------------------------------------

T = TypeVar("T")


def run_with_spinner(message: str, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """
    Run a function while displaying a simple spinner status line.

    - Spinner runs in a daemon thread.
    - No secrets are passed into the spinner; it only sees the message string.
    """
    stop_event = threading.Event()
    spinner_chars = "|/-\\"

    def spinner() -> None:
        i = 0
        while not stop_event.is_set():
            sys.stdout.write(
                "\r" + message + " " + "[" + spinner_chars[i % len(spinner_chars)] + "]"
            )
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1
        # Clear the line when done
        sys.stdout.write("\r" + " " * (len(message) + 6) + "\r")
        sys.stdout.flush()

    thread = threading.Thread(target=spinner, daemon=True)
    thread.start()

    try:
        result = func(*args, **kwargs)
    finally:
        stop_event.set()
        thread.join()

    return result


# ---------------------------------------------------------------------------
# Interactive prompts & menus
# ---------------------------------------------------------------------------

def prompt_api_key() -> str:
    """Securely prompt the user for the Prisma API key."""
    while True:
        key = getpass.getpass("Enter Prisma Access IP API key: ")
        if key.strip():
            return key.strip()
        print("API key cannot be empty. Please try again.")


def show_current_settings(settings: QuerySettings) -> None:
    print()
    print("Current settings:")
    print(f"  Service type : {settings.service_type}")
    print(f"  Address type : {settings.addr_type}")
    print(f"  Location     : {settings.location}")
    print(f"  SSL verify   : {'ON' if settings.verify_ssl else 'OFF'}")
    print(f"  API URL      : {settings.api_url}")
    print(f"  External URL : {'ALLOWED' if settings.allow_external_api_url else 'RESTRICTED'}")
    print()


def menu_select_service_type(current: str) -> str:
    options = [
        ("all", "All service types"),
        ("gp_gateway", "GlobalProtect gateway"),
        ("gp_portal", "GlobalProtect portal"),
        ("remote_network", "Remote Networks"),
        ("clean_pipe", "Clean Pipe"),
        ("swg_proxy", "SWG proxy"),
        ("rbi", "Remote Browser Isolation"),
    ]

    print("\nSelect service type:")
    for idx, (value, desc) in enumerate(options, start=1):
        marker = "*" if value == current else " "
        print(f"  {idx}) {value:<14} {desc} {marker}")

    choice = input(f"Choice [current: {current}]: ").strip()
    if not choice:
        return current

    try:
        idx = int(choice)
        if 1 <= idx <= len(options):
            return options[idx - 1][0]
    except ValueError:
        pass

    print("Invalid choice, keeping current.")
    return current


def menu_select_addr_type(current: str) -> str:
    options = [
        ("all", "All address types"),
        ("active", "Active addresses"),
        ("service_ip", "Service IPs"),
        ("auth_cache_service", "Auth cache service"),
        ("network_load_balancer", "Network load balancer IPs"),
    ]

    print("\nSelect address type:")
    for idx, (value, desc) in enumerate(options, start=1):
        marker = "*" if value == current else " "
        print(f"  {idx}) {value:<20} {desc} {marker}")

    choice = input(f"Choice [current: {current}]: ").strip()
    if not choice:
        return current

    try:
        idx = int(choice)
        if 1 <= idx <= len(options):
            return options[idx - 1][0]
    except ValueError:
        pass

    print("Invalid choice, keeping current.")
    return current


def menu_select_location(current: str) -> str:
    options = [
        ("all", "All locations"),
        ("deployed", "Deployed locations (mainly mobile users)"),
    ]

    print("\nSelect location:")
    for idx, (value, desc) in enumerate(options, start=1):
        marker = "*" if value == current else " "
        print(f"  {idx}) {value:<8} {desc} {marker}")

    choice = input(f"Choice [current: {current}]: ").strip()
    if not choice:
        return current

    try:
        idx = int(choice)
        if 1 <= idx <= len(options):
            return options[idx - 1][0]
    except ValueError:
        pass

    print("Invalid choice, keeping current.")
    return current


def menu_ssl_options(settings: QuerySettings) -> None:
    print("\nSSL / TLS options:")
    print(f"  1) Toggle SSL verification (currently: {'ON' if settings.verify_ssl else 'OFF'})")
    print("  2) Back")

    choice = input("Choice: ").strip()
    if choice == "1":
        settings.verify_ssl = not settings.verify_ssl
        if not settings.verify_ssl:
            print(
                "\nWARNING: SSL certificate validation is DISABLED.\n"
                "This is insecure and should only be used for debugging with "
                "trusted lab environments.\n"
            )
        else:
            print("SSL certificate validation is now ENABLED.")
    else:
        print("Returning to main menu.")


def menu_advanced_options(settings: QuerySettings) -> None:
    print("\nAdvanced options:")
    print(f"  1) Change API URL (current: {settings.api_url})")
    print(
        "  2) Toggle 'Allow external API URL' "
        f"(currently: {'ALLOWED' if settings.allow_external_api_url else 'RESTRICTED'})"
    )
    print("  3) Back")

    choice = input("Choice: ").strip()

    if choice == "1":
        print(
            "\nHelper: If you are using Strata Cloud Manager (SCM), you can find the "
            "correct Prisma Access IP API URL under:\n"
            "  Configuration > NGFW and Prisma Access > Scope: Prisma Access >\n"
            "  Infrastructure Settings (Prisma Access infrastructure page)\n"
        )
        new_url = input("Enter new API URL (HTTPS): ").strip()
        if not new_url:
            print("Empty input, keeping current URL.")
            return
        try:
            validate_api_url(new_url, allow_external=settings.allow_external_api_url)
        except PrismaAccessIPError as exc:
            print(f"Invalid API URL: {exc}")
            return
        settings.api_url = new_url
        print(f"API URL updated to: {settings.api_url}")

    elif choice == "2":
        settings.allow_external_api_url = not settings.allow_external_api_url
        if settings.allow_external_api_url:
            print(
                "\nWARNING: External API URLs are now ALLOWED.\n"
                "The script will no longer enforce that the host is a Palo Alto "
                "domain. Make sure you trust the endpoint before entering your API key.\n"
            )
        else:
            print("External API URLs are now RESTRICTED to trusted Palo Alto domains.")
    else:
        print("Returning to main menu.")


def menu_change_filters(settings: QuerySettings) -> None:
    """Interactive menu to change query filters."""
    while True:
        print("\nChange query filters:")
        print(f"  1) Service type (current: {settings.service_type})")
        print(f"  2) Address type (current: {settings.addr_type})")
        print(f"  3) Location     (current: {settings.location})")
        print("  4) Back")

        choice = input("Choice: ").strip()
        if choice == "1":
            settings.service_type = menu_select_service_type(settings.service_type)
        elif choice == "2":
            settings.addr_type = menu_select_addr_type(settings.addr_type)
        elif choice == "3":
            settings.location = menu_select_location(settings.location)
        else:
            break


def session_loop(api_key: str, settings: QuerySettings) -> None:
    """Main interactive session loop."""
    while True:
        show_current_settings(settings)
        choice = input(
            "Press Enter to run query with these settings, or type 'c' to change them: "
        ).strip().lower()

        if choice == "c":
            menu_change_filters(settings)
            continue

        # Run query with spinner
        try:
            rows = run_with_spinner(
                "Contacting Prisma Access IP API...",
                fetch_prisma_ips,
                api_key,
                settings,
            )
            print_table(rows)
        except PrismaAccessIPError as exc:
            print(f"\n[ERROR] {exc}\n")
        except Exception as exc:
            LOG.exception("Unexpected error during Prisma IP retrieval: %s", exc)
            print("\n[ERROR] Unexpected error occurred. See logs for details.\n")

        # After each run, ask what to do next
        print("What would you like to do next?")
        print("  [R]e-run with same settings")
        print("  [C]hange query filters")
        print("  [S]SL options (enable/disable verification)")
        print("  [A]dvanced options (API URL, domain checks)")
        print("  [Q]uit")

        next_choice = input("Choice: ").strip().lower()
        if next_choice == "r":
            continue
        elif next_choice == "c":
            menu_change_filters(settings)
        elif next_choice == "s":
            menu_ssl_options(settings)
        elif next_choice == "a":
            menu_advanced_options(settings)
        elif next_choice == "q":
            print("Goodbye.")
            break
        else:
            print("Unrecognised choice, running query again with same settings.")


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Interactive Prisma Access external/infrastructure IP retriever.",
    )

    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level for diagnostics (default: INFO).",
    )

    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    configure_logging(args.log_level)

    try:
        api_key = prompt_api_key()
        settings = QuerySettings()

        # Early interactive chance to set API URL with helper text
        print("\nDefault Prisma Access IP API URL:")
        print(f"  {settings.api_url}")
        print(
            "\nIf you are using Strata Cloud Manager (SCM), you can find the correct "
            "Prisma Access IP API URL under:\n"
            "  Configuration > NGFW and Prisma Access > Scope: Prisma Access >\n"
            "  Infrastructure Settings (Prisma Access infrastructure page)\n"
        )
        early_choice = input(
            "Press Enter to keep this URL, or type 'c' to change it now (Advanced options): "
        ).strip().lower()
        if early_choice == "c":
            menu_advanced_options(settings)

        session_loop(api_key, settings)
    except KeyboardInterrupt:
        print("\nInterrupted, exiting.")
        return 1
    finally:
        # Basic hygiene: clear API key reference before exit
        api_key = None  # type: ignore[assignment]

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
