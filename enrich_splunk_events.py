import ipaddress
import json
import os
import subprocess
import sys
from pathlib import Path

import keyring
import requests
import urllib3


BASE_DIR = Path(__file__).resolve().parent

ENRICHMENT_FILE = BASE_DIR / "vt_enrichment.jsonl"
VT_SCRIPT = BASE_DIR / "vt_enrichment.py"

SPLUNK_EXPORT_URL = "https://127.0.0.1:8089/services/search/jobs/export"

MAX_IPS_PER_RUN = 3

CREDENTIAL_SERVICE = "SOC-Lab-Automation"

SPL_QUERY = r'''
search index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=-24h
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| where EventCode="3"
| rex field=_raw "Name='Image'>(?<Image>[^<]*)</Data>"
| rex field=_raw "Name='User'>(?<User>[^<]*)</Data>"
| rex field=_raw "Name='DestinationIp'>(?<DestinationIp>[^<]*)</Data>"
| rex field=_raw "Name='DestinationPort'>(?<DestinationPort>[^<]*)</Data>"
| rex field=_raw "Name='Protocol'>(?<Protocol>[^<]*)</Data>"
| where isnotnull(DestinationIp)
| table _time Image User DestinationIp DestinationPort Protocol
| sort 0 - _time
'''


def load_credentials():
    """Load credentials from Windows Credential Manager."""

    try:
        username = keyring.get_password(
            CREDENTIAL_SERVICE, "SPLUNK_USERNAME"
        )

        splunk_password = keyring.get_password(
            CREDENTIAL_SERVICE, "SPLUNK_PASSWORD"
        )

        vt_api_key = keyring.get_password(
            CREDENTIAL_SERVICE, "VT_API_KEY"
        )

    except Exception as error:
        raise RuntimeError(
            f"Could not access Windows Credential Manager: {error}"
        ) from error

    if not all([username, splunk_password, vt_api_key]):
        raise RuntimeError(
            "Missing credentials in Windows Credential Manager. "
            "Run setup_credentials.py again."
        )

    # These environment variables are inherited by child processes.
    os.environ["SPLUNK_USERNAME"] = username
    os.environ["SPLUNK_PASSWORD"] = splunk_password
    os.environ["VT_API_KEY"] = vt_api_key

    print("[SUCCESS] Credentials loaded securely.")


def fetch_splunk_events():
    """Fetch recent Sysmon network events directly from Splunk."""

    username = os.getenv("SPLUNK_USERNAME")
    password = os.getenv("SPLUNK_PASSWORD")

    if not username or not password:
        raise RuntimeError("Splunk credentials are unavailable.")

    print("\nConnecting to Splunk REST API...")

    response = None

    try:
        response = requests.post(
            SPLUNK_EXPORT_URL,
            auth=(username, password),
            data={
                "search": SPL_QUERY,
                "output_mode": "json"
            },
            verify=False,
            stream=True,
            timeout=(10, 90)
        )

        if response.status_code == 401:
            raise RuntimeError("Splunk authentication failed.")

        response.raise_for_status()

        events = []

        for line in response.iter_lines():
            if not line:
                continue

            try:
                payload = json.loads(line.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue

            if payload.get("result"):
                events.append(payload["result"])

            for message in payload.get("messages", []):
                if message.get("type") == "ERROR":
                    raise RuntimeError(
                        message.get("text", "Splunk search failed.")
                    )

        print("Splunk connection successful.")
        print(f"Sysmon network events retrieved: {len(events)}")

        return events

    except requests.RequestException as error:
        raise RuntimeError(
            f"Could not retrieve events from Splunk: {error}"
        ) from error

    finally:
        if response is not None:
            response.close()


def load_enriched_ips():
    """Load previously enriched IP addresses."""

    enriched = set()

    if not ENRICHMENT_FILE.exists():
        return enriched

    with ENRICHMENT_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            try:
                record = json.loads(line)

                if record.get("ip"):
                    enriched.add(record["ip"])

            except json.JSONDecodeError:
                continue

    return enriched


def normalize_ip(raw_ip):
    """Validate globally routable unicast IPv4 addresses."""

    if not isinstance(raw_ip, str):
        return None

    try:
        ip = ipaddress.ip_address(raw_ip.strip())

        # Convert IPv4-mapped IPv6 addresses to IPv4.
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped

        # Reject non-global and non-unicast addresses.
        if (
            not ip.is_global
            or ip.is_multicast
            or ip.is_unspecified
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
        ):
            return None

        # This lab enriches IPv4 destinations only.
        if ip.version != 4:
            return None

        return str(ip)

    except ValueError:
        return None


def extract_public_ips(events, enriched_ips):
    """Identify public IPs not previously enriched."""

    candidates = {}

    for event in events:

        ip = normalize_ip(event.get("DestinationIp"))

        if not ip:
            continue

        if ip in enriched_ips:
            continue

        candidates.setdefault(
            ip,
            {
                "process": event.get("Image"),
                "user": event.get("User"),
                "port": event.get("DestinationPort"),
                "protocol": event.get("Protocol")
            }
        )

    return candidates


def run_enrichment(ip):
    """Run the existing VirusTotal enrichment script."""

    print(f"\nEnriching IP: {ip}")

    try:
        result = subprocess.run(
            [
                sys.executable,
                str(VT_SCRIPT),
                ip
            ],
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=45,
            check=False
        )

        if result.stdout:
            print(result.stdout)

        if result.returncode != 0:
            print("Enrichment failed:")
            print(result.stderr)
            return False

        return True

    except subprocess.TimeoutExpired:
        print(f"Enrichment timed out for {ip}.")
        return False


def main():

    # 1. Load credentials before starting any operations.
    load_credentials()

    if not VT_SCRIPT.is_file():
        raise FileNotFoundError("vt_enrichment.py not found.")

    print("=" * 55)
    print("SOC THREAT INTELLIGENCE ENRICHMENT ENGINE")
    print("=" * 55)

    # 2. Fetch fresh events directly from Splunk.
    events = fetch_splunk_events()

    # 3. Load already enriched IPs.
    enriched_ips = load_enriched_ips()

    # 4. Find new public IPv4 destinations.
    candidates = extract_public_ips(events, enriched_ips)

    print("\n--- DISCOVERY SUMMARY ---")
    print(f"Events examined: {len(events)}")
    print(f"Previously enriched IPs: {len(enriched_ips)}")
    print(f"New public IPs found: {len(candidates)}")

    if not candidates:
        print("\nNo new IPs require enrichment.")
        return

    # 5. Limit VirusTotal API calls per execution.
    selected = list(candidates.items())[:MAX_IPS_PER_RUN]

    print("\n--- SELECTED DESTINATIONS ---")

    for ip, details in selected:
        print(
            f"{ip} | "
            f"Process: {details['process']} | "
            f"User: {details['user']} | "
            f"Port: {details['port']} | "
            f"Protocol: {details['protocol']}"
        )

    # 6. Enrich selected destinations.
    successful = 0

    for ip, details in selected:
        if run_enrichment(ip):
            successful += 1

    print("\n--- ENRICHMENT SUMMARY ---")
    print(f"Selected IPs: {len(selected)}")
    print(f"Successful enrichments: {successful}")
    print(f"Failed enrichments: {len(selected) - successful}")
    print(f"Enrichment file: {ENRICHMENT_FILE}")

    print("\nProcessing completed.")


if __name__ == "__main__":

    urllib3.disable_warnings(
        urllib3.exceptions.InsecureRequestWarning
    )

    try:
        main()

    except (
        RuntimeError,
        ValueError,
        FileNotFoundError
    ) as error:

        print(f"\nERROR: {error}")
        sys.exit(1)
