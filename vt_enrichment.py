import os
import sys
import json
import ipaddress
import requests
from datetime import datetime, timezone

VT_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"


def investigate_ip(ip_address):
    """Retrieve threat intelligence for a public IP address."""

    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        raise RuntimeError("VT_API_KEY environment variable is missing.")

    # Validate the IP address
    try:
        ip = ipaddress.ip_address(ip_address)
    except ValueError:
        raise ValueError("Invalid IP address.")

    if not ip.is_global:
        raise ValueError("Only globally routable IP addresses are supported.")

    headers = {
        "x-apikey": api_key,
        "accept": "application/json"
    }

    response = requests.get(
        VT_API_URL.format(ip),
        headers=headers,
        timeout=20
    )

    if response.status_code == 401:
        raise RuntimeError("Invalid VirusTotal API key.")

    if response.status_code == 403:
        raise RuntimeError("VirusTotal API access forbidden.")

    if response.status_code == 404:
        raise RuntimeError("No VirusTotal report found for this IP.")

    if response.status_code == 429:
        raise RuntimeError("VirusTotal API rate limit reached.")

    response.raise_for_status()

    attributes = response.json()["data"]["attributes"]

    stats = attributes.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious > 0:
        verdict = "Malicious"
        severity = "High"
    elif suspicious > 0:
        verdict = "Suspicious"
        severity = "Medium"
    else:
        verdict = "No vendor detections"
        severity = "Informational"

    result = {
        "ip": str(ip),
        "owner": attributes.get("as_owner"),
        "asn": attributes.get("asn"),
        "country": attributes.get("country"),
        "network": attributes.get("network"),
        "reputation": attributes.get("reputation"),
        "analysis_statistics": stats,
        "verdict": verdict,
        "severity": severity
    }

    return result


def main():
    if len(sys.argv) != 2:
        print("Usage: python vt_enrichment.py <IP_ADDRESS>")
        sys.exit(1)

    try:
        result = investigate_ip(sys.argv[1])

        result["enriched_at_utc"] = datetime.now(
            timezone.utc
        ).isoformat()

        output_file = os.path.join(
            os.path.dirname(__file__),
            "vt_enrichment.jsonl"
        )

        with open(output_file, "a", encoding="utf-8") as file:
            file.write(json.dumps(result) + "\n")

        print(json.dumps(result, indent=4))
        print(f"\nSaved enrichment data to: {output_file}")

    except (
        ValueError,
        RuntimeError,
        requests.RequestException
    ) as error:
        print(f"ERROR: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
