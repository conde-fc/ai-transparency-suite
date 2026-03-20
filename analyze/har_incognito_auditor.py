"""HAR incognito auditor — checks if 'private' mode actually prevents tracking.

Compares a HAR file captured in incognito/private mode against known
telemetry patterns to determine if tracking persists. Flags any analytics,
experiment infrastructure, or device fingerprinting found despite the
user's expectation of privacy.
"""

import argparse
import json
import re
import sys
import traceback
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse


SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"

# Fingerprinting indicators — headers and fields that enable device identification
FINGERPRINT_INDICATORS = {
    "headers": [
        "user-agent", "accept-language", "accept-encoding",
        "sec-ch-ua", "sec-ch-ua-platform", "sec-ch-ua-mobile",
        "sec-ch-ua-full-version-list", "sec-ch-ua-arch",
        "sec-ch-ua-model", "sec-ch-ua-bitness",
    ],
    "payload_fields": [
        "screen_width", "screen_height", "screenWidth", "screenHeight",
        "viewport", "resolution", "device_pixel_ratio", "devicePixelRatio",
        "timezone", "timeZone", "language", "languages",
        "platform", "os", "os_version", "osVersion",
        "browser", "browser_version", "browserVersion",
        "device_type", "deviceType", "device_model",
        "canvas_hash", "webgl_hash", "audio_hash",
        "fonts", "plugins", "navigator",
    ],
}

# Persistent ID patterns that survive incognito
PERSISTENT_ID_PATTERNS = [
    (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
     "UUID (potential persistent device ID)"),
    (r"(?:anonymous_?id|anon_?id|device_?id|distinct_?id|user_?id)\s*[:=]\s*['\"]?[\w\-]+",
     "Named persistent identifier"),
]


def load_har(file_path: str) -> dict:
    """Load and parse a HAR file."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_schemas() -> list[dict]:
    """Load all platform schema JSON files."""
    schemas = []
    if SCHEMAS_DIR.exists():
        for schema_file in SCHEMAS_DIR.glob("*.json"):
            with open(schema_file, "r", encoding="utf-8") as f:
                schemas.append(json.load(f))
    return schemas


def build_telemetry_sets(schemas: list[dict]) -> dict:
    """Build telemetry domain and path pattern sets from schemas."""
    return {
        "telemetry_domains": {
            d.lower()
            for s in schemas
            for d in s.get("telemetry_domains", [])
        },
        "telemetry_paths": {
            p.lower()
            for s in schemas
            for p in s.get("telemetry_path_patterns", [])
        },
        "experiment_patterns": {
            p.lower()
            for s in schemas
            for p in s.get("experiment_patterns", [])
        },
    }


def is_telemetry_request(url: str, sets: dict) -> bool:
    """Check if a request URL is telemetry."""
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
    except Exception:
        return False

    for domain in sets["telemetry_domains"]:
        if hostname == domain or hostname.endswith("." + domain):
            return True

    for pattern in sets["telemetry_paths"]:
        if pattern in path:
            return True

    return False


def check_fingerprinting(entry: dict) -> list[dict]:
    """Check if an entry contains fingerprinting data."""
    findings = []

    # Check request headers
    headers = entry.get("request", {}).get("headers", [])
    fp_headers_found = []
    for header in headers:
        name = header.get("name", "").lower()
        if name in FINGERPRINT_INDICATORS["headers"]:
            fp_headers_found.append(name)

    if len(fp_headers_found) >= 3:
        findings.append({
            "type": "fingerprint_headers",
            "detail": f"Sends {len(fp_headers_found)} fingerprinting headers: {', '.join(fp_headers_found[:5])}",
            "severity": "medium",
        })

    # Check payload fields
    for source in ["request", "response"]:
        if source == "request":
            text = entry.get("request", {}).get("postData", {}).get("text", "")
        else:
            text = entry.get("response", {}).get("content", {}).get("text", "")

        if not text:
            continue

        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            continue

        fp_fields = find_fingerprint_fields(data)
        if fp_fields:
            findings.append({
                "type": f"fingerprint_payload_{source}",
                "detail": f"Contains {len(fp_fields)} fingerprinting fields in {source}: {', '.join(fp_fields[:5])}",
                "severity": "high" if source == "request" else "medium",
            })

    return findings


def find_fingerprint_fields(data, prefix="", found=None):
    """Recursively find fingerprinting field names in JSON."""
    if found is None:
        found = []

    if isinstance(data, dict):
        for key, value in data.items():
            key_lower = key.lower().replace("-", "_")
            for fp_field in FINGERPRINT_INDICATORS["payload_fields"]:
                if fp_field.lower() == key_lower:
                    found.append(key)
                    break
            find_fingerprint_fields(value, f"{prefix}.{key}", found)
    elif isinstance(data, list):
        for item in data:
            find_fingerprint_fields(item, prefix, found)

    return found


def check_persistent_ids(entry: dict) -> list[dict]:
    """Check for persistent IDs in request payloads sent during incognito."""
    findings = []

    text = entry.get("request", {}).get("postData", {}).get("text", "")
    if not text:
        return findings

    for pattern, description in PERSISTENT_ID_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            for match in matches[:3]:
                if len(match) > 8:
                    redacted = match[:3] + "***" + match[-3:]
                else:
                    redacted = match[:2] + "***"
                findings.append({
                    "type": "persistent_id",
                    "detail": f"{description}: {redacted}",
                    "severity": "high",
                })

    return findings


def audit_har(har_data: dict, sets: dict) -> dict:
    """Run full incognito audit on a HAR file."""
    entries = har_data.get("log", {}).get("entries", [])

    telemetry_entries = []
    fingerprint_findings = []
    persistent_id_findings = []
    experiment_entries = []
    domain_counter = Counter()

    for entry in entries:
        url = entry.get("request", {}).get("url", "")
        method = entry.get("request", {}).get("method", "UNKNOWN")

        try:
            hostname = urlparse(url).hostname or "unknown"
        except Exception:
            hostname = "unknown"

        # Check for telemetry
        if is_telemetry_request(url, sets):
            telemetry_entries.append({
                "url": url,
                "method": method,
                "domain": hostname,
            })
            domain_counter[hostname] += 1

        # Check for experiment infrastructure
        url_lower = url.lower()
        for exp_pattern in sets["experiment_patterns"]:
            if exp_pattern in url_lower:
                experiment_entries.append({
                    "url": url,
                    "method": method,
                    "domain": hostname,
                    "pattern_matched": exp_pattern,
                })
                break

        # Also check response content for experiment patterns
        resp_text = entry.get("response", {}).get("content", {}).get("text", "")
        if resp_text:
            resp_lower = resp_text.lower()
            for exp_pattern in sets["experiment_patterns"]:
                if exp_pattern in resp_lower:
                    experiment_entries.append({
                        "url": url,
                        "method": method,
                        "domain": hostname,
                        "pattern_matched": f"{exp_pattern} (in response body)",
                    })
                    break

        # Check fingerprinting
        fp = check_fingerprinting(entry)
        for f in fp:
            f["url"] = url
            f["domain"] = hostname
        fingerprint_findings.extend(fp)

        # Check persistent IDs
        pid = check_persistent_ids(entry)
        for f in pid:
            f["url"] = url
            f["domain"] = hostname
        persistent_id_findings.extend(pid)

    # Calculate privacy score (0 = no privacy, 100 = full privacy)
    total = len(entries)
    if total == 0:
        privacy_score = 100
    else:
        telemetry_ratio = len(telemetry_entries) / total
        has_experiments = 1 if experiment_entries else 0
        has_fingerprinting = 1 if fingerprint_findings else 0
        has_persistent_ids = 1 if persistent_id_findings else 0

        penalty = (
            telemetry_ratio * 40 +
            has_experiments * 20 +
            has_fingerprinting * 20 +
            has_persistent_ids * 20
        )
        privacy_score = max(0, round(100 - penalty))

    return {
        "total_entries": total,
        "telemetry_requests": len(telemetry_entries),
        "experiment_requests": len(experiment_entries),
        "fingerprint_findings": len(fingerprint_findings),
        "persistent_id_findings": len(persistent_id_findings),
        "privacy_score": privacy_score,
        "telemetry_domains": dict(domain_counter),
        "telemetry_entries": telemetry_entries,
        "experiment_entries": experiment_entries,
        "fingerprint_details": fingerprint_findings,
        "persistent_id_details": persistent_id_findings,
    }


def format_report(results: dict) -> str:
    """Format incognito audit as readable text."""
    lines = []
    lines.append("=" * 60)
    lines.append("INCOGNITO / PRIVATE MODE AUDIT")
    lines.append("=" * 60)
    lines.append(f"Total requests captured: {results['total_entries']}")
    lines.append(f"Privacy Score: {results['privacy_score']}/100")
    lines.append("")

    # Verdict
    score = results["privacy_score"]
    if score >= 90:
        verdict = "GOOD — Minimal tracking detected in private mode"
    elif score >= 60:
        verdict = "CONCERNING — Some tracking persists in private mode"
    elif score >= 30:
        verdict = "POOR — Significant tracking despite private mode"
    else:
        verdict = "FAILING — Private mode provides virtually no privacy"

    lines.append(f"VERDICT: {verdict}")
    lines.append("")

    # Summary
    lines.append("FINDINGS SUMMARY:")
    lines.append(f"  Telemetry requests:     {results['telemetry_requests']}")
    lines.append(f"  Experiment requests:    {results['experiment_requests']}")
    lines.append(f"  Fingerprinting signals: {results['fingerprint_findings']}")
    lines.append(f"  Persistent IDs:         {results['persistent_id_findings']}")

    # Telemetry domains
    if results["telemetry_domains"]:
        lines.append("")
        lines.append("TELEMETRY DOMAINS CONTACTED:")
        for domain, count in sorted(results["telemetry_domains"].items(),
                                     key=lambda x: -x[1]):
            lines.append(f"  {domain}: {count} requests")

    # Fingerprinting
    if results["fingerprint_details"]:
        lines.append("")
        lines.append("FINGERPRINTING DETAILS:")
        for f in results["fingerprint_details"]:
            lines.append(f"  [{f['severity'].upper()}] {f['detail']}")
            lines.append(f"    URL: {f['url']}")

    # Persistent IDs
    if results["persistent_id_details"]:
        lines.append("")
        lines.append("PERSISTENT ID DETAILS:")
        for f in results["persistent_id_details"]:
            lines.append(f"  [{f['severity'].upper()}] {f['detail']}")
            lines.append(f"    URL: {f['url']}")

    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)


def main():
    """Main entry point for incognito auditor."""
    parser = argparse.ArgumentParser(
        description="Audit whether incognito/private mode actually prevents tracking.",
        epilog="Examples:\n"
               "  python har_incognito_auditor.py incognito_capture.har\n"
               "  python har_incognito_auditor.py incognito_capture.har --json\n"
               "  python har_incognito_auditor.py incognito_capture.har -o audit.txt\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("har_file", help="Path to the HAR file captured in incognito/private mode")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--output", "-o",
                        help="Write report to file instead of stdout")
    args = parser.parse_args()

    try:
        har_data = load_har(args.har_file)
        schemas = load_schemas()
        sets = build_telemetry_sets(schemas)
        results = audit_har(har_data, sets)

        if args.json:
            report = json.dumps(results, indent=2)
        else:
            report = format_report(results)

        if args.output:
            out_path = Path(args.output)
            out_path.write_text(report, encoding="utf-8")
            print(f"Report written to: {out_path}")
        else:
            print(report)

    except Exception:
        traceback.print_exc()
        input("Press Enter to exit...")
        sys.exit(1)


if __name__ == "__main__":
    main()
