"""HAR PII scanner — detects personally identifiable information in HAR payloads.

Scans request and response bodies, headers, cookies, and query parameters
for patterns that match common PII types: emails, phone numbers, IP addresses,
UUIDs (device IDs), GPS coordinates, credit card numbers, and more.

All detection is regex-based — no data leaves the machine.
"""

import argparse
import csv
import io
import json
import re
import sys
import traceback
from pathlib import Path
from urllib.parse import parse_qs, urlparse


# PII detection patterns — each maps a label to (regex, description)
PII_PATTERNS = {
    "email": (
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "Email address",
    ),
    "phone_us": (
        r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)",
        "US phone number",
    ),
    "ipv4": (
        r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)(?!\d)",
        "IPv4 address",
    ),
    "ipv6": (
        r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}",
        "IPv6 address",
    ),
    "uuid": (
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        "UUID (potential device/session ID)",
    ),
    "credit_card": (
        r"(?<!\d)(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}(?!\d)",
        "Credit card number pattern",
    ),
    "ssn": (
        r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)",
        "SSN pattern (US Social Security Number)",
    ),
    "gps_coords": (
        r"(?<!\d)-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}(?!\d)",
        "GPS coordinates (lat,lon with high precision)",
    ),
    "jwt_token": (
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
        "JWT token",
    ),
    "bearer_token": (
        r"[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*",
        "Bearer authentication token",
    ),
    "api_key_generic": (
        r"(?:api[_-]?key|apikey|api_token|access_token|secret_key)\s*[:=]\s*['\"]?[A-Za-z0-9\-._]{16,}",
        "Generic API key pattern",
    ),
}

# Keys/fields in JSON that commonly carry PII
SENSITIVE_FIELD_NAMES = {
    "email", "e-mail", "mail", "user_email", "userEmail",
    "phone", "telephone", "mobile", "cell",
    "name", "first_name", "last_name", "full_name", "username", "user_name",
    "firstName", "lastName", "fullName", "userName",
    "address", "street", "city", "zip", "postal",
    "ssn", "social_security", "dob", "date_of_birth", "birthday",
    "ip", "ip_address", "ipAddress", "remote_addr",
    "latitude", "longitude", "lat", "lon", "lng", "geo",
    "device_id", "deviceId", "fingerprint", "browser_fingerprint",
    "password", "passwd", "secret", "token", "session_id", "sessionId",
    "credit_card", "card_number", "cvv", "expiry",
}


def load_har(file_path: str) -> dict:
    """Load and parse a HAR file."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def scan_text(text: str) -> list[dict]:
    """Scan a text string for PII patterns. Returns list of findings."""
    findings = []
    if not text:
        return findings

    for pii_type, (pattern, description) in PII_PATTERNS.items():
        for match in re.finditer(pattern, text):
            # Redact the match for safe reporting
            raw = match.group()
            if len(raw) > 8:
                redacted = raw[:3] + "***" + raw[-3:]
            else:
                redacted = raw[:2] + "***"

            findings.append({
                "pii_type": pii_type,
                "description": description,
                "redacted_value": redacted,
                "position": match.start(),
            })

    return findings


def scan_json_fields(data, path="", findings=None):
    """Recursively scan JSON for sensitive field names."""
    if findings is None:
        findings = []

    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            key_lower = key.lower().replace("-", "_")

            if key_lower in SENSITIVE_FIELD_NAMES:
                if isinstance(value, str) and value:
                    if len(value) > 8:
                        redacted = value[:3] + "***" + value[-3:]
                    else:
                        redacted = value[:2] + "***"
                else:
                    redacted = str(type(value).__name__)

                findings.append({
                    "pii_type": "sensitive_field",
                    "description": f"Sensitive field name: {key}",
                    "field_path": current_path,
                    "redacted_value": redacted,
                })

            scan_json_fields(value, current_path, findings)

    elif isinstance(data, list):
        for i, item in enumerate(data):
            scan_json_fields(item, f"{path}[{i}]", findings)

    return findings


def scan_headers(headers: list[dict]) -> list[dict]:
    """Scan HTTP headers for PII."""
    findings = []
    for header in headers:
        name = header.get("name", "")
        value = header.get("value", "")
        text_findings = scan_text(value)
        for f in text_findings:
            f["location"] = f"header:{name}"
        findings.extend(text_findings)
    return findings


def scan_cookies(cookies: list[dict]) -> list[dict]:
    """Scan cookies for PII."""
    findings = []
    for cookie in cookies:
        name = cookie.get("name", "")
        value = cookie.get("value", "")
        text_findings = scan_text(value)
        for f in text_findings:
            f["location"] = f"cookie:{name}"
        findings.extend(text_findings)
    return findings


def scan_query_params(url: str) -> list[dict]:
    """Scan URL query parameters for PII."""
    findings = []
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param_name, values in params.items():
            for value in values:
                text_findings = scan_text(value)
                for f in text_findings:
                    f["location"] = f"query_param:{param_name}"
                findings.extend(text_findings)
    except Exception:
        pass
    return findings


def scan_entry(entry: dict) -> dict | None:
    """Scan a single HAR entry for PII. Returns finding dict or None."""
    url = entry.get("request", {}).get("url", "")
    method = entry.get("request", {}).get("method", "UNKNOWN")
    all_findings = []

    # Scan URL query params
    qp = scan_query_params(url)
    all_findings.extend(qp)

    # Scan request headers
    req_headers = entry.get("request", {}).get("headers", [])
    rh = scan_headers(req_headers)
    for f in rh:
        f["direction"] = "request"
    all_findings.extend(rh)

    # Scan request cookies
    req_cookies = entry.get("request", {}).get("cookies", [])
    rc = scan_cookies(req_cookies)
    for f in rc:
        f["direction"] = "request"
    all_findings.extend(rc)

    # Scan request body
    post_text = entry.get("request", {}).get("postData", {}).get("text", "")
    if post_text:
        req_text_findings = scan_text(post_text)
        for f in req_text_findings:
            f["location"] = "request_body"
            f["direction"] = "request"
        all_findings.extend(req_text_findings)

        try:
            req_json = json.loads(post_text)
            json_findings = scan_json_fields(req_json)
            for f in json_findings:
                f["location"] = "request_body_field"
                f["direction"] = "request"
            all_findings.extend(json_findings)
        except (json.JSONDecodeError, TypeError):
            pass

    # Scan response headers
    resp_headers = entry.get("response", {}).get("headers", [])
    rsh = scan_headers(resp_headers)
    for f in rsh:
        f["direction"] = "response"
    all_findings.extend(rsh)

    # Scan response body
    resp_text = entry.get("response", {}).get("content", {}).get("text", "")
    if resp_text:
        resp_text_findings = scan_text(resp_text)
        for f in resp_text_findings:
            f["location"] = "response_body"
            f["direction"] = "response"
        all_findings.extend(resp_text_findings)

        try:
            resp_json = json.loads(resp_text)
            json_findings = scan_json_fields(resp_json)
            for f in json_findings:
                f["location"] = "response_body_field"
                f["direction"] = "response"
            all_findings.extend(json_findings)
        except (json.JSONDecodeError, TypeError):
            pass

    if not all_findings:
        return None

    try:
        hostname = urlparse(url).hostname or "unknown"
    except Exception:
        hostname = "unknown"

    return {
        "url": url,
        "method": method,
        "domain": hostname,
        "findings": all_findings,
    }


def analyze_har(har_data: dict) -> dict:
    """Scan all HAR entries for PII."""
    entries = har_data.get("log", {}).get("entries", [])
    entry_results = []
    pii_type_counts = {}

    for entry in entries:
        result = scan_entry(entry)
        if result:
            entry_results.append(result)
            for f in result["findings"]:
                pt = f["pii_type"]
                pii_type_counts[pt] = pii_type_counts.get(pt, 0) + 1

    return {
        "total_entries_scanned": len(entries),
        "entries_with_pii": len(entry_results),
        "total_pii_findings": sum(pii_type_counts.values()),
        "pii_type_counts": pii_type_counts,
        "entries": entry_results,
    }


def format_report(results: dict) -> str:
    """Format PII scan results as readable text."""
    lines = []
    lines.append("=" * 60)
    lines.append("PII SCAN REPORT")
    lines.append("=" * 60)
    lines.append(f"Entries scanned: {results['total_entries_scanned']}")
    lines.append(f"Entries with PII: {results['entries_with_pii']}")
    lines.append(f"Total PII findings: {results['total_pii_findings']}")
    lines.append("")

    if results["pii_type_counts"]:
        lines.append("PII TYPE BREAKDOWN:")
        for pii_type, count in sorted(results["pii_type_counts"].items(),
                                       key=lambda x: -x[1]):
            desc = PII_PATTERNS.get(pii_type, (None, pii_type))[1]
            lines.append(f"  {desc}: {count}")

    for entry in results["entries"]:
        lines.append("")
        lines.append(f"--- {entry['method']} {entry['domain']} ---")
        for f in entry["findings"]:
            location = f.get("location", "unknown")
            direction = f.get("direction", "")
            prefix = f"[{direction}] " if direction else ""
            lines.append(
                f"  {prefix}{f['pii_type']}: {f['redacted_value']} "
                f"(in {location})"
            )

    if not results["entries"]:
        lines.append("")
        lines.append("No PII detected in this HAR file.")

    lines.append("")
    lines.append("=" * 60)
    lines.append("NOTE: Redacted values shown. Review original HAR carefully.")
    lines.append("NEVER share HAR files without sanitizing PII first.")
    lines.append("=" * 60)
    return "\n".join(lines)


def format_csv(results: dict) -> str:
    """Format PII findings as CSV."""
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_ALL, doublequote=True)
    writer.writerow(["domain", "method", "pii_type", "description",
                     "location", "direction", "redacted_value"])
    for entry in results["entries"]:
        for f in entry["findings"]:
            desc = PII_PATTERNS.get(f["pii_type"], (None, f["pii_type"]))[1]
            writer.writerow([
                entry["domain"],
                entry["method"],
                f["pii_type"],
                desc,
                f.get("location", ""),
                f.get("direction", ""),
                f["redacted_value"],
            ])
    return output.getvalue()


def main():
    """Main entry point for PII scanner."""
    parser = argparse.ArgumentParser(
        description="Scan a HAR file for personally identifiable information (PII).",
        epilog="Examples:\n"
               "  python har_pii_scanner.py capture.har\n"
               "  python har_pii_scanner.py capture.har --json\n"
               "  python har_pii_scanner.py capture.har --csv -o pii_findings.csv\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("har_file", help="Path to the HAR file to analyze")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--csv", action="store_true",
                        help="Output results as CSV")
    parser.add_argument("--output", "-o",
                        help="Write report to file instead of stdout")
    args = parser.parse_args()

    try:
        har_data = load_har(args.har_file)
        results = analyze_har(har_data)

        if args.json:
            report = json.dumps(results, indent=2)
        elif args.csv:
            report = format_csv(results)
        else:
            report = format_report(results)

        if args.output:
            out_path = Path(args.output)
            encoding = "utf-8-sig" if args.csv else "utf-8"
            out_path.write_text(report, encoding=encoding)
            print(f"Report written to: {out_path}")
        else:
            print(report)

    except Exception:
        traceback.print_exc()
        input("Press Enter to exit...")
        sys.exit(1)


if __name__ == "__main__":
    main()
