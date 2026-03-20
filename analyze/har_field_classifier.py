"""HAR field classifier — classifies data fields by privacy sensitivity.

Extracts all JSON field names from request and response payloads across
a HAR file, classifies each by privacy sensitivity level (critical, high,
medium, low, benign), and reports which domains send/receive each field.

This helps answer: "What data fields is the platform actually collecting,
and how sensitive are they?"
"""

import argparse
import csv
import io
import json
import sys
import traceback
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse


# Field sensitivity classifications
# Maps lowercase field names to (sensitivity_level, category, description)
FIELD_CLASSIFICATIONS = {
    # CRITICAL — direct personal identifiers
    "email": ("critical", "PII", "Email address"),
    "e-mail": ("critical", "PII", "Email address"),
    "user_email": ("critical", "PII", "Email address"),
    "useremail": ("critical", "PII", "Email address"),
    "phone": ("critical", "PII", "Phone number"),
    "telephone": ("critical", "PII", "Phone number"),
    "mobile": ("critical", "PII", "Mobile number"),
    "ssn": ("critical", "PII", "Social Security Number"),
    "social_security": ("critical", "PII", "Social Security Number"),
    "credit_card": ("critical", "financial", "Credit card number"),
    "card_number": ("critical", "financial", "Credit card number"),
    "cvv": ("critical", "financial", "Card verification value"),
    "password": ("critical", "auth", "Password"),
    "passwd": ("critical", "auth", "Password"),
    "secret": ("critical", "auth", "Secret key"),
    "secret_key": ("critical", "auth", "Secret key"),
    "api_key": ("critical", "auth", "API key"),
    "apikey": ("critical", "auth", "API key"),
    "access_token": ("critical", "auth", "Access token"),
    "refresh_token": ("critical", "auth", "Refresh token"),

    # HIGH — identifiers and tracking
    "name": ("high", "PII", "Personal name"),
    "first_name": ("high", "PII", "First name"),
    "last_name": ("high", "PII", "Last name"),
    "full_name": ("high", "PII", "Full name"),
    "firstname": ("high", "PII", "First name"),
    "lastname": ("high", "PII", "Last name"),
    "fullname": ("high", "PII", "Full name"),
    "username": ("high", "PII", "Username"),
    "user_name": ("high", "PII", "Username"),
    "user_id": ("high", "identifier", "User identifier"),
    "userid": ("high", "identifier", "User identifier"),
    "device_id": ("high", "identifier", "Device identifier"),
    "deviceid": ("high", "identifier", "Device identifier"),
    "session_id": ("high", "identifier", "Session identifier"),
    "sessionid": ("high", "identifier", "Session identifier"),
    "anonymous_id": ("high", "identifier", "Anonymous tracking ID"),
    "anonymousid": ("high", "identifier", "Anonymous tracking ID"),
    "distinct_id": ("high", "identifier", "Distinct tracking ID"),
    "distinctid": ("high", "identifier", "Distinct tracking ID"),
    "fingerprint": ("high", "identifier", "Browser fingerprint"),
    "browser_fingerprint": ("high", "identifier", "Browser fingerprint"),
    "ip": ("high", "network", "IP address"),
    "ip_address": ("high", "network", "IP address"),
    "ipaddress": ("high", "network", "IP address"),
    "remote_addr": ("high", "network", "Remote address"),
    "address": ("high", "PII", "Physical address"),
    "street": ("high", "PII", "Street address"),
    "date_of_birth": ("high", "PII", "Date of birth"),
    "dob": ("high", "PII", "Date of birth"),
    "birthday": ("high", "PII", "Birthday"),
    "token": ("high", "auth", "Authentication token"),
    "authorization": ("high", "auth", "Authorization header"),
    "cookie": ("high", "auth", "Session cookie"),

    # MEDIUM — behavioral and device data
    "latitude": ("medium", "location", "Latitude coordinate"),
    "longitude": ("medium", "location", "Longitude coordinate"),
    "lat": ("medium", "location", "Latitude coordinate"),
    "lon": ("medium", "location", "Longitude coordinate"),
    "lng": ("medium", "location", "Longitude coordinate"),
    "geo": ("medium", "location", "Geolocation data"),
    "geolocation": ("medium", "location", "Geolocation data"),
    "city": ("medium", "location", "City"),
    "country": ("medium", "location", "Country"),
    "region": ("medium", "location", "Region"),
    "zip": ("medium", "location", "ZIP/postal code"),
    "postal": ("medium", "location", "Postal code"),
    "timezone": ("medium", "device", "Timezone"),
    "user_agent": ("medium", "device", "User agent string"),
    "useragent": ("medium", "device", "User agent string"),
    "screen_width": ("medium", "device", "Screen width"),
    "screen_height": ("medium", "device", "Screen height"),
    "screenwidth": ("medium", "device", "Screen width"),
    "screenheight": ("medium", "device", "Screen height"),
    "resolution": ("medium", "device", "Screen resolution"),
    "viewport": ("medium", "device", "Viewport size"),
    "device_pixel_ratio": ("medium", "device", "Device pixel ratio"),
    "platform": ("medium", "device", "Platform"),
    "os": ("medium", "device", "Operating system"),
    "os_version": ("medium", "device", "OS version"),
    "browser": ("medium", "device", "Browser name"),
    "browser_version": ("medium", "device", "Browser version"),
    "language": ("medium", "device", "Language setting"),
    "languages": ("medium", "device", "Language preferences"),
    "referrer": ("medium", "behavioral", "Referrer URL"),
    "referer": ("medium", "behavioral", "Referrer URL"),
    "page_url": ("medium", "behavioral", "Current page URL"),
    "page_title": ("medium", "behavioral", "Current page title"),
    "event": ("medium", "behavioral", "Event name"),
    "event_name": ("medium", "behavioral", "Event name"),
    "action": ("medium", "behavioral", "User action"),
    "keystroke": ("medium", "behavioral", "Keystroke data"),
    "keystrokes": ("medium", "behavioral", "Keystroke data"),
    "input": ("medium", "behavioral", "User input"),
    "query": ("medium", "behavioral", "Search query"),
    "search": ("medium", "behavioral", "Search query"),

    # LOW — analytics metadata
    "timestamp": ("low", "metadata", "Event timestamp"),
    "time": ("low", "metadata", "Time"),
    "duration": ("low", "metadata", "Duration"),
    "experiment": ("low", "experiment", "Experiment name"),
    "variant": ("low", "experiment", "Experiment variant"),
    "feature_gate": ("low", "experiment", "Feature gate"),
    "feature_flag": ("low", "experiment", "Feature flag"),
    "ab_test": ("low", "experiment", "A/B test"),
    "version": ("low", "metadata", "Application version"),
    "app_version": ("low", "metadata", "Application version"),
    "build": ("low", "metadata", "Build number"),
    "sdk_version": ("low", "metadata", "SDK version"),
    "library": ("low", "metadata", "Analytics library name"),
    "source": ("low", "metadata", "Event source"),
    "type": ("low", "metadata", "Event/object type"),
    "category": ("low", "metadata", "Category"),
}


def load_har(file_path: str) -> dict:
    """Load and parse a HAR file."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_fields(data, path="", fields=None):
    """Recursively extract all field names from a JSON structure."""
    if fields is None:
        fields = []

    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            fields.append({
                "name": key,
                "path": current_path,
                "value_type": type(value).__name__,
                "has_value": value is not None and value != "" and value != [],
            })
            extract_fields(value, current_path, fields)
    elif isinstance(data, list):
        for i, item in enumerate(data):
            extract_fields(item, f"{path}[{i}]", fields)

    return fields


def classify_field(field_name: str) -> tuple[str, str, str]:
    """Classify a field name. Returns (sensitivity, category, description)."""
    key = field_name.lower().replace("-", "_")

    if key in FIELD_CLASSIFICATIONS:
        return FIELD_CLASSIFICATIONS[key]

    # Pattern-based fallback
    if any(token in key for token in ["_id", "id_", "identifier"]):
        return ("medium", "identifier", "Identifier field")
    if any(token in key for token in ["track", "metric", "analytic", "telemetry"]):
        return ("medium", "analytics", "Analytics field")
    if any(token in key for token in ["count", "total", "sum", "avg"]):
        return ("low", "metrics", "Metric field")

    return ("benign", "unknown", "Unclassified field")


def analyze_har(har_data: dict) -> dict:
    """Analyze all entries and classify every data field found."""
    entries = har_data.get("log", {}).get("entries", [])

    # Track: field_name -> {sensitivity, category, description, domains, directions, count}
    field_registry = {}

    for entry in entries:
        url = entry.get("request", {}).get("url", "")
        try:
            hostname = urlparse(url).hostname or "unknown"
        except Exception:
            hostname = "unknown"

        # Process request body
        req_text = entry.get("request", {}).get("postData", {}).get("text", "")
        if req_text:
            try:
                req_json = json.loads(req_text)
                fields = extract_fields(req_json)
                for f in fields:
                    register_field(field_registry, f["name"], hostname, "request")
            except (json.JSONDecodeError, TypeError):
                pass

        # Process response body
        resp_text = entry.get("response", {}).get("content", {}).get("text", "")
        if resp_text:
            try:
                resp_json = json.loads(resp_text)
                fields = extract_fields(resp_json)
                for f in fields:
                    register_field(field_registry, f["name"], hostname, "response")
            except (json.JSONDecodeError, TypeError):
                pass

    # Build results
    classified = []
    for field_name, info in sorted(field_registry.items()):
        sensitivity, category, description = classify_field(field_name)
        classified.append({
            "field": field_name,
            "sensitivity": sensitivity,
            "category": category,
            "description": description,
            "occurrences": info["count"],
            "domains": sorted(info["domains"]),
            "directions": sorted(info["directions"]),
        })

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "benign": 4}
    classified.sort(key=lambda x: (severity_order.get(x["sensitivity"], 5), x["field"]))

    # Count by sensitivity
    sensitivity_counts = defaultdict(int)
    for item in classified:
        sensitivity_counts[item["sensitivity"]] += 1

    return {
        "total_entries_scanned": len(entries),
        "total_unique_fields": len(classified),
        "sensitivity_counts": dict(sensitivity_counts),
        "fields": classified,
    }


def register_field(registry: dict, field_name: str, domain: str, direction: str):
    """Register a field occurrence in the registry."""
    if field_name not in registry:
        registry[field_name] = {
            "count": 0,
            "domains": set(),
            "directions": set(),
        }
    registry[field_name]["count"] += 1
    registry[field_name]["domains"].add(domain)
    registry[field_name]["directions"].add(direction)


def format_report(results: dict) -> str:
    """Format field classification as readable text."""
    lines = []
    lines.append("=" * 70)
    lines.append("FIELD CLASSIFICATION REPORT")
    lines.append("=" * 70)
    lines.append(f"Entries scanned: {results['total_entries_scanned']}")
    lines.append(f"Unique fields found: {results['total_unique_fields']}")
    lines.append("")

    lines.append("SENSITIVITY BREAKDOWN:")
    for level in ["critical", "high", "medium", "low", "benign"]:
        count = results["sensitivity_counts"].get(level, 0)
        indicator = "!!!" if level == "critical" else ("!!" if level == "high" else "")
        lines.append(f"  {level.upper():10s}: {count:4d} {indicator}")

    current_level = None
    for item in results["fields"]:
        if item["sensitivity"] != current_level:
            current_level = item["sensitivity"]
            lines.append("")
            lines.append(f"--- {current_level.upper()} SENSITIVITY ---")

        domains = ", ".join(item["domains"])
        dirs = ", ".join(item["directions"])
        lines.append(f"  {item['field']}")
        lines.append(f"    {item['description']} [{item['category']}]")
        lines.append(f"    Occurrences: {item['occurrences']} | Domains: {domains} | Direction: {dirs}")

    lines.append("")
    lines.append("=" * 70)
    return "\n".join(lines)


def format_csv(results: dict) -> str:
    """Format field classification as CSV."""
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_ALL, doublequote=True)
    writer.writerow(["field", "sensitivity", "category", "description",
                     "occurrences", "domains", "directions"])
    for item in results["fields"]:
        writer.writerow([
            item["field"],
            item["sensitivity"],
            item["category"],
            item["description"],
            item["occurrences"],
            "; ".join(item["domains"]),
            "; ".join(item["directions"]),
        ])
    return output.getvalue()


def main():
    """Main entry point for field classifier."""
    parser = argparse.ArgumentParser(
        description="Classify all data fields in a HAR file by privacy sensitivity.",
        epilog="Examples:\n"
               "  python har_field_classifier.py capture.har\n"
               "  python har_field_classifier.py capture.har --csv -o fields.csv\n"
               "  python har_field_classifier.py capture.har --json\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("har_file", help="Path to the HAR file to analyze")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--csv", action="store_true",
                        help="Output results as CSV")
    parser.add_argument("--output", "-o",
                        help="Write report to file instead of stdout")
    parser.add_argument("--min-severity",
                        choices=["critical", "high", "medium", "low", "benign"],
                        default="benign",
                        help="Only show fields at this severity or above")
    args = parser.parse_args()

    try:
        har_data = load_har(args.har_file)
        results = analyze_har(har_data)

        # Filter by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "benign": 4}
        min_level = severity_order[args.min_severity]
        results["fields"] = [
            f for f in results["fields"]
            if severity_order.get(f["sensitivity"], 5) <= min_level
        ]

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
