"""HAR telemetry counter — classifies requests as functional or telemetry.

Analyzes a HAR file and classifies each HTTP request as FUNCTIONAL (serves
the user's request) or TELEMETRY (analytics, tracking, experiments). Uses
platform schema definitions from schemas/ for classification rules.
"""

import argparse
import json
import sys
import traceback
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse


SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"


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


def build_classification_rules(schemas: list[dict]) -> dict:
    """Build combined classification lookup from all schemas."""
    rules = {
        "telemetry_domains": set(),
        "cdn_domains": set(),
        "first_party_domains": set(),
        "telemetry_path_patterns": set(),
        "functional_path_patterns": set(),
    }
    for schema in schemas:
        for domain in schema.get("telemetry_domains", []):
            rules["telemetry_domains"].add(domain.lower())
        for domain in schema.get("cdn_domains", []):
            rules["cdn_domains"].add(domain.lower())
        for domain in schema.get("first_party_domains", []):
            rules["first_party_domains"].add(domain.lower())
        for pattern in schema.get("telemetry_path_patterns", []):
            rules["telemetry_path_patterns"].add(pattern.lower())
        for pattern in schema.get("functional_path_patterns", []):
            rules["functional_path_patterns"].add(pattern.lower())
    return rules


def classify_request(url: str, rules: dict) -> str:
    """Classify a single request URL as 'functional', 'telemetry', 'cdn', or 'unknown'."""
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
    except Exception:
        return "unknown"

    # Check telemetry domains first (strongest signal)
    for domain in rules["telemetry_domains"]:
        if hostname == domain or hostname.endswith("." + domain):
            return "telemetry"

    # Check CDN domains
    for domain in rules["cdn_domains"]:
        if hostname == domain or hostname.endswith("." + domain):
            return "cdn"

    # Check path patterns on first-party domains
    is_first_party = False
    for domain in rules["first_party_domains"]:
        if hostname == domain or hostname.endswith("." + domain):
            is_first_party = True
            break

    # Check telemetry paths
    for pattern in rules["telemetry_path_patterns"]:
        if pattern in path:
            return "telemetry"

    # Check functional paths
    for pattern in rules["functional_path_patterns"]:
        if pattern in path:
            return "functional"

    # First-party domains default to functional
    if is_first_party:
        return "functional"

    return "unknown"


def analyze_har(har_data: dict, rules: dict) -> dict:
    """Analyze all entries in a HAR file and return classification results."""
    entries = har_data.get("log", {}).get("entries", [])
    classifications = []
    domain_breakdown = {}

    for entry in entries:
        url = entry.get("request", {}).get("url", "")
        method = entry.get("request", {}).get("method", "UNKNOWN")
        classification = classify_request(url, rules)

        try:
            hostname = urlparse(url).hostname or "unknown"
        except Exception:
            hostname = "unknown"

        classifications.append({
            "url": url,
            "method": method,
            "domain": hostname,
            "classification": classification,
        })

        if hostname not in domain_breakdown:
            domain_breakdown[hostname] = Counter()
        domain_breakdown[hostname][classification] += 1

    # Summarize
    totals = Counter(c["classification"] for c in classifications)
    total_requests = len(classifications)

    return {
        "total_requests": total_requests,
        "totals": dict(totals),
        "percentages": {
            k: round(v / total_requests * 100, 1) if total_requests > 0 else 0
            for k, v in totals.items()
        },
        "domain_breakdown": {
            domain: dict(counts) for domain, counts in domain_breakdown.items()
        },
        "details": classifications,
    }


def format_report(results: dict) -> str:
    """Format analysis results as a readable text report."""
    lines = []
    lines.append("=" * 60)
    lines.append("TELEMETRY vs FUNCTIONAL REQUEST ANALYSIS")
    lines.append("=" * 60)
    lines.append(f"Total Requests: {results['total_requests']}")
    lines.append("")

    # Summary
    lines.append("CLASSIFICATION SUMMARY:")
    for category in ["telemetry", "functional", "cdn", "unknown"]:
        count = results["totals"].get(category, 0)
        pct = results["percentages"].get(category, 0)
        bar = "#" * int(pct / 2)
        lines.append(f"  {category.upper():12s}: {count:4d} ({pct:5.1f}%) {bar}")

    # Domain breakdown
    lines.append("")
    lines.append("PER-DOMAIN BREAKDOWN:")
    for domain, counts in sorted(results["domain_breakdown"].items()):
        total = sum(counts.values())
        parts = ", ".join(f"{k}: {v}" for k, v in sorted(counts.items()))
        lines.append(f"  {domain}: {total} requests ({parts})")

    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)


def main():
    """Main entry point for telemetry counter."""
    parser = argparse.ArgumentParser(
        description="Count telemetry vs functional requests in a HAR file.",
        epilog="Examples:\n"
               "  python har_telemetry_counter.py capture.har\n"
               "  python har_telemetry_counter.py capture.har --json\n"
               "  python har_telemetry_counter.py capture.har --details\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("har_file", help="Path to the HAR file to analyze")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--details", action="store_true",
                        help="Include per-request classification details")
    parser.add_argument("--output", "-o",
                        help="Write report to file instead of stdout")
    args = parser.parse_args()

    try:
        har_data = load_har(args.har_file)
        schemas = load_schemas()
        rules = build_classification_rules(schemas)
        results = analyze_har(har_data, rules)

        if not args.details:
            results.pop("details", None)

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
