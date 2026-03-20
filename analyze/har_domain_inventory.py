"""HAR domain inventory — lists and classifies all domains contacted.

Extracts every unique domain from a HAR file, classifies each as
first-party, analytics, CDN, or unknown, and flags third-party domains
not mentioned in the platform's privacy policy schemas.
"""

import argparse
import csv
import io
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


def build_domain_lookup(schemas: list[dict]) -> dict:
    """Build a domain-to-category lookup from all schemas."""
    lookup = {}
    for schema in schemas:
        platform = schema.get("platform", "unknown")
        for domain in schema.get("first_party_domains", []):
            lookup[domain.lower()] = ("first_party", platform)
        for domain in schema.get("telemetry_domains", []):
            lookup[domain.lower()] = ("analytics", platform)
        for domain in schema.get("cdn_domains", []):
            lookup[domain.lower()] = ("cdn", platform)
    return lookup


def classify_domain(hostname: str, lookup: dict) -> tuple[str, str]:
    """Classify a domain. Returns (category, associated_platform)."""
    hostname = hostname.lower()

    # Direct match
    if hostname in lookup:
        return lookup[hostname]

    # Subdomain match
    parts = hostname.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in lookup:
            return lookup[parent]

    return ("unknown", "unknown")


def inventory_domains(har_data: dict, lookup: dict) -> list[dict]:
    """Build a domain inventory from HAR entries."""
    domain_stats = {}
    entries = har_data.get("log", {}).get("entries", [])

    for entry in entries:
        url = entry.get("request", {}).get("url", "")
        method = entry.get("request", {}).get("method", "UNKNOWN")
        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower()
        except Exception:
            continue

        if not hostname:
            continue

        if hostname not in domain_stats:
            category, platform = classify_domain(hostname, lookup)
            domain_stats[hostname] = {
                "domain": hostname,
                "category": category,
                "associated_platform": platform,
                "request_count": 0,
                "methods": Counter(),
                "paths": set(),
            }

        domain_stats[hostname]["request_count"] += 1
        domain_stats[hostname]["methods"][method] += 1
        try:
            domain_stats[hostname]["paths"].add(urlparse(url).path)
        except Exception:
            pass

    # Convert to serializable list
    results = []
    for hostname, stats in sorted(domain_stats.items()):
        results.append({
            "domain": stats["domain"],
            "category": stats["category"],
            "associated_platform": stats["associated_platform"],
            "request_count": stats["request_count"],
            "methods": dict(stats["methods"]),
            "unique_paths": len(stats["paths"]),
            "sample_paths": sorted(stats["paths"])[:5],
        })

    return results


def format_report(inventory: list[dict]) -> str:
    """Format domain inventory as readable text."""
    lines = []
    lines.append("=" * 70)
    lines.append("DOMAIN INVENTORY")
    lines.append("=" * 70)
    lines.append(f"Total unique domains: {len(inventory)}")

    # Group by category
    by_category = {}
    for item in inventory:
        cat = item["category"]
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(item)

    for category in ["first_party", "analytics", "cdn", "unknown"]:
        items = by_category.get(category, [])
        if not items:
            continue
        lines.append("")
        lines.append(f"--- {category.upper()} ({len(items)} domains) ---")
        for item in items:
            methods = ", ".join(f"{m}: {c}" for m, c in item["methods"].items())
            lines.append(f"  {item['domain']}")
            lines.append(f"    Requests: {item['request_count']} | Methods: {methods}")
            lines.append(f"    Unique paths: {item['unique_paths']}")
            if item["category"] == "unknown":
                lines.append(f"    ⚠ NOT in any platform schema — may be undisclosed third-party")

    lines.append("")
    lines.append("=" * 70)
    return "\n".join(lines)


def format_csv(inventory: list[dict]) -> str:
    """Format domain inventory as CSV."""
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_ALL, doublequote=True)
    writer.writerow(["domain", "category", "associated_platform",
                     "request_count", "unique_paths", "methods"])
    for item in inventory:
        methods_str = "; ".join(f"{m}: {c}" for m, c in item["methods"].items())
        writer.writerow([
            item["domain"],
            item["category"],
            item["associated_platform"],
            item["request_count"],
            item["unique_paths"],
            methods_str,
        ])
    return output.getvalue()


def main():
    """Main entry point for domain inventory."""
    parser = argparse.ArgumentParser(
        description="List and classify all domains contacted in a HAR file.",
        epilog="Examples:\n"
               "  python har_domain_inventory.py capture.har\n"
               "  python har_domain_inventory.py capture.har --csv -o domains.csv\n"
               "  python har_domain_inventory.py capture.har --json\n",
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
        schemas = load_schemas()
        lookup = build_domain_lookup(schemas)
        inventory = inventory_domains(har_data, lookup)

        if args.json:
            report = json.dumps(inventory, indent=2)
        elif args.csv:
            report = format_csv(inventory)
        else:
            report = format_report(inventory)

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
