"""HAR file validator — validates structure and reports basic statistics.

Validates that a file is a properly formatted HAR (HTTP Archive) file,
counts entries, and warns about sensitive data that should be sanitized.
"""

import argparse
import json
import sys
import traceback
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse


def load_har(file_path: str) -> dict:
    """Load and parse a HAR file, returning the parsed JSON."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    if not path.suffix.lower() == ".har":
        print(f"Warning: File does not have .har extension: {path.name}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_structure(har_data: dict) -> list[str]:
    """Validate HAR JSON structure. Returns list of errors (empty = valid)."""
    errors = []
    if "log" not in har_data:
        errors.append("Missing top-level 'log' key")
        return errors

    log = har_data["log"]

    if "version" not in log:
        errors.append("Missing 'log.version'")
    if "entries" not in log:
        errors.append("Missing 'log.entries'")
        return errors
    if not isinstance(log["entries"], list):
        errors.append("'log.entries' is not a list")
        return errors

    for i, entry in enumerate(log["entries"]):
        if "request" not in entry:
            errors.append(f"Entry {i}: missing 'request'")
        else:
            req = entry["request"]
            if "method" not in req:
                errors.append(f"Entry {i}: missing 'request.method'")
            if "url" not in req:
                errors.append(f"Entry {i}: missing 'request.url'")
        if "response" not in entry:
            errors.append(f"Entry {i}: missing 'response'")

    return errors


def extract_domains(har_data: dict) -> Counter:
    """Extract and count all domains from HAR entries."""
    domains = Counter()
    for entry in har_data.get("log", {}).get("entries", []):
        url = entry.get("request", {}).get("url", "")
        try:
            parsed = urlparse(url)
            if parsed.hostname:
                domains[parsed.hostname] += 1
        except Exception:
            pass
    return domains


def extract_methods(har_data: dict) -> Counter:
    """Count HTTP methods used in HAR entries."""
    methods = Counter()
    for entry in har_data.get("log", {}).get("entries", []):
        method = entry.get("request", {}).get("method", "UNKNOWN")
        methods[method] += 1
    return methods


def extract_content_types(har_data: dict) -> Counter:
    """Count response content types in HAR entries."""
    types = Counter()
    for entry in har_data.get("log", {}).get("entries", []):
        content = entry.get("response", {}).get("content", {})
        mime = content.get("mimeType", "unknown")
        # Normalize: take just the base type
        mime = mime.split(";")[0].strip()
        types[mime] += 1
    return types


def check_sensitive_data(har_data: dict) -> list[str]:
    """Check for potentially sensitive data in HAR file. Returns warnings."""
    warnings = []
    entries = har_data.get("log", {}).get("entries", [])

    has_cookies = False
    has_auth_headers = False
    has_tokens = False

    for entry in entries:
        req = entry.get("request", {})

        # Check cookies
        cookies = req.get("cookies", [])
        if cookies:
            has_cookies = True

        # Check headers for auth tokens
        for header in req.get("headers", []):
            name = header.get("name", "").lower()
            if name in ("authorization", "x-api-key", "x-auth-token"):
                has_auth_headers = True
            value = header.get("value", "").lower()
            if "bearer " in value or "token " in value:
                has_tokens = True

    if has_cookies:
        warnings.append("SENSITIVE: HAR file contains cookies (may include session tokens)")
    if has_auth_headers:
        warnings.append("SENSITIVE: HAR file contains authorization headers")
    if has_tokens:
        warnings.append("SENSITIVE: HAR file contains bearer/auth tokens")

    if warnings:
        warnings.append(">> Sanitize this file before sharing! Do not post raw HAR files publicly.")

    return warnings


def format_report(file_path: str, har_data: dict, errors: list[str],
                  domains: Counter, methods: Counter, content_types: Counter,
                  warnings: list[str]) -> str:
    """Format the validation report as a string."""
    lines = []
    lines.append("=" * 60)
    lines.append("HAR FILE VALIDATION REPORT")
    lines.append("=" * 60)
    lines.append(f"File: {file_path}")

    entries = har_data.get("log", {}).get("entries", [])
    version = har_data.get("log", {}).get("version", "unknown")
    lines.append(f"HAR Version: {version}")
    lines.append(f"Total Entries: {len(entries)}")

    # Validation
    lines.append("")
    if errors:
        lines.append(f"VALIDATION: FAILED ({len(errors)} errors)")
        for err in errors:
            lines.append(f"  ✗ {err}")
    else:
        lines.append("VALIDATION: PASSED")

    # Domains
    lines.append("")
    lines.append(f"DOMAINS ({len(domains)} unique):")
    for domain, count in domains.most_common():
        lines.append(f"  {domain}: {count} requests")

    # Methods
    lines.append("")
    lines.append("HTTP METHODS:")
    for method, count in methods.most_common():
        lines.append(f"  {method}: {count}")

    # Content types
    lines.append("")
    lines.append("RESPONSE CONTENT TYPES:")
    for ctype, count in content_types.most_common():
        lines.append(f"  {ctype}: {count}")

    # Sensitive data warnings
    if warnings:
        lines.append("")
        lines.append("SECURITY WARNINGS:")
        for warning in warnings:
            lines.append(f"  ⚠ {warning}")

    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)


def export_json_report(file_path: str, har_data: dict, errors: list[str],
                       domains: Counter, methods: Counter,
                       content_types: Counter, warnings: list[str]) -> dict:
    """Create a JSON-serializable report dictionary."""
    entries = har_data.get("log", {}).get("entries", [])
    return {
        "file": file_path,
        "har_version": har_data.get("log", {}).get("version", "unknown"),
        "total_entries": len(entries),
        "valid": len(errors) == 0,
        "errors": errors,
        "domains": dict(domains.most_common()),
        "methods": dict(methods.most_common()),
        "content_types": dict(content_types.most_common()),
        "security_warnings": warnings,
    }


def main():
    """Main entry point for HAR validator."""
    parser = argparse.ArgumentParser(
        description="Validate HAR file structure and report basic statistics.",
        epilog="Examples:\n"
               "  python har_validator.py capture.har\n"
               "  python har_validator.py capture.har --json\n"
               "  python har_validator.py capture.har --json --output report.json\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("har_file", help="Path to the HAR file to validate")
    parser.add_argument("--json", action="store_true",
                        help="Output report as JSON instead of text")
    parser.add_argument("--output", "-o", help="Write report to file instead of stdout")
    args = parser.parse_args()

    try:
        # Load and validate
        har_data = load_har(args.har_file)
        errors = validate_structure(har_data)
        domains = extract_domains(har_data)
        methods = extract_methods(har_data)
        content_types = extract_content_types(har_data)
        warnings = check_sensitive_data(har_data)

        if args.json:
            report = json.dumps(
                export_json_report(args.har_file, har_data, errors,
                                   domains, methods, content_types, warnings),
                indent=2,
            )
        else:
            report = format_report(args.har_file, har_data, errors,
                                   domains, methods, content_types, warnings)

        if args.output:
            out_path = Path(args.output)
            out_path.write_text(report, encoding="utf-8")
            print(f"Report written to: {out_path}")
        else:
            print(report)

        # Exit with error code if validation failed
        sys.exit(1 if errors else 0)

    except Exception:
        traceback.print_exc()
        input("Press Enter to exit...")
        sys.exit(1)


if __name__ == "__main__":
    main()
