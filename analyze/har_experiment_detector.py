"""HAR experiment detector — finds A/B tests, feature gates, and experiment configs.

Searches HAR file entries for StatsIg payloads, feature gates, experiment
configurations, and A/B test assignments. Extracts experiment names,
group assignments, and feature flag states.
"""

import argparse
import json
import re
import sys
import traceback
from pathlib import Path
from urllib.parse import urlparse


SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"

# Keywords that indicate experiment/feature-gate infrastructure
EXPERIMENT_KEYWORDS = [
    "statsig", "feature_gate", "feature_gates", "featuregate",
    "dynamic_config", "dynamic_configs", "experiment", "experiments",
    "layer_config", "layer_configs", "ab_test", "a_b_test",
    "feature_flag", "feature_flags", "variant", "treatment",
    "control_group", "test_group", "bucket", "cohort",
    "launch_config", "rollout",
]

# URL patterns that indicate experiment infrastructure
EXPERIMENT_URL_PATTERNS = [
    r"featuregates\.org",
    r"statsig\.com",
    r"api\.statsig\.com",
    r"events\.statsig\.com",
    r"/v1/initialize",
    r"/v1/get_config",
    r"/v1/log_event",
    r"ab\.chatgpt\.com",
    r"/experiments?/",
    r"/feature.?gates?/",
]


def load_har(file_path: str) -> dict:
    """Load and parse a HAR file."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def check_url_for_experiments(url: str) -> bool:
    """Check if a URL matches known experiment infrastructure patterns."""
    for pattern in EXPERIMENT_URL_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    return False


def extract_json_payload(entry: dict, source: str) -> dict | None:
    """Extract and parse JSON from request or response body."""
    if source == "request":
        text = entry.get("request", {}).get("postData", {}).get("text", "")
    elif source == "response":
        text = entry.get("response", {}).get("content", {}).get("text", "")
    else:
        return None

    if not text:
        return None

    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


def search_for_keywords(data, path="", results=None):
    """Recursively search a JSON structure for experiment-related keywords."""
    if results is None:
        results = []

    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            key_lower = key.lower()
            for keyword in EXPERIMENT_KEYWORDS:
                if keyword in key_lower:
                    results.append({
                        "path": current_path,
                        "key": key,
                        "value": value if not isinstance(value, (dict, list)) else f"<{type(value).__name__}>",
                        "keyword_match": keyword,
                    })
                    break
            search_for_keywords(value, current_path, results)
    elif isinstance(data, list):
        for i, item in enumerate(data):
            search_for_keywords(item, f"{path}[{i}]", results)

    return results


def extract_feature_gates(data: dict) -> list[dict]:
    """Extract feature gate definitions from a parsed JSON payload."""
    gates = []

    # StatsIg format
    fg = data.get("feature_gates", {})
    if isinstance(fg, dict):
        for gate_name, gate_data in fg.items():
            if isinstance(gate_data, dict):
                gates.append({
                    "name": gate_name,
                    "value": gate_data.get("value"),
                    "rule_id": gate_data.get("rule_id", "unknown"),
                    "type": "feature_gate",
                })
            else:
                gates.append({
                    "name": gate_name,
                    "value": gate_data,
                    "rule_id": "unknown",
                    "type": "feature_gate",
                })

    return gates


def extract_dynamic_configs(data: dict) -> list[dict]:
    """Extract dynamic configs / experiment assignments from a parsed payload."""
    configs = []

    dc = data.get("dynamic_configs", {})
    if isinstance(dc, dict):
        for config_name, config_data in dc.items():
            if isinstance(config_data, dict):
                configs.append({
                    "name": config_name,
                    "value": config_data.get("value", {}),
                    "rule_id": config_data.get("rule_id", "unknown"),
                    "type": "dynamic_config",
                })

    return configs


def analyze_entry(entry: dict) -> dict | None:
    """Analyze a single HAR entry for experiment data. Returns finding or None."""
    url = entry.get("request", {}).get("url", "")
    method = entry.get("request", {}).get("method", "UNKNOWN")

    is_experiment_url = check_url_for_experiments(url)

    # Check both request and response payloads
    request_data = extract_json_payload(entry, "request")
    response_data = extract_json_payload(entry, "response")

    request_keywords = search_for_keywords(request_data) if request_data else []
    response_keywords = search_for_keywords(response_data) if response_data else []

    feature_gates = []
    dynamic_configs = []

    if response_data:
        feature_gates = extract_feature_gates(response_data)
        dynamic_configs = extract_dynamic_configs(response_data)
    if request_data:
        feature_gates.extend(extract_feature_gates(request_data))
        dynamic_configs.extend(extract_dynamic_configs(request_data))

    has_findings = (is_experiment_url or request_keywords or
                    response_keywords or feature_gates or dynamic_configs)

    if not has_findings:
        return None

    try:
        hostname = urlparse(url).hostname or "unknown"
    except Exception:
        hostname = "unknown"

    return {
        "url": url,
        "method": method,
        "domain": hostname,
        "is_experiment_url": is_experiment_url,
        "feature_gates": feature_gates,
        "dynamic_configs": dynamic_configs,
        "request_keyword_matches": request_keywords,
        "response_keyword_matches": response_keywords,
    }


def analyze_har(har_data: dict) -> dict:
    """Analyze all entries in a HAR file for experiment infrastructure."""
    entries = har_data.get("log", {}).get("entries", [])
    findings = []

    for entry in entries:
        result = analyze_entry(entry)
        if result:
            findings.append(result)

    # Summarize
    all_gates = []
    all_configs = []
    for finding in findings:
        all_gates.extend(finding["feature_gates"])
        all_configs.extend(finding["dynamic_configs"])

    return {
        "total_entries_scanned": len(entries),
        "entries_with_experiments": len(findings),
        "total_feature_gates": len(all_gates),
        "total_dynamic_configs": len(all_configs),
        "feature_gates": all_gates,
        "dynamic_configs": all_configs,
        "findings": findings,
    }


def format_report(results: dict) -> str:
    """Format experiment detection results as markdown."""
    lines = []
    lines.append("# Experiment Detection Report")
    lines.append("")
    lines.append(f"**Entries scanned:** {results['total_entries_scanned']}")
    lines.append(f"**Entries with experiment data:** {results['entries_with_experiments']}")
    lines.append(f"**Feature gates found:** {results['total_feature_gates']}")
    lines.append(f"**Dynamic configs found:** {results['total_dynamic_configs']}")

    # Feature gates
    if results["feature_gates"]:
        lines.append("")
        lines.append("## Feature Gates")
        lines.append("")
        lines.append("| Name | Value | Rule ID |")
        lines.append("|------|-------|---------|")
        for gate in results["feature_gates"]:
            lines.append(f"| {gate['name']} | {gate['value']} | {gate['rule_id']} |")

    # Dynamic configs
    if results["dynamic_configs"]:
        lines.append("")
        lines.append("## Dynamic Configs / Experiments")
        lines.append("")
        for config in results["dynamic_configs"]:
            lines.append(f"### {config['name']}")
            lines.append(f"- **Rule ID:** {config['rule_id']}")
            lines.append(f"- **Value:** `{json.dumps(config['value'])}`")
            lines.append("")

    # Detailed findings
    if results["findings"]:
        lines.append("## Detailed Findings")
        lines.append("")
        for i, finding in enumerate(results["findings"], 1):
            lines.append(f"### Finding {i}")
            lines.append(f"- **URL:** `{finding['url']}`")
            lines.append(f"- **Method:** {finding['method']}")
            lines.append(f"- **Domain:** {finding['domain']}")
            lines.append(f"- **Experiment URL match:** {finding['is_experiment_url']}")

            if finding["request_keyword_matches"]:
                lines.append(f"- **Request keywords:** {len(finding['request_keyword_matches'])} matches")
                for match in finding["request_keyword_matches"]:
                    lines.append(f"  - `{match['path']}` (keyword: {match['keyword_match']})")

            if finding["response_keyword_matches"]:
                lines.append(f"- **Response keywords:** {len(finding['response_keyword_matches'])} matches")
                for match in finding["response_keyword_matches"]:
                    lines.append(f"  - `{match['path']}` (keyword: {match['keyword_match']})")

            lines.append("")

    if not results["findings"]:
        lines.append("")
        lines.append("No experiment infrastructure detected in this HAR file.")

    return "\n".join(lines)


def main():
    """Main entry point for experiment detector."""
    parser = argparse.ArgumentParser(
        description="Detect A/B tests, feature gates, and experiment configs in a HAR file.",
        epilog="Examples:\n"
               "  python har_experiment_detector.py capture.har\n"
               "  python har_experiment_detector.py capture.har --json\n"
               "  python har_experiment_detector.py capture.har -o report.md\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("har_file", help="Path to the HAR file to analyze")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--output", "-o",
                        help="Write report to file instead of stdout")
    args = parser.parse_args()

    try:
        har_data = load_har(args.har_file)
        results = analyze_har(har_data)

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
