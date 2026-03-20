# AI Transparency Suite (ATS)

**Open-source forensic toolkit for analyzing undisclosed data collection by AI chat platforms.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

## Why This Exists

Major AI chat platforms collect significantly more data than their privacy policies disclose. Telemetry calls, undisclosed third-party analytics integrations, A/B experiment infrastructure, and persistent tracking in supposedly "private" modes are common across the industry. Consumers deserve tools to see exactly what is being collected and compare it against what platforms claim.

ATS provides that capability using passive forensic analysis of HAR (HTTP Archive) files — the same network data your browser already records.

## What It Finds

- **Telemetry ratios** — what percentage of API calls serve you vs. track you
- **Undisclosed integrations** — third-party analytics (Segment, Amplitude, StatsIg) not mentioned in privacy policies
- **Experiment infrastructure** — A/B tests, feature gates, and experiment configs running silently
- **PII in "private" modes** — email addresses, UUIDs, and identifiers transmitted even in incognito/private sessions
- **Domain inventories** — every server your browser contacts during a chat session
- **Field-level classification** — what each data field represents and its privacy sensitivity

## Platforms Covered

| Platform | Company | URL |
|----------|---------|-----|
| Claude | Anthropic | claude.ai |
| ChatGPT | OpenAI | chatgpt.com |
| Grok | xAI | grok.com |
| DeepSeek | DeepSeek | chat.deepseek.com |
| Gemini | Google | gemini.google.com |

## Quick Start

### 1. Install

```bash
git clone https://github.com/conde-fc/ai-transparency-suite.git
cd ai-transparency-suite
pip install -r requirements.txt
```

### 2. Capture a HAR File

Open your browser's DevTools (F12), go to the **Network** tab, interact with an AI chat platform, then right-click and **Export HAR**. See [`capture/CAPTURE_GUIDE.md`](capture/CAPTURE_GUIDE.md) for detailed instructions.

### 3. Validate Your Capture

```bash
python capture/har_validator.py your_capture.har
```

### 4. Run Analysis

```bash
# Count telemetry vs functional requests
python analyze/har_telemetry_counter.py your_capture.har

# List all domains contacted
python analyze/har_domain_inventory.py your_capture.har

# Find A/B experiments and feature gates
python analyze/har_experiment_detector.py your_capture.har

# Scan for PII in requests
python analyze/har_pii_scanner.py your_capture.har

# Compare normal vs incognito sessions
python analyze/har_incognito_auditor.py normal.har incognito.har

# Classify all data fields
python analyze/har_field_classifier.py your_capture.har
```

## Project Structure

```
ai-transparency-suite/
├── capture/          # HAR capture guide and validator
├── analyze/          # Core analysis tools
├── compare/          # Policy vs reality comparison tools
├── report/           # Evidence report generation
├── schemas/          # Platform-specific endpoint/pattern definitions
├── examples/         # Synthetic example outputs (no real data)
├── tests/            # Unit tests with synthetic fixtures
└── docs/             # Methodology, legal context, contributing guide
```

## Methodology

All analysis is based on **passive observation** of network traffic that your browser already handles. ATS does not intercept, inject, or modify any traffic. It reads HAR files — standard JSON exports from browser DevTools — and classifies what it finds. Every finding is independently reproducible by anyone with a browser and DevTools.

See [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) for the full forensic methodology.

## Contributing

Contributions are welcome! Please read [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) before submitting a pull request.

## Legal Disclaimer

This toolkit is provided for **research and educational purposes only**. It is not legal advice. The tools perform passive analysis of network data that your own browser generates. Users are responsible for complying with applicable laws and terms of service in their jurisdiction. Consult a qualified attorney for legal guidance regarding privacy complaints or data access requests.

## License

MIT License — see [LICENSE](LICENSE) for details.
