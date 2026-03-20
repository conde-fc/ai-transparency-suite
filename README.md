# AI Transparency Suite (ATS)

**Open-source toolkit for measuring and documenting data collection by AI chat platforms.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

## Why This Exists

As AI tools become part of daily workflows, understanding what happens during your sessions matters. Consumers interact with AI platforms through a browser, and everything that happens — every API call, every analytics payload, every experiment assignment — is already visible in the browser's developer tools. ATS organizes that visibility into reproducible, structured analysis. Using standard HAR (HTTP Archive) captures, it measures telemetry ratios, inventories third-party integrations, detects experiment infrastructure, and maps the relationship between observed data collection and published privacy disclosures. All findings are independently reproducible.

## What It Finds

- **Telemetry ratios** — what percentage of API calls serve the user vs. perform analytics
- **Observed integrations** — third-party analytics services (Segment, Amplitude, StatsIg) found in network traffic
- **Experiment infrastructure** — A/B tests, feature gates, and experiment configs present in API responses
- **Private mode behavior** — what data is still transmitted during incognito/private sessions
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

# Audit a capture from incognito/private mode
python analyze/har_incognito_auditor.py incognito_capture.har

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
