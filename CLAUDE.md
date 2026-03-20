# AI Transparency Suite (ATS)
# Project CLAUDE.md — Read this FIRST every session

## OWNER
Fernando Conde (conde-fc on GitHub)
Repo: https://github.com/conde-fc/ai-transparency-suite

## PURPOSE
Open-source forensic toolkit enabling any consumer to capture, analyze, and document undisclosed data collection by AI chat platforms. Supports FTC complaints, GDPR/CCPA requests, and independent research.

## ABSOLUTE RULES
1. NEVER include API keys, cookies, session tokens, email addresses, or any PII in code, comments, examples, or commits
2. NEVER delete files — move to .archive/ if replacing
3. All Python scripts include try/except with traceback.print_exc() and input("Press Enter...")
4. All CSV output uses quoting=csv.QUOTE_ALL, doublequote=True, encoding='utf-8-sig'
5. State constraints and limits in FIRST line of every docstring
6. No fabricated data in examples — use clearly marked SYNTHETIC placeholders
7. Every script must be self-contained with dynamic paths (no hardcoded user paths)
8. Pre-flight checks before any operation (file exists? dependencies installed? output dir writable?)
9. Commit messages: "type: description" (feat/fix/docs/refactor/test)

## IP BOUNDARY — READ CAREFULLY
This project (ATS) is open-source under MIT license. It covers forensic METHODOLOGY only:
what platforms collect, how to capture it, how to classify it, how to compare it to disclosures.

The following are PATENT-PROTECTED (US Provisional, Dec 2025) and must NEVER appear in this repo:
- Primitive linguistic pattern definitions (the 17-36 atomic patterns)
- Detection algorithms for identifying behavioral mechanisms
- Composition rules mapping primitives to higher-order mechanisms
- FSC (Failed Solution Cycle) or WIP (Wasted Interaction Percentage) formulas
- Severity scoring formulas or temporal correlation methodology
- IHMF (Integrated Harm Measurement Framework) specifics
- Any content from the ai-interaction-safety-specs repo's unpublished material

If in doubt: ATS answers "WHAT data do platforms collect?" — never "HOW does that data harm users at the mechanism level?"
The patent covers the HOW. This repo covers the WHAT.

## ARCHITECTURE
```
ai-transparency-suite/
├── CLAUDE.md                    # This file
├── README.md                    # Public-facing documentation
├── LICENSE                      # MIT
├── requirements.txt             # Python dependencies
├── setup.py                     # Optional pip install
├── .gitignore                   # Exclude HAR files, .env, __pycache__, etc.
│
├── capture/                     # Phase 1: How to capture data
│   ├── CAPTURE_GUIDE.md         # Step-by-step HAR capture instructions per platform
│   └── har_validator.py         # Validates HAR file structure before analysis
│
├── analyze/                     # Phase 2: Analysis tools
│   ├── har_telemetry_counter.py # Counts telemetry vs functional API calls
│   ├── har_domain_inventory.py  # Lists all domains contacted during session
│   ├── har_field_classifier.py  # Classifies fields by privacy sensitivity
│   ├── har_experiment_detector.py # Finds A/B test configs, feature gates, statsig
│   ├── har_pii_scanner.py       # Detects PII in request/response payloads
│   └── har_incognito_auditor.py # Checks if "private" modes actually prevent tracking
│
├── compare/                     # Phase 3: Policy vs reality
│   ├── policy_field_mapper.py   # Maps collected fields to privacy policy disclosures
│   └── export_gap_analyzer.py   # Compares what platform collects vs what it exports to user
│
├── report/                      # Phase 4: Output generation
│   ├── evidence_report.py       # Generates markdown evidence report from analysis
│   ├── templates/               # Report templates
│   │   ├── ftc_complaint.md     # FTC complaint template with evidence placeholders
│   │   ├── gdpr_request.md      # GDPR data access request template
│   │   └── findings_summary.md  # General findings template
│   └── sanitizer.py             # Strips all PII from reports before sharing
│
├── schemas/                     # Platform-specific knowledge
│   ├── claude.json              # Known Claude API endpoints, telemetry patterns
│   ├── chatgpt.json             # Known ChatGPT endpoints, statsig patterns
│   ├── grok.json                # Known Grok endpoints, thinking token patterns
│   ├── deepseek.json            # Known DeepSeek endpoints, telemetry infra
│   └── gemini.json              # Known Gemini RPC patterns
│
├── examples/                    # Sanitized example outputs (NO real user data)
│   ├── SYNTHETIC_WARNING.md     # "All data in this folder is synthetic"
│   ├── sample_telemetry_report.md
│   ├── sample_domain_inventory.csv
│   └── sample_experiment_findings.md
│
├── tests/                       # Unit tests
│   ├── test_har_parser.py
│   ├── test_telemetry_counter.py
│   ├── test_pii_scanner.py
│   └── fixtures/                # Minimal synthetic HAR snippets for testing
│       └── synthetic_har.json
│
└── docs/                        # Extended documentation
    ├── METHODOLOGY.md           # Forensic methodology explanation
    ├── PLATFORM_FINDINGS.md     # Summary of findings per platform (no PII)
    ├── LEGAL_CONTEXT.md         # Relevant regulations (CCPA, GDPR, FTC Act)
    └── CONTRIBUTING.md          # How others can contribute
```

## PLATFORMS COVERED
1. Claude (Anthropic) — claude.ai
2. ChatGPT (OpenAI) — chatgpt.com
3. Grok (xAI) — grok.com
4. DeepSeek — chat.deepseek.com
5. Gemini (Google) — gemini.google.com

## KEY FINDINGS TO DOCUMENT (sanitized, no PII)
- Anthropic: telemetry during incognito mode, Segment.io/Amplitude integrations not in policy
- OpenAI: 82% of API calls are telemetry, statsig experiment infrastructure undisclosed
- DeepSeek: keystroke collection, China-based servers, weak encryption
- Grok: thinking token timestamps (billed but invisible computation)
- Gemini: RPC obfuscation making analysis deliberately difficult

## GIT WORKFLOW
- Main branch: `main`
- Feature branches: `feat/tool-name`
- Always commit with descriptive messages
- Push to GitHub regularly
- Never commit .har files, .env, or anything with PII

## DEPENDENCIES (keep minimal)
- Python 3.10+
- Standard library preferred (json, csv, pathlib, argparse, re, collections)
- Optional: rich (for CLI output formatting)
- NO heavy frameworks — this must run on any machine with Python

## TESTING
- pytest for unit tests
- All tools must work on synthetic HAR data (no real captures in repo)
- CI via GitHub Actions (lint + test on push)
