# AI Transparency Suite (ATS) — Claude Code Execution Plan
# Feed this to Claude Code as your first prompt after placing files in the project directory

## CONTEXT
I'm building an open-source repository called "AI Transparency Suite" (ATS).
GitHub: https://github.com/conde-fc/ai-transparency-suite
It enables any consumer to capture and analyze undisclosed data collection by AI chat platforms.
Read CLAUDE.md first — it has the full architecture, rules, and constraints.

## PHASE 1 — SCAFFOLD (do this now)

1. Read CLAUDE.md completely
2. Initialize git repo in this directory
3. Create .gitignore (exclude: *.har, .env, __pycache__/, *.pyc, .DS_Store, node_modules/, *.sqlite, /output/, /captures/)
4. Create the full directory structure from CLAUDE.md
5. Create LICENSE (MIT, copyright Fernando Conde 2026)
6. Create requirements.txt (minimal: rich>=13.0.0, pytest>=7.0.0)
7. Create setup.py with basic metadata (name=ai-transparency-suite, author=Fernando Conde)
8. Create README.md — professional, clear, structured:
   - What this toolkit does (one paragraph)
   - Why it exists (data collection exceeds disclosure — cite no specific user)
   - Quick start (install, capture HAR, run analysis)
   - What it finds (telemetry ratios, undisclosed integrations, experiment configs, PII in "private" modes)
   - Platforms covered (Claude, ChatGPT, Grok, DeepSeek, Gemini)
   - Contributing
   - Legal disclaimer (this is a research tool, not legal advice)
9. Create examples/SYNTHETIC_WARNING.md
10. Create docs/METHODOLOGY.md — explain the forensic methodology:
    - HAR capture is passive observation (F12 → Network → Export)
    - No interception, injection, or modification of traffic
    - Scripts analyze what platforms voluntarily send to the browser
    - All findings are independently reproducible
11. Create docs/LEGAL_CONTEXT.md — reference CCPA ADMT, GDPR profiling articles, FTC Section 5
12. Create docs/CONTRIBUTING.md — standard open-source contribution guide
13. Commit: "feat: initial project scaffold"

## PHASE 2 — CAPTURE GUIDE (do this next)

1. Create capture/CAPTURE_GUIDE.md:
   - Browser requirements (Chrome/Edge with DevTools)
   - Step-by-step HAR capture for each platform (with screenshots path placeholders)
   - How to capture in "normal" mode vs "incognito/private" mode
   - What to look for (Network tab, filter by XHR/Fetch)
   - How to export the HAR file
   - Security warnings (HAR files contain session tokens — never share raw files)
   - How to sanitize before analysis (the toolkit does this automatically)

2. Create capture/har_validator.py:
   - Takes a .har file path as input via argparse
   - Validates JSON structure (is it a valid HAR?)
   - Counts total entries (requests)
   - Reports: domains contacted, request methods, content types
   - Warns if file contains cookies/auth tokens (pre-sanitization check)
   - Output: validation report to stdout + optional JSON
   - Include --help with clear usage examples

3. Commit: "feat: capture guide and HAR validator"

## PHASE 3 — CORE ANALYSIS TOOLS (do these one at a time, test each)

### Tool 1: har_telemetry_counter.py
- Input: .har file via argparse
- Classifies each request as FUNCTIONAL (serves user's request) or TELEMETRY (analytics, tracking, experiments)
- Classification rules in schemas/ JSON files (domain patterns, path patterns)
- Output: ratio (e.g., "82.1% telemetry, 17.9% functional"), breakdown by domain
- Includes: "unknown" category for requests that don't match either pattern
- Test with synthetic fixture
- Commit: "feat: add har_telemetry_counter"

### Tool 2: har_domain_inventory.py
- Input: .har file
- Lists every unique domain contacted
- Classifies each: first-party, analytics, advertising, CDN, unknown
- Flags third-party domains not mentioned in platform's privacy policy
- Output: CSV + stdout summary
- Commit: "feat: add har_domain_inventory"

### Tool 3: har_experiment_detector.py
- Input: .har file
- Searches for: statsig payloads, feature_gates, experiment configs, A/B test assignments
- Extracts: experiment names, group assignments, feature flag states
- Output: markdown report of all detected experiments
- Commit: "feat: add har_experiment_detector"

### Tool 4: har_pii_scanner.py
- Input: .har file
- Scans all request/response bodies for: email patterns, UUIDs, IP addresses, auth tokens, names
- Reports: what PII was found, in which request, to which domain
- Critical for incognito audit: "your email was sent to X even in private mode"
- Commit: "feat: add har_pii_scanner"

### Tool 5: har_incognito_auditor.py
- Input: two .har files (one normal session, one incognito/private session) via argparse
- Compares: which telemetry endpoints are still called, which PII still transmitted
- Output: delta report — "these N requests still occurred in private mode with PII"
- Commit: "feat: add har_incognito_auditor"

### Tool 6: har_field_classifier.py
- Input: .har file
- Deep-parses all JSON request/response bodies
- Classifies every field by category: user_profile, behavioral, telemetry, functional, experiment, content
- Assigns privacy_sensitivity score (0-3)
- Output: CSV of all fields with classifications
- Commit: "feat: add har_field_classifier"

### Create schemas/ JSON files alongside tools:
- claude.json, chatgpt.json, grok.json, deepseek.json, gemini.json
- Each contains: known first-party domains, known telemetry endpoints, known experiment patterns
- Commit: "feat: add platform schema definitions"

## PHASE 4 — COMPARISON TOOLS

### policy_field_mapper.py
- Input: analysis output (from Phase 3) + platform schema JSON
- Compares fields collected vs fields disclosed in privacy policy
- Output: gap report — "these N fields are collected but not disclosed"
- Commit: "feat: add policy_field_mapper"

### export_gap_analyzer.py
- Input: platform data export + HAR analysis
- Compares what platform gives you in a data export vs what it actually collects
- Output: delta report with specific field names
- Commit: "feat: add export_gap_analyzer"

## PHASE 5 — REPORTING

### evidence_report.py
- Aggregates all analysis outputs into a single markdown evidence report
- Uses templates from report/templates/
- Includes: executive summary, per-platform findings, methodology reference
- Commit: "feat: add evidence_report generator"

### sanitizer.py
- Strips any remaining PII from reports before sharing
- Scans for email patterns, UUIDs, file paths, auth tokens
- Replaces with [REDACTED_EMAIL], [REDACTED_UUID], [REDACTED_PATH], etc.
- Commit: "feat: add report sanitizer"

### Create report templates:
- report/templates/ftc_complaint.md
- report/templates/gdpr_request.md
- report/templates/findings_summary.md
- Commit: "feat: add report templates"

### Create sample outputs in examples/ using SYNTHETIC data only
- Commit: "feat: add synthetic example outputs"

## PHASE 6 — CI/CD

1. Create .github/workflows/test.yml — run pytest on push
2. Create .github/workflows/lint.yml — run ruff or flake8
3. Commit: "feat: add CI workflows"

## PHASE 7 — PUBLISH

1. Final review of all files for PII (run har_pii_scanner against the repo itself)
2. Add remote: git remote add origin https://github.com/conde-fc/ai-transparency-suite.git
3. Push: git push -u origin main
4. Set repo to PUBLIC on GitHub
5. Add topics: ai-transparency, privacy, har-analysis, telemetry, consumer-rights, ftc

## IMPORTANT NOTES
- DO NOT include any real HAR data, real telemetry captures, or real user data
- All examples must use clearly synthetic/placeholder data
- The repo teaches methodology — users bring their own captures
- Keep dependencies minimal — this must run on any machine with Python 3.10+
- Every script must work standalone: python script.py --help shows usage
- Every script must include try/except with traceback.print_exc() and input("Press Enter...")
