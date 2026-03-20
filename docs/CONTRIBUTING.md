# Contributing to AI Transparency Suite

Thank you for your interest in contributing! This project aims to give consumers visibility into what AI platforms actually collect, and community contributions make it stronger.

## How to Contribute

### Reporting Issues

- Use [GitHub Issues](https://github.com/conde-fc/ai-transparency-suite/issues) to report bugs or suggest enhancements
- Include your Python version and OS when reporting bugs
- Never include real HAR files, session tokens, PII, or credentials in issues

### Adding Platform Support

To add or improve support for a platform:

1. Create or update the schema file in `schemas/` (e.g., `schemas/platform_name.json`)
2. Document known API endpoints, telemetry patterns, and analytics integrations
3. Include only information observable from public network traffic — no reverse engineering of obfuscated code
4. Test with a synthetic HAR fixture in `tests/fixtures/`

### Improving Analysis Tools

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Make your changes
4. Add or update tests in `tests/`
5. Run the test suite: `pytest`
6. Submit a pull request

### Writing Documentation

- Corrections, clarifications, and translations are welcome
- Keep language accessible — this toolkit is for consumers, not just engineers
- Reference specific regulations with citations where possible

## Code Standards

- **Python 3.10+** required
- **Minimal dependencies** — prefer the standard library (`json`, `csv`, `pathlib`, `argparse`, `re`, `collections`)
- **Every script must be self-contained** with dynamic paths (no hardcoded user paths)
- **Error handling**: `try/except` with `traceback.print_exc()` and `input("Press Enter...")` at the end
- **CSV output**: `quoting=csv.QUOTE_ALL`, `doublequote=True`, `encoding='utf-8-sig'`
- **No PII** in code, comments, examples, or commits — ever
- **Synthetic data only** in examples and test fixtures

## Commit Messages

Use the format: `type: description`

Types:
- `feat` — new feature
- `fix` — bug fix
- `docs` — documentation changes
- `refactor` — code restructuring
- `test` — adding or updating tests

## What Not to Submit

- Real HAR files or any real user data
- API keys, session tokens, or credentials
- Content that crosses into patent-protected analysis methodology (see CLAUDE.md IP BOUNDARY section)
- Heavy framework dependencies

## Code of Conduct

Be respectful, constructive, and focused on the mission: consumer transparency. This project exists to help people understand what data is being collected about them — keep that purpose central to all contributions.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
