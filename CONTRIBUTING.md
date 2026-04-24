# Contributing to ThreatBlade

Thanks for taking the time to contribute. Here's how to get started.

## Ways to Contribute

- **Bug reports** — open an issue using the bug report template
- **Feature requests** — open an issue using the feature request template
- **Code** — submit a pull request (see below)
- **Documentation** — fix typos, improve examples, add missing docs

## Development Setup

```bash
git clone https://github.com/najinkya776/ThreatBlade.git
cd ThreatBlade
pip install -r requirements.txt
cp config/keys.json.example config/keys.json
# Add your API keys to config/keys.json
python app.py
```

## Submitting a Pull Request

1. Fork the repository
2. Create a branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Test both the web app and CLI if your change touches shared modules
5. Commit with a clear message explaining what and why
6. Push and open a pull request against `master`

## Adding a New Module

1. Create `modules/your_module.py`
2. Implement a `your_menu()` function for the CLI
3. Implement `_data` functions that return dicts (used by the Flask API)
4. Add a Flask route in `app.py`
5. Add a section in `static/js/app.js` and `templates/index.html`
6. Add a sidebar nav item in `templates/index.html`

## Code Style

- Keep functions small and focused
- No inline comments unless the logic is genuinely non-obvious
- Match the existing style — dark theme, result cards, badge helpers in JS

## Module Ideas

- Shodan IP/host lookup
- URLScan.io submission and result retrieval
- MITRE ATT&CK technique lookup
- Sigma rule generator from IOCs
- Passive DNS history
- Certificate transparency log search

## Reporting Vulnerabilities

See [SECURITY.md](SECURITY.md).
