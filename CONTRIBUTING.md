# Contributing to DNS Tools

Thanks for your interest in contributing! Here's how to get started.

## Getting Started

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/<your-username>/dns-tools.git`
3. **Install dependencies**: `pip install -r requirements.txt`
4. **Run locally**: `python app.py` → open `http://localhost:5000`

## Development

### Project Structure

```
dns-tools/
├── app.py                  # Flask application (serves pages + API)
├── generate_static.py      # Static site generator for GitHub Pages
├── templates/              # Jinja2 HTML templates
├── static/
│   ├── js/modules/         # Alpine.js components & clients
│   └── images/             # Logos and assets
├── tests/                  # Security and integration tests
└── dist/                   # Generated static site (git-ignored)
```

### Key Principles

- **Client-side first** — DNS, RDAP, and analysis happen in the browser; no server proxying of user queries
- **Privacy by design** — no telemetry, no server-side logging of lookups, `localStorage` only
- **Minimal dependencies** — keep the stack lean (Flask + Alpine.js + Tailwind CSS)

### Running Tests

```bash
python -m pytest tests/ -v
```

## Submitting Changes

1. Create a **feature branch**: `git checkout -b feature/my-change`
2. Make your changes with clear, descriptive commits
3. Ensure tests pass: `python -m pytest tests/ -v`
4. Push and open a **Pull Request** against `main`

## Reporting Issues

Use the [issue templates](https://github.com/lewiswigmore/dns-tools/issues/new/choose) for bug reports, feature requests, or questions.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).
