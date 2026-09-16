# DNS Tools

[![Deploy to GitHub Pages](https://github.com/lewiswigmore/dns-tools/actions/workflows/deploy.yml/badge.svg)](https://github.com/lewiswigmore/dns-tools/actions/workflows/deploy.yml)
[![CodeQL](https://github.com/lewiswigmore/dns-tools/actions/workflows/codeql.yml/badge.svg)](https://github.com/lewiswigmore/dns-tools/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Web UI](https://img.shields.io/badge/GitHub_Pages-Open_Site-blue)](https://lewiswigmore.github.io/dns-tools/)

A privacy-focused, client-side web toolkit for DNS lookups, WHOIS/RDAP domain registration queries, email security analysis, and threat intelligence. Deployed as a static site on GitHub Pages.

## Features

### DNS & domain analysis
- **DNS lookups**: query A, AAAA, CNAME, MX, TXT, and NS records via DNS-over-HTTPS (DoH)
- **Provider comparison**: compare results across Google, Cloudflare, and Quad9 DNS resolvers
- **WHOIS / RDAP**: domain registration data (registrar, dates, nameservers, DNSSEC) via IANA bootstrap, queried directly from the browser

### Email security
- **MX records**: mail server analysis with priority and configuration details
- **DMARC**: policy parsing and validation for domain email authentication
- **Email headers**: parse raw headers and check SPF, DKIM, and DMARC authentication results

### Threat intelligence
- **Deep links**: launch lookups against VirusTotal, AbuseIPDB, Shodan, and more for IPs, domains, and file hashes
- **Knowledge base**: curated reference material on DNS, email, networking, security, and cloud topics

### Privacy & UX
- **100% client-side queries**: DNS and RDAP requests go directly from your browser to public resolvers, no server proxy
- **No telemetry**: no analytics, no tracking, no cookies beyond CSRF protection
- **Local history & settings**: stored in `localStorage`, never leaves your browser
- **Dashboard**: session statistics, recent lookups, and quick access to tools
- **Command palette**: press `/` for keyboard-driven navigation

## Quick start

```bash
git clone https://github.com/lewiswigmore/dns-tools.git
cd dns-tools
pip install -r requirements.txt
python app.py
# Open http://localhost:5000
```

## GitHub Pages deployment

The site is automatically deployed on every push to `main` via GitHub Actions:

1. `generate_static.py` renders Jinja2 templates into a `dist/` folder
2. The [deploy workflow](.github/workflows/deploy.yml) uploads and publishes to GitHub Pages

To deploy manually:

```bash
python generate_static.py   # outputs to dist/
```

## Technology

| Layer     | Stack                                      |
| --------- | ------------------------------------------ |
| Backend   | Python / Flask (template rendering only)   |
| Frontend  | Alpine.js, Tailwind CSS                    |
| DNS       | DNS-over-HTTPS (Google, Cloudflare, Quad9) |
| WHOIS     | IANA RDAP Bootstrap (client-side)          |
| Hosting   | GitHub Pages (static)                      |
| CI/CD     | GitHub Actions                             |
| Security  | CodeQL, Dependabot, CSP, CSRF, rate limits |

## Security

See [SECURITY.md](SECURITY.md) for the security policy and vulnerability reporting instructions.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

This project is licensed under the [MIT License](LICENSE).
