# DNS Tools

[![Web UI](https://img.shields.io/badge/GitHub_Pages-Open_Site-blue)](https://lewiswigmore.github.io/dns-tools/)

A privacy-focused, client-side web toolkit for DNS lookups, WHOIS/RDAP domain registration queries, email security analysis, and threat intelligence.

## Features

- DNS record lookups (A, AAAA, CNAME, MX, TXT, NS) via DNS-over-HTTPS
- WHOIS/RDAP domain registration lookups via IANA bootstrap (client-side, no proxy)
- MX record analysis with priority and configuration details
- DMARC policy parsing and validation
- Email header analysis including SPF, DKIM, and DMARC authentication
- Threat intelligence lookups and reputation checks
- Local session-based activity tracking and statistics
- Search history with result caching
- Documentation and resources for DNS and email security

## Setup

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run the application: `python app.py`
4. Open your browser to `http://localhost:5000`

## GitHub Pages Deployment

This project includes a static site generator for GitHub Pages deployment:

1. Run `python generate_static.py` to create static files
2. Enable GitHub Pages in repository settings
3. The GitHub Actions workflow will automatically deploy changes

## Usage

The interface provides separate tools for different types of DNS analysis:

- **DNS Lookup**: Query multiple domains for various record types
- **WHOIS Lookup**: Domain registration data via RDAP (registrar, dates, nameservers, DNSSEC)
- **MX Records**: Analyse mail server configurations
- **DMARC**: Check domain's DMARC policy implementation
- **Email Headers**: Parse and analyze email headers for authentication results
- **Threat Intel**: Reputation and security intelligence lookups

## Technology

Built with Flask and Alpine.js. Uses DNS-over-HTTPS (Google, Cloudflare, Quad9) and IANA RDAP bootstrap for fully client-side lookups.
