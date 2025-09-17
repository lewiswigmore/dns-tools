# DNS Tools

[![Web UI](https://img.shields.io/badge/GitHub_Pages-Open_Site-blue)](https://lewiswigmore.github.io/dns-tools/)

A web-based DNS analysis platform for performing DNS lookups, MX record analysis, DMARC policy checking, and email header analysis.

## Features

- DNS record lookups (A, AAAA, CNAME, MX, TXT, NS)
- MX record analysis with priority and configuration details
- DMARC policy parsing and validation
- Email header analysis including SPF, DKIM, and DMARC authentication
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
- **MX Records**: Analyse mail server configurations
- **DMARC**: Check domain's DMARC policy implementation
- **Email Headers**: Parse and analyze email headers for authentication results

## Technology

Built with Flask and Alpine.js. Uses DNS-over-HTTPS for client-side lookups in the static version.
