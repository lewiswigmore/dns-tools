# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Architecture & Privacy

DNS Tools is designed with a **privacy-first, client-side architecture**:

- All DNS lookups use **DNS-over-HTTPS (DoH)** directly from the browser to Google, Cloudflare, or Quad9
- WHOIS/RDAP queries are made **directly from the browser** via the IANA bootstrap protocol — no server proxy
- **No user data is transmitted to or stored on any backend server**
- Search history and settings are stored exclusively in the browser's `localStorage`
- The Flask backend serves only static HTML/JS/CSS; all queries originate from the client

## Security Features

- **Content Security Policy (CSP)** headers restrict script and resource origins
- **CSRF protection** on all mutating API endpoints
- **Hardened session cookies** (`HttpOnly`, `Secure`, `SameSite=Lax`)
- **Rate limiting** on API routes
- **Security headers**: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`
- **Input validation** on all domain and query inputs

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public issue
2. Use [GitHub's private vulnerability reporting](https://github.com/lewiswigmore/dns-tools/security/advisories/new) to submit a report with:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact
3. You will receive an acknowledgement as soon as possible
4. A fix will be developed and released promptly

Thank you for helping keep DNS Tools secure.
