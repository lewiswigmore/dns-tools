# GitHub Copilot instructions for dns-tools

## Self-improvement rules

This file is a **living document**. You (the AI agent) are expected to keep it accurate and complete. Apply these rules on every session:

1. **Update when you learn something new.** If you discover a convention, pattern, gotcha, or architectural fact not captured here, add it to the relevant section and propose a commit.
2. **Update the Skills table** any time you install or uninstall a skill via `npx skills add/remove`. Add the row and the reinstall command immediately.
3. **Update Project Structure** when new top-level files, folders, or significant modules are added or removed.
4. **Update Key Conventions** when a new recurring pattern is established (e.g. a new naming rule, a new shared utility, a security practice).
5. **Record known gotchas** in the Gotchas section below when a bug, edge case, or non-obvious behaviour is encountered and resolved.
6. **Commit this file atomically** with the code change that prompted the update, or as a standalone `docs: update Copilot instructions` commit if the update is purely documentary.
7. **Do not remove** entries unless they are factually wrong. Prefer marking them obsolete with a `~~strikethrough~~` note and the date.
8. **Security headers, rate-limiting, and CSRF rules defined in `app.py` are non-negotiable.** Never suggest removing or weakening them.

> **For contributors:** If the agent has not updated this file after a significant change, prompt it with: *"Update copilot-instructions.md to reflect what we just did."*

---


## Project stack

- **Backend:** Python / Flask (`app.py`), serves API endpoints and renders Jinja2 templates
- **Frontend:** Vanilla JavaScript (ES modules) in `static/js/modules/`
- **Styling:** Tailwind CSS (CDN) across all templates in `templates/`
- **Static build:** `generate_static.py` converts Flask templates to a `dist/` folder
- **Deployment:** GitHub Pages via `.github/workflows/deploy.yml` (pushes `dist/` on every merge to `main`)

## Agent skills

Skills are **local developer tools** that extend AI assistant capabilities with domain-specific knowledge. They are **not committed to the repository**, each developer installs them locally.

### Skill location

```
.agents/skills/          ← canonical skill files (universal, all agents)
.claude/skills/          ← symlinks to .agents/skills/ for Claude Code
skills-lock.json         ← version lock file (auto-generated)
```

Both directories and `skills-lock.json` are listed in `.gitignore`. When contributing to this project, reinstall skills locally using the commands below.

### Installed skills

| Skill | Purpose | Install command |
|---|---|---|
| `javascript-pro` | Modern ES2023+ JS patterns, async/await, ESM modules | `npx skills add jeffallan/claude-skills@javascript-pro` |
| `tailwindcss` | Tailwind CSS utility classes, responsive design, theming | `npx skills add hairyf/skills@tailwindcss` |
| `flask` | Flask routing, blueprints, Jinja2, request handling | `npx skills add bobmatnyc/claude-mpm-skills@flask` |
| `gh-pages-deploy` | GitHub Pages static deployment via `gh` CLI | `npx skills add aviz85/claude-skills-library@gh-pages-deploy` |
| `csrf-protection` | CSRF token validation for Flask POST/PUT/DELETE endpoints | `npx skills add harperaa/secure-claude-skills@csrf-protection` |
| `gh-cli` | GitHub CLI (`gh`), PRs, issues, releases, Pages, Actions | `npx skills add github/awesome-copilot@gh-cli` |
| `local-dev` | Local development setup, Flask dev server, static build, env config | *(local-only, create `.agents/skills/local-dev/SKILL.md` manually)* |

### Reinstall all skills at once

```bash
npx skills add jeffallan/claude-skills@javascript-pro
npx skills add hairyf/skills@tailwindcss
npx skills add bobmatnyc/claude-mpm-skills@flask
npx skills add aviz85/claude-skills-library@gh-pages-deploy
npx skills add harperaa/secure-claude-skills@csrf-protection
npx skills add github/awesome-copilot@gh-cli
```

## Project structure

```
app.py                        Flask application and API routes
generate_static.py            Static site generator (Flask to dist/)
templates/                    Jinja2 HTML templates
static/js/modules/            Vanilla JS ES module frontend
  components/                 Page-level UI components (lookup, whois, dmarc, etc.)
  utils.js                    Shared browser utilities and single-domain page setup
  rdap-client.js              RDAP domain lookup client (IANA bootstrap, no proxy)
  data/                       Static knowledge base data
tests/                        Pytest security checks and Node.js regression tests
.github/workflows/deploy.yml  GitHub Actions: build + deploy to Pages
```

## Key conventions

- Templates use `url_for()` which is remapped in `generate_static.py` for static output
- JS modules use native ES module imports (no bundler)
- Page-level clipboard actions keep their `copyToClipboard` methods for template bindings and delegate the browser clipboard operation to `copyTextToClipboard()` in `utils.js`
- MX and DMARC pages share the `commonDomainPresets()` and `initializeDomainLookup()` helpers in `utils.js` for consistent presets and URL-driven auto-lookups
- Responsive layout is shared in `templates/base.html`: result headers use `result-toolbar` / `result-actions`; secondary copy/share/export text uses `action-label` (visually hidden on phones, retained for screen readers). Keep primary and destructive actions labelled, and retain 44px mobile touch targets.
- All API calls in `dns-client.js` target public DNS-over-HTTPS resolvers
- DNS-over-HTTPS TXT formatting varies by provider: DMARC lookups normalize unquoted or DNS-quoted, possibly split, TXT data for parsing while retaining the original record value for display and other lookup surfaces.
- Run JavaScript regressions with `node --experimental-default-type=module --test`; both the Tests and Pages deployment workflows run them with Node 22.
- WHOIS/RDAP lookups in `rdap-client.js` use IANA bootstrap (`data.iana.org/rdap/dns.json`, `ipv4.json`, `ipv6.json`) to find authoritative RDAP servers for domains and IPs and query them directly from the browser
- Security headers are set in `app.py` `after_request` hook
- Mutating Flask API routes (`POST`/`PUT`/`PATCH`/`DELETE`) require a valid CSRF token via `X-CSRF-Token` (or `csrf_token` in JSON body), with token issued by `/api/csrf-token`
- Content Library pagination state is URL-driven (`q`, `complexity`, `page`, `size`) via `resources.js` so filtered views are shareable
- The Threat Intelligence page (`intel.html`/`intel.js`) includes a client-side "Fraud Risk Indicators" panel for domains: it combines RDAP registration/status data with DNS presence and mail-auth (SPF/DMARC) checks into heuristic, non-authoritative signals. It runs only on explicit user action (not automatically) and never performs browser-side HTTP reachability checks (unreliable due to CORS)

## Known gotchas

> Add entries here when a non-obvious bug or edge case is discovered and resolved.
> Format: `- **YYYY-MM-DD**: <symptom>: <root cause>, <fix/workaround>`

- **2026-11-10**: Lookup result actions overflowed phone viewports after queries. Allow flex/grid children to shrink, wrap shared result toolbars, and use compact secondary action icons with accessible text. Mobile navigation must be inert while closed and return focus to its toggle when dismissed.
- **2026-11-04**: Editing the Threat Intelligence input left an enabled Run Check that silently did nothing. Share normalized target eligibility between the method guard and button disabled state (`fraudTargetMatches`); show Analyze guidance while they differ. Analyze restores eligibility for the new domain without weakening request-identity guards.
- **2026-11-04**: Fraud risk results could remain under a different Threat Intelligence target. Reset fraud state and invalidate pending requests on input edits, presets, and analysis (including empty/invalid/non-domain targets); guard success, error, and loading updates by request identity and target. Store and display the checked domain with each assessment. A domain comparison alone cannot stop an old request after switching away and back or starting a same-domain recheck.
- **2026-11-03**: Cloudflare DMARC lookups falsely reported missing records because TXT values can contain quoted chunks; normalize complete DNS presentation strings for DMARC matching and parsing, but leave the original TXT values unchanged.
- **2026-11-03**: DMARC comparison views and copied summaries must use each successful provider's parsed `dmarc` result, not TXT `records.length` or the first TXT value: unrelated TXT is not a policy. Show absence per successful provider with no parsed policy, and show explicit `status: 'error'` results as failures. `queryDNS()` still converts transport failures to empty arrays; changing that fallback is separate work.
- **2026-11-03**: Older Dependabot PRs cannot be rebased by the bot after their update configuration is removed (version updates are intentionally disabled here). Use `gh pr update-branch <number> --rebase`, then wait for fresh checks.
- **2026-03-30**: `generate_static.py` maps Flask `url_for()` endpoints to static paths; adding a new Flask route requires a matching entry in the `endpoint_map` dict inside `create_static_site()` or the static build will produce broken links.
- **2026-03-30**: `dist/` is in `.gitignore`. It is built and deployed by GitHub Actions on every push to `main`; never manually commit the `dist/` folder.
- **2026-03-30**: `.agents/` and `skills-lock.json` are excluded from git. Skills must be reinstalled locally by each contributor (see Agent skills section above).
- **2026-03-30**: Flask API write operations now enforce CSRF: client code must fetch token from `/api/csrf-token` (or read template-provided token) and send it in `X-CSRF-Token`; otherwise API responds `403 Invalid or missing CSRF token`.
- **2026-03-30**: CSP `connect-src` uses `https:` (all HTTPS origins) because RDAP servers span hundreds of different domains; this is necessary for the WHOIS/RDAP lookup feature to reach arbitrary registry servers.
- **2026-03-31**: RDAP `nameservers` frequently omit `ipAddresses` for NS hostnames (for example `gov.uk`); UI should treat empty IPv4/IPv6 as expected and optionally enrich via DNS A/AAAA lookups as fallback.
- **2026-04-01**: Bulk domain input (lookup/comparison) in `dns-client.js` didn't strip wrapping quotes/brackets from pasted list-style text, silently dropping otherwise valid entries, and its validator accepted non-domain tokens (numeric-only TLDs) as lookup targets. Fixed via a shared `parseDomainList()`/`sanitizeDomainToken()` helper and a stricter `isValidDomain()` (rejects whitespace, requires an alphabetic 2+ character TLD). Any future bulk-input parsing should go through this shared helper rather than re-duplicating the split/filter logic.
- **2026-09-16**: Bulk lists commonly contain email addresses rather than bare domains (e.g. pasted from a contact export). Rejecting anything with `@` meant those rows silently disappeared from results instead of being looked up. `dns-client.js` now resolves a simple `local-part@domain` token to its domain before validation (via `extractDomainFromToken()`), so the domain is looked up as expected; tokens with more than one `@` are still dropped as ambiguous.
- **2026-09-20**: `rdap-client.js`'s `queryDomain(domain)` resolves to `{ result, server }`, not the parsed RDAP object directly. Any new caller must destructure/`.then(r => r.result)` to reach `{keyDates, status, roles, registrar, nameservers, ...}`, a common trap when adding new features that consume RDAP data (e.g. the Fraud Risk Indicators panel in `intel.js`).
- **2026-09-16**: Bulk paste input (e.g. copying a whole incident timeline/table into the lookup box) commonly contains tokens that are syntactically domain-shaped but aren't real domains: counters like `6.2M`, filenames like `image.png`, and PascalCase identifiers like `Files.Read`, `User.ReadWrite` or a `Namespace.Class.Name` path. `isValidDomain()` in `dns-client.js` now rejects these via three targeted TLD checks: the TLD must be letters-only (or a valid `xn--` punycode form, so no digits), the TLD's case must be uniform (all-lower or all-upper, since real TLDs are never mixed/camelCase, unlike identifiers such as `ReadWrite` or `HttpLoggingMiddleware`), and the TLD isn't a common non-TLD file extension (`png`, `docx`, `json`, etc., kept as a small denylist rather than an allowlist so real-but-uncommon TLDs still work). `.zip`/`.mov` are deliberately left off that denylist since they're real registered gTLDs. This heuristic reduces noise but is not exhaustive; genuinely ambiguous tokens (e.g. a truncated FQDN missing its real suffix) will still pass and simply show "no records found".
