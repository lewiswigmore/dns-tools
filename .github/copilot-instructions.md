# GitHub Copilot Instructions — dns-tools

## Self-Improvement Rules

This file is a **living document**. You (the AI agent) are expected to keep it accurate and complete. Apply these rules on every session:

1. **Update when you learn something new.** If you discover a convention, pattern, gotcha, or architectural fact not captured here, add it to the relevant section and propose a commit.
2. **Update the Skills table** any time you install or uninstall a skill via `npx skills add/remove`. Add the row and the reinstall command immediately.
3. **Update Project Structure** when new top-level files, folders, or significant modules are added or removed.
4. **Update Key Conventions** when a new recurring pattern is established (e.g. a new naming rule, a new shared utility, a security practice).
5. **Record known gotchas** in the Gotchas section below when a bug, edge case, or non-obvious behaviour is encountered and resolved.
6. **Commit this file atomically** with the code change that prompted the update, or as a standalone `docs: update Copilot instructions` commit if the update is purely documentary.
7. **Do not remove** entries unless they are factually wrong — prefer marking them obsolete with a `~~strikethrough~~` note and the date.
8. **Security headers, rate-limiting, and CSRF rules defined in `app.py` are non-negotiable.** Never suggest removing or weakening them.

> **For contributors:** If the agent has not updated this file after a significant change, prompt it with: *"Update copilot-instructions.md to reflect what we just did."*

---


## Project Stack

- **Backend:** Python / Flask (`app.py`) — serves API endpoints and renders Jinja2 templates
- **Frontend:** Vanilla JavaScript (ES modules) in `static/js/modules/`
- **Styling:** Tailwind CSS (CDN) across all templates in `templates/`
- **Static build:** `generate_static.py` converts Flask templates to a `dist/` folder
- **Deployment:** GitHub Pages via `.github/workflows/deploy.yml` (pushes `dist/` on every merge to `main`)

## Agent Skills

Skills are **local developer tools** that extend AI assistant capabilities with domain-specific knowledge. They are **not committed to the repository** — each developer installs them locally.

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
| `gh-cli` | GitHub CLI (`gh`) — PRs, issues, releases, Pages, Actions | `npx skills add github/awesome-copilot@gh-cli` |

### Reinstall all skills at once

```bash
npx skills add jeffallan/claude-skills@javascript-pro
npx skills add hairyf/skills@tailwindcss
npx skills add bobmatnyc/claude-mpm-skills@flask
npx skills add aviz85/claude-skills-library@gh-pages-deploy
npx skills add harperaa/secure-claude-skills@csrf-protection
npx skills add github/awesome-copilot@gh-cli
```

## Project Structure

```
app.py                        Flask application and API routes
generate_static.py            Static site generator (Flask → dist/)
templates/                    Jinja2 HTML templates
static/js/modules/            Vanilla JS ES module frontend
  components/                 Page-level UI components
  data/                       Static knowledge base data
.github/workflows/deploy.yml  GitHub Actions: build + deploy to Pages
```

## Key Conventions

- Templates use `url_for()` which is remapped in `generate_static.py` for static output
- JS modules use native ES module imports (no bundler)
- All API calls in `dns-client.js` target public DNS-over-HTTPS resolvers
- Security headers are set in `app.py` `after_request` hook

## Known Gotchas

> Add entries here when a non-obvious bug or edge case is discovered and resolved.
> Format: `- **YYYY-MM-DD** — <symptom>: <root cause> → <fix/workaround>`

- **2026-03-30** — `generate_static.py` maps Flask `url_for()` endpoints to static paths; adding a new Flask route requires a matching entry in the `endpoint_map` dict inside `create_static_site()` or the static build will produce broken links.
- **2026-03-30** — `dist/` is in `.gitignore`. It is built and deployed by GitHub Actions on every push to `main`; never manually commit the `dist/` folder.
- **2026-03-30** — `.agents/`, `.claude/`, and `skills-lock.json` are excluded from git. Skills must be reinstalled locally by each contributor (see Agent Skills section above).

