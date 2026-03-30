# GitHub Copilot Instructions — dns-tools

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

### Reinstall all skills at once

```bash
npx skills add jeffallan/claude-skills@javascript-pro
npx skills add hairyf/skills@tailwindcss
npx skills add bobmatnyc/claude-mpm-skills@flask
npx skills add aviz85/claude-skills-library@gh-pages-deploy
npx skills add harperaa/secure-claude-skills@csrf-protection
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
