# Contributing

This repository is the single integration point for the six-member team. Keep it boring
and predictable so the demo build never breaks.

## Branches

| Branch | Purpose |
| --- | --- |
| `main` | Stable, demo-ready. Only fast-forward merges from `dev` after a full end-to-end check. |
| `dev` | Integration branch. All feature branches merge here through pull requests. |
| `feature/<area>-<topic>` | New work, e.g. `feature/frontend-dashboard`, `feature/auth-api`, `feature/model-xgboost`. |
| `fix/<topic>` | Bug fixes, e.g. `fix/upload-parser`. |
| `docs/<topic>` | Documentation-only changes. |

Start from `dev`:

```bash
git checkout dev && git pull
git checkout -b feature/<area>-<topic>
```

## Commit messages

Use a simple prefix and a short imperative summary:

`feat:` new feature · `fix:` bug fix · `docs:` documentation · `refactor:` cleanup ·
`test:` tests · `chore:` setup/config

Examples: `feat: add alert detail API`, `fix: handle missing packet timestamps`.

## Pull requests

Open PRs against `dev`. The template asks for: what changed, screenshots for UI, test
status, and known limitations. At least one teammate reviews before merging. Keep PRs
small enough to review in ten minutes.

## Issues and labels

Track work in GitHub Issues / Projects with the columns
Backlog → This Week → In Progress → Blocked → Review → Ready for Integration → Done.

Labels: `frontend`, `backend`, `ml`, `bug`, `urgent`, `demo`, `docs`.

## Naming conventions

- Files: `lowercase_with_underscores` (Python) or `kebab-case` (docs); be consistent within a folder.
- API routes: `/api/v1/alerts`, `/api/v1/predictions`.
- Database tables and columns: `snake_case`.
- React components: `PascalCase`.

## Environment and secrets

- `.env.example` files show the shape only. Never commit a real `.env`.
- Share secrets privately; rotate demo secrets before the final deployment.

## Tests

```bash
./deployment/scripts/run_tests.sh          # backend unit tests + ML contract tests
cd frontend && npm run build               # frontend type-check and build
```

Add or update tests with every feature: parsers, feature calculators, threshold logic,
explanation formatting, and every new API route.

## Ownership

| Area | Owner | Backup |
| --- | --- | --- |
| Product, architecture, integration | Team lead | DevOps |
| Frontend | Frontend engineer | UI/UX + QA |
| Backend and database | Backend engineer (Shreya) | ML engineer |
| AI/ML and data | ML engineer (Yash) | Backend engineer |
| UI/UX, QA, documentation | UI/UX + QA | Frontend engineer |
| DevOps, deployment, demo environment | DevOps (Arnav) | Team lead |

Rule: no critical knowledge lives with one person. Members 1 and 6 can both run the full
stack; members 3 and 4 both understand the inference contract; members 2 and 5 both know
the demo flow.
