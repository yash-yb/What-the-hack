#!/usr/bin/env bash
# One-time GitHub repository setup: issue labels and branch protection for main and dev.
# Requires the GitHub CLI authenticated with admin rights on the repo:  gh auth login
# Usage: ./deployment/scripts/github_setup.sh [owner/repo]
set -euo pipefail
REPO="${1:-DurgeshLabs/What-the-hack}"

echo "== Labels on $REPO"
while IFS='|' read -r name color description; do
  gh label create "$name" --repo "$REPO" --color "$color" --description "$description" --force >/dev/null
  echo "  $name"
done <<'LABELS'
frontend|1d76db|Next.js dashboard, pages, components
backend|0e8a16|FastAPI, database, migrations
ml|5319e7|Datasets, features, models, inference
bug|d73a4a|Something is broken
urgent|b60205|Blocks the demo or another member
demo|fbca04|Demo flow, seed data, backup assets
docs|0075ca|Documentation and contracts
LABELS

protect() {
  local branch="$1" reviews="$2"
  echo "== Protecting $branch (required reviews: $reviews)"
  gh api -X PUT "repos/$REPO/branches/$branch/protection" \
    -H "Accept: application/vnd.github+json" \
    --input - <<JSON >/dev/null
{
  "required_status_checks": {"strict": true, "contexts": ["Backend unit tests", "ML contract tests", "Frontend build", "docker-compose validates"]},
  "enforce_admins": false,
  "required_pull_request_reviews": {"required_approving_review_count": $reviews, "dismiss_stale_reviews": true},
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
}
protect dev 1
protect main 1
echo "Done. Members must merge through pull requests from now on."
