#!/usr/bin/env bash
# Create (or reuse) a Forgejo release for VERSION at HEAD and attach dist/*.
# Adapted from obs-irl-backstage. Re-runnable: skips assets already attached.
# Usage: scripts/forgejo-release.sh vX.Y.Z [prev-tag]
# Env (set by Forgejo Actions): FORGEJO_TOKEN, GITHUB_API_URL, GITHUB_REPOSITORY
set -euo pipefail

VERSION="${1:?usage: forgejo-release.sh vX.Y.Z [prev-tag]}"
PREV="${2:-}"
: "${FORGEJO_TOKEN:?FORGEJO_TOKEN is required}"
: "${GITHUB_API_URL:?GITHUB_API_URL is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
API="${GITHUB_API_URL%/}/repos/${GITHUB_REPOSITORY}"
AUTH="Authorization: token $FORGEJO_TOKEN"

shopt -s nullglob
ASSETS=(dist/*)
[[ ${#ASSETS[@]} -gt 0 ]] || { echo "ERROR: dist/ is empty; run make dist" >&2; exit 1; }

NOTES_FILE="$(mktemp)"
trap 'rm -f "$NOTES_FILE"' EXIT
{
  echo "## Changes"
  echo
  git log --no-merges --pretty='- %s' "${PREV:+$PREV..}HEAD"
} >"$NOTES_FILE"

# No -f: a 404 here is expected and maps to "" via `.id // empty`.
RELEASE_ID="$(curl -sS -H "$AUTH" "$API/releases/tags/$VERSION" | jq -r '.id // empty' || true)"
if [[ -z "$RELEASE_ID" ]]; then
  echo "Creating Forgejo release $VERSION on $GITHUB_REPOSITORY..."
  RELEASE_ID="$(
    jq -n --arg tag "$VERSION" --arg target "$(git rev-parse HEAD)" --rawfile body "$NOTES_FILE" \
      '{tag_name: $tag, name: $tag, body: $body, target_commitish: $target}' |
      curl -sSf -X POST "$API/releases" -H "$AUTH" -H 'Content-Type: application/json' --data-binary @- |
      jq -er '.id'
  )"
else
  echo "Release $VERSION already exists (id $RELEASE_ID); attaching assets to it."
fi

EXISTING="$(curl -sS -H "$AUTH" "$API/releases/$RELEASE_ID/assets" | jq -r '.[].name' || true)"
for f in "${ASSETS[@]}"; do
  name="$(basename "$f")"
  if grep -Fxq "$name" <<<"$EXISTING"; then
    echo "Skipping $name (already attached)"
    continue
  fi
  curl -sSf -X POST "$API/releases/$RELEASE_ID/assets?name=$name" -H "$AUTH" -F "attachment=@$f" >/dev/null
  echo "Attached $name"
done
