#!/bin/sh
# Fetch the cross-repository contracts this Gateway tests from the Content repository, read-only.
#
# Content is the only home of every cross-repository contract (owner decision 2026-11-05): no other
# repository keeps a copy. This Gateway owns docs/contracts/domain-api-v1.json there and edits it in
# Content first; on every pull request of this repository the file is fetched from Content main into
# build/contracts/ (git-ignored) and DomainContractTest reads it from there.
#
# Credentials, in order: CONTENT_READ_TOKEN (CI: a fine-grained token with Contents: read on Content
# alone), then GH_TOKEN, then the developer's own `gh auth login`. The token is never printed and never
# appears on a command line.
#
# Settings (environment): CONTENT_REF (default main), CONTRACTS_DIR (default build/contracts, relative to
# the repository root). Exit status 0 only when every file is in place.
set -eu

REPOSITORY="lookahead99ms/lookahead-learning-content"
CONTRACTS_PATH="docs/contracts"
FILES="domain-api-v1.json"
REF="${CONTENT_REF:-main}"
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="${CONTRACTS_DIR:-build/contracts}"
case "$OUT" in /*) ;; *) OUT="$ROOT/$OUT" ;; esac

fail() {
    printf 'fetch-contracts: %s\n' "$1" >&2
    printf 'fetch-contracts: fix: %s\n' "$2" >&2
    exit 1
}

cleanup() { rm -f "${CONFIG:-}" "${PART:-}" "${ERRORS:-}"; }
trap cleanup EXIT INT TERM
CONFIG=""; PART=""; ERRORS=""

mkdir -p "$OUT"

for FILE in $FILES; do
    SOURCE="$REPOSITORY@$REF:$CONTRACTS_PATH/$FILE"
    TARGET="$OUT/$FILE"
    PART="$TARGET.part"
    ERRORS="$TARGET.err"
    rm -f "$PART" "$ERRORS"
    STATUS=""

    if [ -n "${CONTENT_READ_TOKEN:-}" ] || [ -n "${GH_TOKEN:-}" ]; then
        TOKEN="${CONTENT_READ_TOKEN:-${GH_TOKEN:-}}"
        # The token travels in a curl config file (mode 600), not in the process arguments.
        CONFIG=$(mktemp "${TMPDIR:-/tmp}/fetch-contracts.XXXXXX")
        chmod 600 "$CONFIG"
        printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" > "$CONFIG"
        unset TOKEN
        STATUS=$(curl --silent --show-error --location --config "$CONFIG" \
            --header "Accept: application/vnd.github.raw+json" \
            --header "X-GitHub-Api-Version: 2022-11-28" \
            --output "$PART" --write-out '%{http_code}' \
            "https://api.github.com/repos/$REPOSITORY/contents/$CONTRACTS_PATH/$FILE?ref=$REF" 2>"$ERRORS") || STATUS="000"
        rm -f "$CONFIG"; CONFIG=""
        HOW="the token in CONTENT_READ_TOKEN or GH_TOKEN"
    else
        command -v gh >/dev/null 2>&1 || fail "no CONTENT_READ_TOKEN or GH_TOKEN is set and the gh command is not installed; $SOURCE was not fetched." \
            "in CI set the CONTENT_READ_TOKEN secret (a fine-grained token with Contents: read on the Content repository); locally install gh and run 'gh auth login', or export GH_TOKEN."
        if gh api --header "Accept: application/vnd.github.raw+json" \
            "repos/$REPOSITORY/contents/$CONTRACTS_PATH/$FILE?ref=$REF" > "$PART" 2>"$ERRORS"; then
            STATUS="200"
        else
            STATUS=$(sed -n 's/.*HTTP \([0-9][0-9][0-9]\).*/\1/p' "$ERRORS" | head -n 1)
            [ -n "$STATUS" ] || STATUS="000"
        fi
        HOW="your own gh login"
    fi

    case "$STATUS" in
        200)
            if [ ! -s "$PART" ] || ! head -c 1 "$PART" | grep -q '{'; then
                fail "$SOURCE answered 200 but the body is not a JSON object." \
                    "check $CONTRACTS_PATH/$FILE on Content $REF; the file must be the contract itself."
            fi
            mv "$PART" "$TARGET"
            rm -f "$ERRORS"
            printf 'fetch-contracts: %s -> %s\n' "$SOURCE" "$TARGET"
            ;;
        401|403)
            fail "GitHub refused $SOURCE (HTTP $STATUS) with $HOW." \
                "in CI the CONTENT_READ_TOKEN secret must be a fine-grained token with Contents: read on the Content repository and must not have expired; locally run 'gh auth login' with an account that can read Content."
            ;;
        404)
            fail "$SOURCE was not found (HTTP 404) with $HOW." \
                "check that $CONTRACTS_PATH/$FILE exists on Content $REF (set CONTENT_REF for another branch); GitHub also answers 404 when the token cannot read the private Content repository, so check the token's repository access too."
            ;;
        *)
            DETAIL=$(sed -e 's/[Bb]earer [^ ]*/Bearer [redacted]/g' "$ERRORS" 2>/dev/null | head -n 3 | tr '\n' ' ')
            fail "could not fetch $SOURCE (HTTP ${STATUS:-000}). ${DETAIL:-no further detail}" \
                "check the network and https://api.github.com, then retry; the expected output is $TARGET."
            ;;
    esac
done
