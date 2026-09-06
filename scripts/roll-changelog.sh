#!/usr/bin/env sh
#
# Promote CHANGELOG.md's [Unreleased] section into a published version
# section, drop the version it replaces, and open a fresh empty [Unreleased].
#
# CHANGELOG.md deliberately holds only two sections — [Unreleased] and the
# most recent release — so it stays readable instead of growing without
# bound. Older entries remain available in their git tags and GitHub
# releases. Run via `make tag VERSION=vX.Y.Z`, which commits the result and
# tags it, so the tagged commit is the one the release workflow reads its
# notes from.
#
# POSIX sh + awk on purpose: this repo has no Node, Python or other runtime
# in its build path, and a release step is the last place to add one.

set -eu

VERSION="${1:?usage: roll-changelog.sh vX.Y.Z}"
FILE="${2:-CHANGELOG.md}"

case "$VERSION" in
	v*) ;;
	*) echo "roll-changelog: VERSION must start with 'v' (got '$VERSION')" >&2; exit 1 ;;
esac

ver="${VERSION#v}"
today="$(date -u +%Y-%m-%d)"

# Everything above [Unreleased] is the preamble, reused verbatim.
header="$(awk '/^## \[Unreleased\]/ { exit } { print }' "$FILE")"

# The [Unreleased] body: what this release is actually made of.
body="$(awk '
	/^## \[Unreleased\]/ { grab = 1; next }
	grab && /^## \[/     { exit }
	grab && /^\[[^]]+\]: / { exit }
	grab                 { print }
' "$FILE")"

if [ -z "$(printf '%s' "$body" | tr -d '[:space:]')" ]; then
	echo "roll-changelog: [Unreleased] in $FILE is empty — nothing to release." >&2
	exit 1
fi

# The version being replaced, so the new compare link spans the right range.
prev="$(awk -F'[][]' '/^## \[/ && $2 != "Unreleased" { print $2; exit }' "$FILE")"
if [ -z "$prev" ]; then
	echo "roll-changelog: no published version section found in $FILE" >&2
	exit 1
fi

# Derive the repo URL from the existing link rather than hardcoding it, so a
# move or rename does not silently produce dead compare links.
repo="$(awk -F': ' '/^\[Unreleased\]: / { print $2; exit }' "$FILE" | sed 's#/compare/.*##')"
if [ -z "$repo" ]; then
	echo "roll-changelog: could not derive the repository URL from $FILE" >&2
	exit 1
fi

tmp="$FILE.tmp.$$"
trap 'rm -f "$tmp"' EXIT

{
	printf '%s\n\n' "$header"
	printf '## [Unreleased]\n\n'
	printf '## [%s] - %s\n\n' "$ver" "$today"
	# Command substitution already ate the body's trailing newlines, so only
	# the blank line under the old heading needs dropping.
	printf '%s\n' "$body" | awk 'NF { seen = 1 } seen'
	printf '\n'
	printf '[Unreleased]: %s/compare/%s...main\n' "$repo" "$VERSION"
	printf '[%s]: %s/compare/v%s...%s\n' "$ver" "$repo" "$prev" "$VERSION"
} > "$tmp"

mv "$tmp" "$FILE"
trap - EXIT
echo "==> $FILE: [Unreleased] promoted to [$ver] (replacing [$prev])"
