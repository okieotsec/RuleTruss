#!/bin/sh
# Install the privacy check as a git pre-push hook in one repository.
#
#   tools/install_privacy_hook.sh
#
# The hook runs the check on the commits about to be pushed and blocks the push
# if anything is found. "git push --no-verify" skips it, so the same check also
# runs again in CI as a backstop.
set -eu

repo="${1:-.}"
here="$(cd "$(dirname "$0")" && pwd)"
hooks_dir="$(git -C "$repo" rev-parse --path-format=absolute --git-path hooks)"
hook="$hooks_dir/pre-push"

if [ -e "$hook" ]; then
    echo "A pre-push hook already exists at the hooks path; not overwriting it." >&2
    echo "Remove or merge it by hand, then run this again." >&2
    exit 1
fi

mkdir -p "$hooks_dir"
cat > "$hook" <<EOF
#!/bin/sh
# Installed by tools/install_privacy_hook.sh
exec python3 "$here/privacy_check.py" --pre-push --show-names "\$@"
EOF
chmod +x "$hook"
echo "Installed pre-push privacy check."
