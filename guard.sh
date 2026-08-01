#!/usr/bin/env bash
# guard.sh — fixture/scorer integrity guard (CHARTER.md rules 1 & 7).
#
#   freeze : SHA-256 every file under fixtures/ plus scorer.py -> .guard-hashes
#   check  : recompute and compare; "INTEGRITY OK" (exit 0) or
#            "TAMPERED: <paths>" (exit 1)
#   list   : print protected paths
#
# Content is LF-normalized (CR stripped) before hashing so Windows CRLF
# checkouts cannot cause phantom TAMPERED reports. Runs under Git Bash.

set -u
cd "$(dirname "$0")"
HASH_FILE=".guard-hashes"

protected_paths() {
    {
        find fixtures -type f ! -path "*node_modules*" -print
        echo "scorer.py"
    } | sed 's|\\|/|g; s|^\./||' | LC_ALL=C sort
}

hash_file() {
    # LF-normalize, then SHA-256.
    tr -d '\r' < "$1" | sha256sum | awk '{print $1}'
}

cmd="${1:-}"
case "$cmd" in
    list)
        protected_paths
        ;;

    freeze)
        tmp="$HASH_FILE.tmp"
        : > "$tmp"
        while IFS= read -r f; do
            printf '%s  %s\n' "$(hash_file "$f")" "$f" >> "$tmp"
        done < <(protected_paths)
        mv "$tmp" "$HASH_FILE"
        echo "FROZEN: $(wc -l < "$HASH_FILE" | tr -d ' ') files hashed into $HASH_FILE"
        ;;

    check)
        if [ ! -f "$HASH_FILE" ]; then
            echo "NO BASELINE: $HASH_FILE does not exist. The human runs './guard.sh freeze' to create it."
            exit 1
        fi
        declare -A baseline
        while IFS= read -r line; do
            h="${line%%  *}"
            f="${line#*  }"
            baseline["$f"]="$h"
        done < "$HASH_FILE"

        tampered=()
        declare -A seen
        while IFS= read -r f; do
            seen["$f"]=1
            if [ -z "${baseline[$f]:-}" ]; then
                tampered+=("$f (ADDED: not in baseline)")
            elif [ "$(hash_file "$f")" != "${baseline[$f]}" ]; then
                tampered+=("$f (MODIFIED)")
            fi
        done < <(protected_paths)

        for f in "${!baseline[@]}"; do
            if [ -z "${seen[$f]:-}" ]; then
                tampered+=("$f (DELETED)")
            fi
        done

        if [ "${#tampered[@]}" -eq 0 ]; then
            echo "INTEGRITY OK"
            exit 0
        else
            printf 'TAMPERED:'
            printf ' %s' "${tampered[@]}"
            printf '\n'
            exit 1
        fi
        ;;

    *)
        echo "usage: $0 {freeze|check|list}" >&2
        exit 2
        ;;
esac
