#!/usr/bin/env bash
# Maintain the per-branch benchmark pages in a gh-pages checkout.
#
# Usage: branch_pages.sh index <pages-dir> <site-root-url>
#        branch_pages.sh prune <pages-dir> [branch ...]
#
# index  Rewrite branches/index.html, linking every page under branches/.
# prune  Delete every page under branches/ that belongs to none of the given
#        branches, i.e. to a branch that no longer exists: its own page,
#        branches/<slug>/, and those of runs by hand against other baselines,
#        branches/<slug>-vs-<baseline>/. Prints what it deletes.
#
# <slug> is how bench-branch.yml names a branch's directory; see slug below.
set -euo pipefail

# A branch name flattened into one path segment. Must match bench-branch.yml.
slug() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed 's|[^a-z0-9._-]|-|g'
}

index() {
    local pages=$1 root=$2
    {
        echo '<!DOCTYPE html>'
        echo '<html lang="en"><head><meta charset="utf-8">'
        echo '<meta name="viewport" content="width=device-width, initial-scale=1">'
        echo '<link rel="stylesheet" href="../style.css">'
        echo '<link rel="icon" type="image/x-icon" href="../favicon.svg">'
        echo '<title>BorrowSanitizer Benchmarks: branches</title></head>'
        echo '<body><header id="header"><h1 class="dashboard-title">Benchmarks by branch</h1></header>'
        echo "<main id=\"main\"><ul><li><a href=\"${root}\">main (history)</a></li>"
        for d in "$pages"/branches/*/; do
            [ -f "${d}data.json" ] || continue
            n=$(basename "$d")
            echo "<li><a href=\"${n}/\">${n}</a></li>"
        done
        echo '</ul></main></body></html>'
    } > "$pages/branches/index.html"
}

prune() {
    local pages=$1; shift
    local slugs=() b d n s keep
    for b in "$@"; do slugs+=("$(slug "$b")"); done
    for d in "$pages"/branches/*/; do
        [ -d "$d" ] || continue
        n=$(basename "$d")
        keep=false
        for s in "${slugs[@]}"; do
            if [ "$n" = "$s" ] || [[ "$n" == "$s"-vs-* ]]; then keep=true; break; fi
        done
        if [ "$keep" = false ]; then
            echo "deleting branches/$n"
            rm -rf "$d"
        fi
    done
}

case "${1:-}" in
    index) shift; index "$@" ;;
    prune) shift; prune "$@" ;;
    slug) shift; slug "$1"; echo ;;
    *) echo "usage: $0 {index <pages-dir> <root-url> | prune <pages-dir> [branch ...] | slug <branch>}" >&2; exit 2 ;;
esac
