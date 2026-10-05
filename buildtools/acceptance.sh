#!/usr/bin/env bash
# Run by Sokar's machine tool on a rented machine, as an unprivileged user, after it installed Sokar
# and this repository's package from a candidate directory. Shell, because it runs on a
# machine that has nothing of this repository but the package: it checks what an operator would.
#
# Exit 0 only when the installed package is registered with the package manager, its binary is where
# Sokar looks for it, and it works without any Java on the PATH.
set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
    echo "run this as the unprivileged user, not as root" >&2
    exit 2
fi

installed() {
    if command -v dpkg-query >/dev/null; then
        dpkg-query -W -f='${db:Status-Abbrev}' "$1" 2>/dev/null | grep -q '^ii'
    else
        rpm -q "$1" >/dev/null 2>&1
    fi
}

FILTER=/usr/libexec/sokar/sokar-message-sluice-filter
checked=0
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if installed sokar-message-sluice-filter; then
    test -x "$FILTER"
    M="$work/mail"
    mkdir -p "$M"/{incoming,sent} "$M"/filter/{accepted,feedback}
    mkdir -m 700 "$M"/filter/{rejected,error}
    printf '%s\n' '{"messageId":"a-1","role":"ROLE_AGENT","parts":[{"text":"The build is green again."}]}' \
        > "$M/incoming/clean.json"
    printf '%s\n' '{"messageId":"a-2","role":"ROLE_AGENT","parts":[{"text":"Here: UEsDBBQAAAAIAGx0Mlt3b3JkL2RvY3VtZW50LnhtbKxVS27bMBC9C8E7RVJ2m9qw ok."}]}' \
        > "$M/incoming/payload.json"
    printf '%s\n' '{"messageId":"a-3","role":"ROLE_AGENT","parts":[{"raw":"UEsDBBQAAAAI"}]}' \
        > "$M/incoming/raw.json"
    set +e
    env -i PATH=/usr/bin:/bin "$FILTER" --mail "$M" --blocking --stabilityDelayMillis 0
    code=$?
    set -e
    test "$code" -eq 1
    test -f "$M/filter/accepted/clean.json"
    test -f "$M/filter/rejected/payload.json"
    test -f "$M/filter/rejected/raw.json"
    test "$(ls "$M/filter/feedback" | wc -l)" -eq 3
    echo "filter: installed, and refused what it must"
    checked=$((checked + 1))
fi

if [ "$checked" -eq 0 ]; then
    echo "the filter's package is not installed" >&2
    exit 1
fi
