#!/usr/bin/env bash
set -euo pipefail
recipe="$RUNNER_TEMP/dns-recipe"
source_dir="$RUNNER_TEMP/dns-fork"
mkdir "$recipe" "$source_dir"
curl -fsSL --retry 3 https://codeload.github.com/brofranks/tailscale/tar.gz/18ca94e8f08346bda1a694b2ac71ffd29907f7ec |
    tar -xz --strip-components=1 -C "$recipe"
read -r _ upstream < "$recipe/upstream"
curl -fsSL --retry 3 "https://codeload.github.com/tailscale/tailscale/tar.gz/$upstream" |
    tar -xz --strip-components=1 -C "$source_dir"
while read -r patch; do
    (cd "$source_dir" && git apply --whitespace=error "$recipe/patches/$patch")
done < "$recipe/patches/series"
go mod edit -replace="tailscale.com=$source_dir"
