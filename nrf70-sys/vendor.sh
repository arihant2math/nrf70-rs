#!/bin/sh
# Re-vendors the upstream C that nrf70-sys compiles: copies the pinned
# checkouts into vendor/, builds once with -MD, and keeps only the headers the
# compiler read, the sources build.rs names (patched ones compile from a copy
# in OUT_DIR), and the license and firmware files. Update the commits in
# vendor-manifest.toml to match the printed revisions.
#
# Usage: ./vendor.sh <nrf70-bm checkout> <hostap checkout>
set -eu

[ $# -eq 2 ] || { echo "usage: $0 <nrf70-bm> <hostap>" >&2; exit 2; }
bm=$(cd "$1" && pwd)
hostap=$(cd "$2" && pwd)
cd "$(dirname "$0")"
here=$(pwd)

for repo in "$bm" "$bm/nrf_wifi" "$bm/sdk-nrfxlib" "$hostap"; do
	echo "$(git -C "$repo" rev-parse HEAD) $repo"
done

fw=sdk-nrfxlib/nrf_wifi/bin/zephyr/default/nrf70.bin
keep="nrf70-bm/sdk-nrfxlib/LICENSE nrf70-bm/$fw hostap/COPYING hostap/README"

rm -rf vendor/nrf70-bm vendor/hostap
mkdir -p vendor/nrf70-bm/sdk-nrfxlib vendor/hostap
cp -R "$bm/nrf70_bm_lib" "$bm/nrf_wifi" vendor/nrf70-bm/
cp "$bm/sdk-nrfxlib/LICENSE" vendor/nrf70-bm/sdk-nrfxlib/
mkdir -p "vendor/nrf70-bm/$(dirname "$fw")"
cp "$bm/$fw" "vendor/nrf70-bm/$fw"
cp -R "$hostap/src" "$hostap/COPYING" "$hostap/README" vendor/hostap/
find vendor/nrf70-bm vendor/hostap -name .git -prune -exec rm -rf {} +

target=$(mktemp -d)
trap 'rm -rf "$target"' EXIT
CFLAGS_thumbv8m_main_none_eabihf=-MD cargo build -p nrf70-sys \
	--target thumbv8m.main-none-eabihf --target-dir "$target"

used=$(mktemp)
{
	find "$target" -path '*nrf70-sys*' -name '*.d' -exec cat {} +
	find "$target" -path '*nrf70-sys*' \( -name output -o -name stdout \) -exec cat {} + |
		sed -n 's/^cargo:rerun-if-changed=//p'
} | tr ' \\' '\n\n' | sed -n "s|^$here/vendor/||p" >"$used"
for f in $keep; do echo "$f"; done >>"$used"
sort -u -o "$used" "$used"

(cd vendor && find nrf70-bm hostap -type f | sort) | comm -23 - "$used" |
	(cd vendor && xargs rm -f)
find vendor/nrf70-bm vendor/hostap -type d -empty -delete
rm -f "$used"
du -sh vendor/nrf70-bm vendor/hostap
