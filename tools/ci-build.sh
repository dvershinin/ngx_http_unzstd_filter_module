#!/usr/bin/env bash

set -euo pipefail

FLAVOR="${1:-nginx}"
VERSION="${2:-1.30.4}"
MODE="${3:-dynamic}"
ROOT="${BUILD_ROOT:-$PWD/.build}"
MODULE_DIR="$PWD"

if [ "$FLAVOR" != "nginx" ]; then
    echo "unsupported flavor: $FLAVOR" >&2
    exit 2
fi
if [ "$MODE" != "dynamic" ] && [ "$MODE" != "asan" ]; then
    echo "unsupported build mode: $MODE" >&2
    exit 2
fi

archive="$ROOT/nginx-$VERSION.tar.gz"
source="$ROOT/nginx-$VERSION"
mkdir -p "$ROOT"
if [ ! -f "$archive" ]; then
    curl -fsSL "https://nginx.org/download/nginx-$VERSION.tar.gz" -o "$archive"
fi
rm -rf "$source"
tar -xzf "$archive" -C "$ROOT"

add_module="--add-dynamic-module=$MODULE_DIR"
cc_opt="-g3 -O0 -fno-omit-frame-pointer"
ld_opt=""
if [ "$MODE" = "asan" ]; then
    rm -rf /tmp/asan
    mkdir -p /tmp/asan
    export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:log_path=/tmp/asan/asan"
    export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1:log_path=/tmp/asan/ubsan"
    # NGINX core intentionally permits memcpy(NULL, NULL, 0) for empty
    # ngx_str_t values. GCC's nonnull-attribute UBSan check rejects that core
    # convention before a request reaches this module, so disable only that
    # sub-check. ASan and every other UBSan check remain fatal.
    sanitizer="-fsanitize=address,undefined -fno-sanitize=nonnull-attribute -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g3 -O1"
    add_module="--add-module=$MODULE_DIR"
    cc_opt="$sanitizer"
    ld_opt="$sanitizer"
fi

cd "$source"
./configure \
    --with-compat \
    --with-debug \
    --with-http_stub_status_module \
    --with-cc-opt="$cc_opt" \
    --with-ld-opt="$ld_opt" \
    "$add_module"
make -j"$(nproc)"

printf 'binary=%s\n' "$source/objs/nginx"
if [ "$MODE" = "dynamic" ]; then
    printf 'module=%s\n' "$source/objs/ngx_http_unzstd_filter_module.so"
fi
