#!/usr/bin/env bash

set -euo pipefail

NGINX_VERSION="${NGINX_VERSION:-1.30.4}"
ASAN="${ASAN:-0}"
MODE=dynamic
if [ "$ASAN" = "1" ]; then
    MODE=asan
    rm -rf /tmp/asan
    mkdir -p /tmp/asan
    export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:log_path=/tmp/asan/asan"
    export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1:log_path=/tmp/asan/ubsan"
fi

bash tools/ci-build.sh nginx "$NGINX_VERSION" "$MODE"

build="/work/.build/nginx-$NGINX_VERSION/objs"
export TEST_NGINX_BINARY="$build/nginx"
export TEST_NGINX_VERBOSE=1

globals=""
if [ "$(id -u)" = "0" ]; then
    globals="user root;\n"
fi
if [ "$MODE" = "dynamic" ]; then
    globals="${globals}load_module $build/ngx_http_unzstd_filter_module.so;\n"
fi
TEST_NGINX_GLOBALS="$(printf '%b' "$globals")"
export TEST_NGINX_GLOBALS

if [ "$#" -eq 0 ]; then
    set -- t/unzstd.t
fi

if [ "$ASAN" = "1" ]; then
    set +e
    prove -v "$@"
    rc=$?
    set -e
    if grep -q "AddressSanitizer\|UndefinedBehaviorSanitizer\|runtime error:" \
        /tmp/asan/* 2>/dev/null; then
        echo "sanitizer report detected" >&2
        grep -h -m 12 -E \
          "AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:" \
          /tmp/asan/* >&2
        exit 1
    fi
    exit "$rc"
fi

exec prove -v "$@"
