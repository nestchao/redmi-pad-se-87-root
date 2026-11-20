#!/bin/sh
# 编译本仓库里的所有诊断工具
#
# 需要 Android NDK。设置 ANDROID_NDK 环境变量指向 NDK 根目录：
#   export ANDROID_NDK=/path/to/android-ndk-r27c
#
# 用法：
#   ./scripts/build.sh            # 编译全部
#   ./scripts/build.sh pwn_min    # 只编译某一个

set -e

NDK="${ANDROID_NDK:-$HOME/Android/Sdk/ndk/27.2.12479018}"
CC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang"
[ -x "$CC" ] || CC="$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android34-clang.cmd"
[ -x "$CC" ] || { echo "找不到 clang，请设置 ANDROID_NDK"; exit 1; }

OUT=build
mkdir -p "$OUT"

build_one() {
    src="$1"
    name=$(basename "$src" .c)
    printf '  %-18s ' "$name"
    "$CC" -O2 -static -D_GNU_SOURCE -o "$OUT/$name" "$src" 2>"$OUT/$name.err" \
        && echo OK || { echo FAIL; cat "$OUT/$name.err" | head -5; }
}

if [ $# -gt 0 ]; then
    for f in "$@"; do build_one "tools/$f.c"; done
else
    echo "编译 tools/ 下所有工具:"
    for src in tools/*.c; do
        [ -f "$src" ] && build_one "$src"
    done
fi

echo
echo "产物在 $OUT/"
for f in "$OUT"/*; do
    case "$f" in
        *.err) continue ;;
    esac
    [ -f "$f" ] || continue
    printf '  %-20s %s bytes\n' "$(basename "$f")" "$(wc -c < "$f" | tr -d ' ')"
done
