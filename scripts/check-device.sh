#!/bin/sh
# 检查设备是否在本项目的适用范围内
#
# 用法:
#   ./scripts/check-device.sh [serial]

S="${1:-}"
ADB="adb ${S:+-s $S}"

pass() { printf '  \033[32m[ OK ]\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m[WARN]\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m[FAIL]\033[0m %s\n' "$1"; }

echo "=== 设备检查 ==="

if ! $ADB shell true 2>/dev/null; then
    fail "adb 连不上设备"
    exit 1
fi

DEVICE=$($ADB shell getprop ro.product.device 2>/dev/null | tr -d '\r')
MODEL=$($ADB shell getprop ro.product.model  2>/dev/null | tr -d '\r')
BUILD=$($ADB shell getprop ro.build.display.id 2>/dev/null | tr -d '\r')
KERNEL=$($ADB shell uname -r 2>/dev/null | tr -d '\r')
SELINUX=$($ADB shell getenforce 2>/dev/null | tr -d '\r')
VBSTATE=$($ADB shell getprop ro.boot.verifiedbootstate 2>/dev/null | tr -d '\r')
UID_=$($ADB shell id -u 2>/dev/null | tr -d '\r')

echo "  device   : $DEVICE"
echo "  model    : $MODEL"
echo "  build    : $BUILD"
echo "  kernel   : $KERNEL"
echo "  selinux  : $SELINUX"
echo "  vbstate  : $VBSTATE"
echo

echo "=== 判定 ==="

[ "$DEVICE" = "flare" ] && pass "机型代号 flare" || warn "机型代号不是 flare（$DEVICE）"

WANT="6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k"
if [ "$KERNEL" = "$WANT" ]; then
    pass "内核串精确匹配"
else
    fail "内核串不匹配"
    echo "        期望: $WANT"
    echo "        实际: $KERNEL"
    echo "        → 需要用目标内核的 vmlinux 重新生成 profile（见 docs/11-reproduce.md 第 6 节）"
fi

[ "$VBSTATE" = "green" ] && pass "bootloader 已锁（正常，本项目不需要解锁）" \
                         || warn "verifiedbootstate=$VBSTATE（不是标准锁定状态）"

[ "$UID_" = "2000" ] && pass "起始权限 uid=2000 (shell)" \
                     || warn "起始权限是 uid=$UID_（不是标准的 2000）"

# 关键能力检查
echo
echo "=== tracefs 可达性 ==="

if $ADB shell 'head -c 1 /sys/kernel/tracing/tracing_on' >/dev/null 2>&1; then
    pass "tracing_on 可读"
else
    fail "tracing_on 不可读 → 后续全部无法进行"
fi

if $ADB shell 'cat /sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw' >/dev/null 2>&1; then
    pass "trace_pipe_raw 可读（需要 readtracefs 组）"
else
    warn "trace_pipe_raw 读不到 → 检查 shell 是否在 3012(readtracefs) 组"
fi

if $ADB shell 'echo -n "" > /sys/kernel/tracing/events/kmem/kmem_cache_alloc/enable' >/dev/null 2>&1; then
    pass "events/*/enable 可写"
else
    warn "events/*/enable 写不了 → 可能需要先 Permissive"
fi

echo
echo "=== 组权限 ==="
$ADB shell id | tr -d '\r' | tr ',' '\n' | grep -E 'readtracefs|uhid' | sed 's/^/  /'

echo
echo "=== 结论 ==="
if [ "$KERNEL" = "$WANT" ]; then
    echo "  内核匹配 → 可以直接用 artifacts/ 里的二进制"
    echo "  下一步: adb push artifacts/shark-k66118-fixed /data/local/tmp/shark66118"
    echo "          adb shell '/data/local/tmp/shark66118 probe'"
else
    echo "  内核不匹配 → 需要重新生成 profile"
    echo "  参考: docs/11-reproduce.md 第 6 节"
fi
