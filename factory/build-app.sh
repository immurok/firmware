#!/bin/bash
#
# 编译 App 固件 (OTA V2 模式)
#
# 用法:
#   ./build-app.sh           # Debug 版本
#   ./build-app.sh --debug   # Debug 版本
#   ./build-app.sh --release # Release 版本
#
# 输出: build/immurok_CH592F.hex
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

TOOLCHAIN_SIZE="${TOOLCHAIN_PATH:-/opt/riscv-wch-gcc}/bin/riscv-wch-elf-size"

# 区域大小定义
IMAGE_A_SIZE=$((216 * 1024))      # 216KB

# 解析参数
BUILD_MODE="debug"
MAKE_TARGET="ota-v2"

if [ "$1" == "--release" ]; then
    BUILD_MODE="release"
    MAKE_TARGET="ota-v2-release"
elif [ "$1" == "--debug" ] || [ -z "$1" ]; then
    BUILD_MODE="debug"
    MAKE_TARGET="ota-v2"
else
    echo "用法: $0 [--debug|--release]"
    exit 1
fi

echo "==========================================="
echo "  编译 immurok App 固件 (OTA V2)"
echo "  模式: $BUILD_MODE"
echo "==========================================="
echo ""

# 编译 App
make clean >/dev/null 2>&1
make $MAKE_TARGET 2>&1 | grep -v "^make\[" | tail -20

# 获取编译后的大小
if [ -f "build/immurok_CH592F.elf" ]; then
    APP_TEXT=$("$TOOLCHAIN_SIZE" build/immurok_CH592F.elf | tail -1 | awk '{print $1}')
    APP_DATA=$("$TOOLCHAIN_SIZE" build/immurok_CH592F.elf | tail -1 | awk '{print $2}')
    APP_TOTAL=$((APP_TEXT + APP_DATA))
    APP_PERCENT=$((APP_TOTAL * 100 / IMAGE_A_SIZE))

    echo ""
    echo "==========================================="
    echo "  App 固件大小统计 ($BUILD_MODE)"
    echo "==========================================="
    echo ""
    printf "  App 代码大小:    %6d bytes (%d KB)\n" $APP_TOTAL $((APP_TOTAL / 1024))
    printf "  Image A 区域:    %6d bytes (%d KB)\n" $IMAGE_A_SIZE $((IMAGE_A_SIZE / 1024))
    printf "  占用比例:        %6d %%\n" $APP_PERCENT
    echo ""

    # 进度条
    BAR_WIDTH=40
    FILLED=$((APP_PERCENT * BAR_WIDTH / 100))
    printf "  ["
    for ((i=0; i<BAR_WIDTH; i++)); do
        if [ $i -lt $FILLED ]; then
            printf "#"
        else
            printf "-"
        fi
    done
    printf "] %d%%\n" $APP_PERCENT
    echo ""
    echo "==========================================="
    echo "  输出文件: build/immurok_CH592F.hex"
    echo "  编译模式: $BUILD_MODE"
    echo "==========================================="
else
    echo "ERROR: 编译失败"
    exit 1
fi
