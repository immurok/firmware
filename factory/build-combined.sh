#!/bin/bash
#
# 编译并合并 Bootloader + App 固件 (OTA V2)
#
# 用法:
#   ./build-combined.sh           # Debug 版本
#   ./build-combined.sh --debug   # Debug 版本
#   ./build-combined.sh --release # Release 版本
#
# 输出: build/immurok_OTA_V2_Combined.hex
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FIRMWARE_DIR="$SCRIPT_DIR/.."
IAP_DIR="$FIRMWARE_DIR/../ota/iap"

cd "$FIRMWARE_DIR"
BUILD_DIR="build"
TOOLCHAIN_SIZE="${TOOLCHAIN_PATH:-/opt/riscv-wch-gcc}/bin/riscv-wch-elf-size"

# 区域大小定义
BOOTLOADER_SIZE=$((16 * 1024))    # 16KB
IMAGE_A_SIZE=$((216 * 1024))      # 216KB

# 解析参数
BUILD_MODE="debug"
APP_MAKE_TARGET="ota-v2"
IAP_DEBUG_FLAG="DEBUG=1"

if [ "$1" == "--release" ]; then
    BUILD_MODE="release"
    APP_MAKE_TARGET="ota-v2-release"
    IAP_DEBUG_FLAG=""
elif [ "$1" == "--debug" ] || [ -z "$1" ]; then
    BUILD_MODE="debug"
    APP_MAKE_TARGET="ota-v2"
    IAP_DEBUG_FLAG="DEBUG=1"
else
    echo "用法: $0 [--debug|--release]"
    exit 1
fi

echo "==========================================="
echo "  编译 immurok OTA V2 完整固件"
echo "  (Bootloader + App)"
echo "  模式: $BUILD_MODE"
echo "==========================================="
echo ""

# 1. 编译 IAP Bootloader
echo ">>> 编译 IAP Bootloader..."
cd "$IAP_DIR"
make clean >/dev/null 2>&1
make V2=1 $IAP_DEBUG_FLAG 2>&1 | grep -E "(CC|AS|LD|text|data|bss)" | tail -10
IAP_HEX="$IAP_DIR/build/immurok_IAP_V2.hex"

if [ ! -f "$IAP_HEX" ]; then
    echo "ERROR: IAP 编译失败"
    exit 1
fi

# 获取 IAP 大小
IAP_TEXT=$("$TOOLCHAIN_SIZE" build/immurok_IAP_V2.elf | tail -1 | awk '{print $1}')
IAP_DATA=$("$TOOLCHAIN_SIZE" build/immurok_IAP_V2.elf | tail -1 | awk '{print $2}')
IAP_TOTAL=$((IAP_TEXT + IAP_DATA))

# 2. 编译 App
echo ""
echo ">>> 编译 App..."
cd "$FIRMWARE_DIR"
make clean >/dev/null 2>&1
make $APP_MAKE_TARGET 2>&1 | grep -E "(CC|AS|LD|text|data|bss)" | tail -10
APP_HEX="$BUILD_DIR/immurok_CH592F.hex"

if [ ! -f "$APP_HEX" ]; then
    echo "ERROR: App 编译失败"
    exit 1
fi

# 获取 App 大小
APP_TEXT=$("$TOOLCHAIN_SIZE" build/immurok_CH592F.elf | tail -1 | awk '{print $1}')
APP_DATA=$("$TOOLCHAIN_SIZE" build/immurok_CH592F.elf | tail -1 | awk '{print $2}')
APP_TOTAL=$((APP_TEXT + APP_DATA))

# 3. 合并固件
echo ""
echo ">>> 合并固件..."
COMBINED_HEX="$BUILD_DIR/immurok_OTA_V2_Combined.hex"
sed '$ d' "$IAP_HEX" > "$COMBINED_HEX"
cat "$APP_HEX" >> "$COMBINED_HEX"

# 4. 显示统计
IAP_PERCENT=$((IAP_TOTAL * 100 / BOOTLOADER_SIZE))
APP_PERCENT=$((APP_TOTAL * 100 / IMAGE_A_SIZE))

echo ""
echo "==========================================="
echo "  固件大小统计 ($BUILD_MODE)"
echo "==========================================="
echo ""
echo "  Bootloader (IAP):"
printf "    代码大小:      %6d bytes (%d KB)\n" $IAP_TOTAL $((IAP_TOTAL / 1024))
printf "    区域大小:      %6d bytes (%d KB)\n" $BOOTLOADER_SIZE $((BOOTLOADER_SIZE / 1024))
printf "    占用比例:      %6d %%\n" $IAP_PERCENT

# IAP 进度条
BAR_WIDTH=40
FILLED=$((IAP_PERCENT * BAR_WIDTH / 100))
printf "    ["
for ((i=0; i<BAR_WIDTH; i++)); do
    if [ $i -lt $FILLED ]; then
        printf "#"
    else
        printf "-"
    fi
done
printf "] %d%%\n" $IAP_PERCENT

echo ""
echo "  App (Image A):"
printf "    代码大小:      %6d bytes (%d KB)\n" $APP_TOTAL $((APP_TOTAL / 1024))
printf "    区域大小:      %6d bytes (%d KB)\n" $IMAGE_A_SIZE $((IMAGE_A_SIZE / 1024))
printf "    占用比例:      %6d %%\n" $APP_PERCENT

# App 进度条
FILLED=$((APP_PERCENT * BAR_WIDTH / 100))
printf "    ["
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
echo "  Flash 布局"
echo "==========================================="
echo ""
echo "  0x00000 - 0x04000: Bootloader (16KB)"
echo "  0x04000 - 0x3A000: App (216KB)"
echo "  0x3A000 - 0x70000: OTA Area (216KB)"
echo ""
echo "==========================================="
echo "  输出文件: $COMBINED_HEX"
echo "  编译模式: $BUILD_MODE"
echo "==========================================="
