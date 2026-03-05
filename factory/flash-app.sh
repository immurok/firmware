#!/bin/bash
#
# 上传 App 固件到设备 (仅 App，不含 Bootloader)
#
# 适用于: 已有 Bootloader 的设备，只更新 App
# 注意: 会覆盖 0x4000-0x3A000 区域
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

HEX_FILE="build/immurok_CH592F.hex"

echo "==========================================="
echo "  上传 App 固件"
echo "==========================================="
echo ""

# 检查固件文件
if [ ! -f "$HEX_FILE" ]; then
    echo "ERROR: 固件文件不存在: $HEX_FILE"
    echo "请先运行 ./factory/build-app.sh 编译固件"
    exit 1
fi

echo "固件文件: $HEX_FILE"
echo "目标区域: 0x04000 - 0x3A000 (Image A)"
echo ""

# 检查烧录工具
if ! command -v wlink &> /dev/null; then
    echo "ERROR: wlink 工具未安装"
    echo "请安装: cargo install wlink"
    exit 1
fi

echo ">>> 正在烧录..."
echo ""

wlink --chip CH59X flash "$HEX_FILE"

echo ""
echo "==========================================="
echo "  烧录完成!"
echo "==========================================="
