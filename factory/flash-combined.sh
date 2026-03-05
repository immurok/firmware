#!/bin/bash
#
# 上传完整固件 (Bootloader + App)
#
# 适用于: 新设备首次烧录 或 完整重刷
# 注意: 会覆盖整个 Flash (0x0000-0x70000)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

HEX_FILE="build/immurok_OTA_V2_Combined.hex"

echo "==========================================="
echo "  上传完整固件 (Bootloader + App)"
echo "==========================================="
echo ""

# 检查固件文件
if [ ! -f "$HEX_FILE" ]; then
    echo "ERROR: 固件文件不存在: $HEX_FILE"
    echo "请先运行 ./factory/build-combined.sh 编译固件"
    exit 1
fi

echo "固件文件: $HEX_FILE"
echo ""
echo "Flash 布局:"
echo "  0x00000 - 0x04000: Bootloader (16KB)"
echo "  0x04000 - 0x3A000: App (216KB)"
echo "  0x3A000 - 0x70000: OTA Area (216KB)"
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
echo ""
echo "启动流程: Reset -> Bootloader (0x0) -> App (0x4000)"
