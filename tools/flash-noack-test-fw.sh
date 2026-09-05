#!/usr/bin/env bash
#
# flash-noack-test-fw.sh — 编译并烧录「强制 sleep no-ack」的测试固件
#
# 为什么需要它：test-dual-auth.sh 在普通固件上跑通，只能说明「这次没撞上」。
# 原 bug 依赖 fp_power_off() 拿不到 PS_Sleep ack（BLE 忙时才高发），拿不到
# 才会走抬指 touch-reset 恢复，第 2 个 AUTH_REQUEST 才有窗口可抢。BLE 空闲
# 时 ack 基本都拿得到 → 恢复路径根本不执行 → 跑十遍全绿也证明不了修复。
#
# 这个脚本用 TEST_DEFS=-DFP_FORCE_SLEEP_NOACK 让 fp_power_off() 恒返回
# slept=false，于是**每一次抬指**都走 touch-reset 恢复，
# test-dual-auth.sh 的 T2 必然落进那个窗口 —— 变成必现的确定性测试。
#
# 构建模式用 debug（有日志 + 无睡眠），不是 release-debug：
# release-debug 的 HAL_SLEEP=TRUE 会让 MCU 在 BLE 事件之间不停睡/醒，
# SLEEP.c 唤醒后没重跑 SetSysClock，HSE/PLL 没稳时 UART3 就在发 →
# 波特率飘 → 日志乱码（同一个空格时而 0x38 时而 0x3C）。
# 台面测试插着 USB，不睡觉的功耗无所谓，换干净日志值得。
#
# 用法：
#   firmware/tools/flash-noack-test-fw.sh            # 烧测试固件
#   firmware/tools/flash-noack-test-fw.sh --restore  # 烧回正常 release 固件
#
# 烧完测试固件后：
#   firmware/tools/test-dual-auth.sh
# 期望：T1/T2/T3 全 PASS，且设备日志里每一轮都能看到
#   post-lift touch recovery (DETECT=0 slept=0)
#   Gate: FP busy (reset=1 sleep=0 enroll=0), defer to touch
# 修复前同样的固件会在 T2 就死掉，且按键救不回来。
#
# 测完务必 --restore，别把带 FP_FORCE_SLEEP_NOACK 的固件留在设备上。

set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
HW_VER="${HW_VER:-6}"

C_HI=$'\033[36m'; C_NG=$'\033[31m'; C_OK=$'\033[32m'; C_0=$'\033[0m'

MODE="test"
[ "${1:-}" = "--restore" ] && MODE="restore"
[ "${1:-}" = "--wide" ] && MODE="wide"
[ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] && { sed -n '2,30p' "$0"; exit 0; }

if [ -z "${TOOLCHAIN_PATH:-}" ]; then
  echo "${C_NG}TOOLCHAIN_PATH 没设${C_0}，先 export 到 RISC-V 工具链目录"
  exit 1
fi

# Makefile 的 CURRENT_FLAGS 里带了 TEST_DEFS，切换时会自动 rm build/*.o，
# 所以不用手工 clean —— 但 .build_flags 也因此成了可信的事后凭据。
FLAGS_FILE="$REPO/firmware/build/.build_flags"

if [ "$MODE" != "restore" ]; then
  if [ "$MODE" = "wide" ]; then
    DEFS="-DFP_FORCE_SLEEP_NOACK -DFP_TEST_TOUCH_RESET_HOLD_MS=4000"
    echo "${C_HI}▸ 编译 + 烧录测试固件 (VER=$HW_VER, debug/无睡眠, no-ack + 4s 宽窗口)${C_0}"
  else
    DEFS="-DFP_FORCE_SLEEP_NOACK"
    echo "${C_HI}▸ 编译 + 烧录测试固件 (VER=$HW_VER, debug/无睡眠, FP_FORCE_SLEEP_NOACK)${C_0}"
  fi
  TEST_DEFS="$DEFS" "$REPO/ota/upload-ota.sh" "VER=$HW_VER" debug

  if grep -q "TEST_DEFS=$DEFS" "$FLAGS_FILE" 2>/dev/null \
     && strings "$REPO/firmware/build/immurok_CH592F.bin" | grep -q "FP_FORCE_SLEEP_NOACK"; then
    echo "${C_OK}✓ 已烧录测试固件: $(cat "$FLAGS_FILE")${C_0}"
  else
    echo "${C_NG}✗ TEST_DEFS 没生效（build_flags: $(cat "$FLAGS_FILE" 2>/dev/null)）—— 别测${C_0}"
    exit 1
  fi

  cat <<EOF

${C_HI}接下来：${C_0}
  1) ${C_NG}用 USB 线接上设备${C_0}（没有 /dev/cu.usbmodem* 就没有设备日志，
     没有日志就无法确认第 2 个 AUTH_REQUEST 到底有没有撞进窗口 ——
     那样跑出来的全 PASS 只是「没撞上」，不是「修好了」）
  2) firmware/tools/test-dual-auth.sh --gap 1.5
     （--gap 1.5 让第 2 个申请等你抬完指再发，正好落进恢复窗口；
       gap=0 时它比抬指还早到，走的是修复前也安全的 WAIT_LIFT 分支）
  3) 设备日志里每轮必须出现这三行，缺一说明没测到点上:
       post-lift touch recovery (DETECT=? slept=0)
       Gate: FP busy (reset=1 sleep=0 enroll=0), defer to touch
       Touch reset: sleep no-ack, retry 1/2
  4) ${C_NG}测完一定要跑 flash-noack-test-fw.sh --restore${C_0}
EOF
else
  echo "${C_HI}▸ 编译 + 烧录正常固件 (VER=$HW_VER, release)${C_0}"
  "$REPO/ota/upload-ota.sh" "VER=$HW_VER" release

  if grep -q "TEST_DEFS=$" "$FLAGS_FILE" 2>/dev/null; then
    echo "${C_OK}✓ 已恢复正常固件: $(cat "$FLAGS_FILE")${C_0}"
  else
    echo "${C_NG}✗ build_flags 里 TEST_DEFS 非空: $(cat "$FLAGS_FILE" 2>/dev/null)${C_0}"
    exit 1
  fi
fi
