#!/usr/bin/env bash
#
# test-dual-auth.sh — 连发两个授权申请后指纹传感器是否还活着
#
# 回归目标（固件 1.7.7）：fp_gate_enter() 复用「已上电」模块时不看忙标志，
# 第 2 个 AUTH_REQUEST 会抢跑一次搜索，GET_IMAGE 撞死 touch-reset 的
# CMD_SLEEP → R599S 没进 wake-on-touch standby → 触摸永久失效，且按按键
# 也救不回来。详见 memory/keng_gate_enter_reuse_busy_fp.md。
#
# 判据：sudo 的 PAM 栈里 pam_immurok.so 是 `auth sufficient`。
#   - 指纹通过  → sudo 直接成功（exit 0）
#   - 指纹没通过 → 落到 pam_opendirectory 要密码，stdin 是 /dev/null → 失败
# 所以「sudo 成功与否」就是「这一轮指纹有没有工作」的干净布尔值。
#
# 用法：
#   firmware/tools/test-dual-auth.sh            # 默认顺序模式
#   firmware/tools/test-dual-auth.sh --parallel # 两个申请真并发（测 BUSY 路径）
#   firmware/tools/test-dual-auth.sh --gap 0.3  # T1 返回后等 0.3s 再发 T2
#
# 注意：全程不要用 imk 包装本脚本 —— 那会引入 pre-authorization，
#       把「这次到底有没有真的按指纹」这件事糊掉。

set -uo pipefail

GAP=0
PARALLEL=0
TIMEOUT=40

while [ $# -gt 0 ]; do
  case "$1" in
    --parallel) PARALLEL=1; shift ;;
    --gap)      GAP="$2"; shift 2 ;;
    --timeout)  TIMEOUT="$2"; shift 2 ;;
    -h|--help)  sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "未知参数: $1"; exit 2 ;;
  esac
done

C_OK=$'\033[32m'; C_NG=$'\033[31m'; C_HI=$'\033[36m'; C_DIM=$'\033[2m'; C_0=$'\033[0m'
REPORT="${TMPDIR:-/tmp}/immurok-dual-auth-$(date +%Y%m%d-%H%M%S).log"
SERIAL_LOG=""
SERIAL_PID=""

log()  { printf '%s\n' "$*" | tee -a "$REPORT"; }
step() { log ""; log "${C_HI}▸ $*${C_0}"; }

# macOS 没有 timeout(1)，自己搭一个看门狗。
run_timeout() {
  local secs="$1"; shift
  "$@" & local pid=$!
  ( sleep "$secs"; kill -TERM "$pid" 2>/dev/null ) & local wd=$!
  wait "$pid"; local rc=$?
  kill "$wd" 2>/dev/null; wait "$wd" 2>/dev/null
  return $rc
}

cleanup() {
  [ -n "$SERIAL_PID" ] && kill "$SERIAL_PID" 2>/dev/null
}
trap cleanup EXIT

# ── 前置检查 ────────────────────────────────────────────────────────────
step "前置检查"

if ! pgrep -x immurok >/dev/null; then
  log "${C_NG}✗ immurok.app 没在运行${C_0}，先启动 /Applications/immurok.app"
  exit 1
fi
log "  ✓ immurok.app 在运行"

if ! grep -q "pam_immurok.so" /etc/pam.d/sudo_local 2>/dev/null; then
  log "${C_NG}✗ /etc/pam.d/sudo_local 里没有 pam_immurok.so${C_0}，本测试的判据不成立"
  exit 1
fi
log "  ✓ sudo_local 已挂 pam_immurok.so"

imk pam-key status >/dev/null 2>&1
case $? in
  0) log "  ✓ imk pam-key: 已安装且匹配" ;;
  4) log "  ${C_NG}✗ imk pam-key: app 不可达${C_0}" ; exit 1 ;;
  *) log "  ${C_DIM}· imk pam-key: 未安装/不匹配（不影响本测试）${C_0}" ;;
esac

# 设备 release-debug 日志（USB CDC）。插着就顺手抓，没插也不影响判定。
PORT="$(ls /dev/cu.usbmodem* 2>/dev/null | head -1)"
if [ -n "$PORT" ]; then
  SERIAL_LOG="${REPORT%.log}-device.log"
  "$(dirname "$0")/read-device-log.py" "$PORT" "$SERIAL_LOG" >/dev/null 2>&1 &
  SERIAL_PID=$!
  log "  ✓ 设备日志抓取中: $PORT → $SERIAL_LOG"
else
  log "  ${C_DIM}· 没找到 /dev/cu.usbmodem*，跳过设备日志（不影响判定）${C_0}"
  log "  ${C_DIM}  注意 release 固件本来就没有 PRINT 日志；要看设备日志需${C_0}"
  log "  ${C_DIM}  ota/upload-ota.sh release-debug 重刷 + USB 线接设备。${C_0}"
fi

log ""
log "报告: $REPORT"

# ── 一轮 = 一次 sudo = 一次触摸 ─────────────────────────────────────────
# 返回 0 表示这一轮指纹工作正常。
touch_round() {
  local label="$1"
  local t0 t1
  sudo -k 2>/dev/null
  log ""
  log "${C_HI}  ┌─ $label ─ 请触摸指纹传感器${C_0}"
  t0=$(python3 -c 'import time;print(time.time())')
  run_timeout "$TIMEOUT" sudo -S -p '' true </dev/null >/dev/null 2>&1
  local rc=$?
  t1=$(python3 -c 'import time;print(time.time())')
  local dt
  dt=$(python3 -c "print(f'{($t1-$t0):.1f}')")
  if [ $rc -eq 0 ]; then
    # 真按一次指纹不可能快过 0.3s。这么快 = sudo 时间戳缓存或 app 的
    # pre-authorization 命中，这一轮根本没碰设备，判定不可信。
    if [ "$(python3 -c "print(1 if $dt < 0.3 else 0)")" = "1" ]; then
      log "${C_NG}  └─ $label: ${dt}s 就通过了 —— 没走设备，判据失效${C_0}"
      log "${C_NG}     （sudo 时间戳缓存 / pre-auth 命中；等 30s 再跑一次）${C_0}"
      return 2
    fi
    log "${C_OK}  └─ $label: 指纹通过 (${dt}s)${C_0}"
  else
    log "${C_NG}  └─ $label: 指纹未通过 (rc=$rc, ${dt}s) —— 传感器无反应 / 落回密码${C_0}"
  fi
  return $rc
}

RESULTS=()
record() { RESULTS+=("$1"); }
# $1=标签 $2=rc  (0=PASS, 2=判据失效, 其它=FAIL)
record_rc() {
  case "$2" in
    0) record "$1:PASS" ;;
    2) record "$1:INVALID" ;;
    *) record "$1:FAIL" ;;
  esac
}

if [ "$PARALLEL" = "1" ]; then
  step "并发模式：两个授权申请同时发（测 DeviceActivityCoordinator BUSY 路径）"
  log "  说明：其中一个会被 app 判 BUSY 落回密码，这是设计行为，不算失败。"
  log "  真正要看的是 T3 —— 并发之后传感器还活着没有。"
  sudo -k 2>/dev/null
  log ""
  log "${C_HI}  ┌─ T1+T2 并发 ─ 请触摸一次指纹传感器${C_0}"
  run_timeout "$TIMEOUT" sudo -S -p '' true </dev/null >/dev/null 2>&1 & p1=$!
  run_timeout "$TIMEOUT" sudo -S -p '' true </dev/null >/dev/null 2>&1 & p2=$!
  wait $p1; r1=$?
  wait $p2; r2=$?
  if [ $r1 -eq 0 ] || [ $r2 -eq 0 ]; then
    log "${C_OK}  └─ T1+T2: 至少一个通过 (rc=$r1/$r2)${C_0}"
    record "T1+T2 并发:PASS"
  else
    log "${C_NG}  └─ T1+T2: 两个都没通过 (rc=$r1/$r2)${C_0}"
    record "T1+T2 并发:FAIL"
  fi
else
  step "顺序模式：T1 返回后立刻发 T2（复现原 bug 的时间窗）"
  log "  第 1 次指纹匹配的瞬间设备就回 SEC_OK，此时手指还压在传感器上、"
  log "  设备正要进 WAIT_LIFT → 抬指 → PS_Sleep → 可能的 touch-reset。"
  log "  T2 的 AUTH_REQUEST 正好落进这个窗口 —— 修复前它会抢跑搜索撞死 sleep。"

  touch_round "T1 基线"; r1=$?
  record_rc "T1 基线" $r1

  if [ "$GAP" != "0" ]; then
    log "  ${C_DIM}(等 ${GAP}s 再发 T2)${C_0}"
    sleep "$GAP"
  fi

  touch_round "T2 背靠背"; r2=$?
  record_rc "T2 背靠背" $r2
fi

step "T3 存活确认（停 3 秒，再来一次）"
log "  修复前：传感器此时已死，触摸完全没反应，这一步必然失败。"
sleep 3
touch_round "T3 存活"; r3=$?
record_rc "T3 存活" $r3

# ── 按键逃生口回归（只在前面挂了才需要） ────────────────────────────────
NEED_BTN=0
[ "${r3:-1}" != "0" ] && [ "${r3:-1}" != "2" ] && NEED_BTN=1

if [ "$NEED_BTN" = "1" ]; then
  step "T4 按键逃生口回归"
  log "${C_HI}  请短按一下设备上的按键（<1s），然后回车继续${C_0}"
  read -r _ </dev/tty
  sleep 1
  touch_round "T4 按键恢复后"; r4=$?
  record_rc "T4 按键恢复" $r4
fi

# ── 汇总 ────────────────────────────────────────────────────────────────
step "结果"
FAILED=0
for r in "${RESULTS[@]}"; do
  case "$r" in
    *:PASS)    log "  ${C_OK}PASS${C_0}     ${r%:*}" ;;
    *:INVALID) log "  ${C_NG}INVALID${C_0}  ${r%:*}  (没走设备，重跑)"; FAILED=1 ;;
    *)         log "  ${C_NG}FAIL${C_0}     ${r%:*}"; FAILED=1 ;;
  esac
done

if [ -n "$SERIAL_PID" ]; then
  sleep 1; kill "$SERIAL_PID" 2>/dev/null; SERIAL_PID=""
  step "设备日志关键行"
  grep -aE 'Gate: FP busy|FP_AUTH_EVT: FP busy|FP_SEARCH_EVT: FP busy|post-lift touch recovery|Touch reset|sleep no-ack|sleep OK|FP_FORCE_SLEEP_NOACK|FP_TEST_TOUCH_RESET_HOLD|Fingerprint power|FP matched|Auth OK' \
      "$SERIAL_LOG" 2>/dev/null | tail -80 | tee -a "$REPORT"

  # 有日志就必须验「测到点上了没有」。全 PASS 但没走到冲突窗口 =
  # 假阳性，比 FAIL 更危险（会让人以为验过了）。
  step "证据核查"
  ev_fail=0
  if grep -aq "FP_FORCE_SLEEP_NOACK" "$SERIAL_LOG" 2>/dev/null; then
    log "  ✓ 跑的是强制 no-ack 测试固件"
  else
    log "${C_NG}  ✗ 日志里没有 FP_FORCE_SLEEP_NOACK —— 设备上不是测试固件${C_0}"
    log "${C_NG}    (普通固件下 sleep 多半能 ack，恢复路径根本不执行)${C_0}"
    ev_fail=1
  fi
  if grep -aq "post-lift touch recovery" "$SERIAL_LOG" 2>/dev/null; then
    log "  ✓ 抬指恢复路径执行了"
  else
    log "${C_NG}  ✗ 没有 post-lift touch recovery —— 没进恢复路径${C_0}"
    ev_fail=1
  fi
  if grep -aq "Gate: FP busy" "$SERIAL_LOG" 2>/dev/null; then
    log "  ${C_OK}✓ Gate: FP busy —— fp_gate_enter 真的挡下了抢跑，修复代码执行了${C_0}"
  else
    log "${C_NG}  ✗ 没有 Gate: FP busy —— 第 2 个 AUTH_REQUEST 没撞进窗口${C_0}"
    log "${C_NG}    试 --wide 固件 + --gap 1.5${C_0}"
    ev_fail=1
  fi
  if [ "$ev_fail" = "1" ]; then
    log ""
    log "${C_NG}  上面的 PASS 不构成修复验证 —— 没有测到点上。${C_0}"
    FAILED=1
  fi
  log ""
  log "完整设备日志: $SERIAL_LOG"
fi

log ""
if [ "$FAILED" = "0" ]; then
  log "${C_OK}══ 全部通过：连发两个授权申请后传感器仍正常 ══${C_0}"
else
  log "${C_NG}══ 有失败项：把 $REPORT 贴回来 ══${C_0}"
fi
log "报告: $REPORT"
exit "$FAILED"
