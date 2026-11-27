#!/usr/bin/env python3
"""每次构建后对「ECC 标量乘搬进 RAM 执行」的强制检查。不通过就不出 bin / hex。

固件在做 P-256 标量乘之前，把链接脚本排在一起的那段热点代码（_ecc_hot_start ~
_ecc_hot_end）整段拷进 RAM 执行（见 APP/immurok_ecc_fast.c）。这件事成立有几个前提，
编译器换个版本、uECC 里多一个辅助函数都可能悄悄打破，所以每次都查：

  布局   热点段非空且不超过上限；段内只有 immurok_ecc_fast.o 的代码，函数首尾相接；
         EccPoint_mult 和 mmod_fast 在段内。
  自包含 段内指令的所有直接跳转 / 调用，目标都在段内（漏列了函数就会在这里报出来）；
         没有 auipc（PC 相对的长调用或取址，搬走后会指错地方）。
  栈     ECF_STACK_NEED 不小于「标量乘调用链 + 中断余量」；四个入口（配对两步、签名、
         密钥生成）走到跳板时，栈指针离搬进来的代码还有至少 ECF_STACK_NEED 字节——
         否则运行时会退回 Flash 执行，不崩，但又回到 2 秒。

另外查一件和 ECC 无关、但同样出在 work_buf 上的事（2026-11-26 审计）：

  读改写 keystore / security 的整块读改写期间，work_buf 里放着待写回的那一块。work_buf 紧贴
         在主栈下面，栈只要压进去，被压的字节就原样写回 Flash。所以每条走到这些函数的
         路径，连同 Flash 例程自己的栈帧，都必须装在主栈里。

栈深都按「非嵌套派发」算：固件里中途泵 TMOS 的地方用 TMOS_NESTED_PUMP() 打了标记，
做 ECC 和整块读改写的事件处理在嵌套时会把自己改期（immurok_scratch.h）。

用法（Makefile 自动调用）：
    verify.py --elf build/x.elf --map build/x.map --nm <nm> --objdump <objdump>
"""
import argparse, bisect, re, subprocess, sys

IRQ_ALLOWANCE = 256   # 标量乘期间中断处理（LLE / BB / RTC）可能叠上来的栈

ap = argparse.ArgumentParser()
for a in ("elf", "map", "nm", "objdump"):
    ap.add_argument("--" + a, required=True)
ap.add_argument("-q", "--quiet", action="store_true")
args = ap.parse_args()

def run(*cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, errors="replace").stdout

ok = True
def chk(cond, msg):
    global ok
    if not cond:
        ok = False
    if not cond or not args.quiet:
        print(("  ok  " if cond else "  !!  ") + msg)

# ---- 符号 ----
syms = []
for line in run(args.nm, "-S", "-n", args.elf).splitlines():
    p = line.split()
    if len(p) == 4:
        syms.append((int(p[0], 16), int(p[1], 16), p[2], p[3]))
    elif len(p) == 3:
        syms.append((int(p[0], 16), 0, p[1], p[2]))

def sym(name):
    c = [(a, s) for a, s, t, n in syms if n == name]
    if len(c) != 1:
        print(f"  !!  符号 {name} 应恰好出现一次，实际 {len(c)} 次")
        sys.exit(1)
    return c[0]

start, end = sym("_ecc_hot_start")[0], sym("_ecc_hot_end")[0]
mult = sym("EccPoint_mult")[0]
mmod = sym("vli_mmod_fast_secp256r1")[0]
need, guard = sym("ecf_stack_need")[0], sym("ecf_guard")[0]
work = sym("immurok_keystore_work_buf")[0]
stack_top = sym("_eusrstack")[0]
stack_bottom = sym("_heap_end")[0]     # .stack 段的起点
WORK_SIZE = 4096
code = end - start

data_len, MAX_CODE = sym("ecf_data_len")[0], sym("ecf_max_code")[0]
extent = ((code + 3) & ~3) + data_len

print(f"ecc_fast: 热点代码 {code} 字节 + 数据区 {data_len} = 占用 work_buf 低端 {extent} 字节，"
      f"ECF_STACK_NEED={need}")

# 下面所有栈余量都是拿 work_buf 和栈顶两个地址相减算的，前提是 work_buf 紧贴在主栈下面。
# 链接脚本没把它放进 .stack_guard 段的话（Link_OTA_V2.ld 曾经如此），它会落到别处，
# 相减得出一个大得离谱的「余量」，而栈下面其实是别的变量。
# 中间允许有空闲的 RAM（debug 构建就空着一千多字节），但不能有别的变量。
gap = stack_bottom - (work + WORK_SIZE)
between = sorted(n for a, s_, t, n in syms
                 if t in "bBdDsS" and work + WORK_SIZE <= a < stack_bottom and n != "_heap_end")
chk(gap >= 0 and not between,
    f"work_buf 是主栈下面最后一块（中间空闲 {gap} 字节）"
    + ("：中间还有 " + ", ".join(between[:4]) if between else ""))

chk(0 < code <= MAX_CODE, f"热点代码非空且不超过 {MAX_CODE}（当前 {code}）")
chk(start <= mult < end, "EccPoint_mult 在热点段内")
chk(start <= mmod < end, "vli_mmod_fast_secp256r1 在热点段内")

text = [(a, s, n) for a, s, t, n in syms if t in "tT"]
inside = sorted((a, s, n) for a, s, n in text if start <= a < end)
pad, prev = 0, start
for a, s, n in inside:
    pad += max(0, a - prev)
    prev = max(prev, a + s)
pad += max(0, end - prev)
chk(pad <= 4, f"段内函数首尾相接（空隙 {pad} 字节）")

# 映射文件里每个输入段一条记录：段名（可能单独占一行）+ 地址 + 大小 + 目标文件。
# 只看代码段——带调试信息的构建里，.debug_* 段的「地址」是从 0 起的偏移，会撞进这个范围。
foreign, cur = [], ""
for line in open(args.map, errors="replace"):
    nm_ = re.match(r"\s+(\.[A-Za-z_][^\s]*)", line)
    if nm_:
        cur = nm_.group(1)
    mm_ = re.search(r"\s(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\S+\.o)\)?\s*$", line)
    if mm_ and cur.startswith(".text") and int(mm_.group(2), 16) \
            and start <= int(mm_.group(1), 16) < end and "immurok_ecc_fast.o" not in mm_.group(3):
        foreign.append(mm_.group(3).rsplit("/", 1)[-1])
chk(not foreign, "段内只有 immurok_ecc_fast.o 的代码" + ("：" + ", ".join(sorted(set(foreign))) if foreign else ""))

# ---- 反汇编：自包含性 + 栈帧 + 调用图（一律按地址，不按名字） ----
hot = lambda a: start <= a < end
starts = sorted(set(a for a, s, n in text))
name_at = {}
for a, s, n in text:
    name_at.setdefault(a, n)

def func_of(a):
    i = bisect.bisect_right(starts, a) - 1
    return starts[i] if i >= 0 else None

frame, calls = {}, {}
leaks, auipc, ninsn = [], [], 0
for line in run(args.objdump, "-d", args.elf).splitlines():
    m = re.match(r"^\s*([0-9a-f]+):\s+([0-9a-f]{4,8})\s+(\S+)\s*(.*)$", line)
    if not m:
        continue
    a, op, rest = int(m.group(1), 16), m.group(3), m.group(4)
    f = func_of(a)
    sm = re.match(r"sp,sp,-(\d+)", rest) if op in ("addi", "add", "c.addi16sp", "c.addi") else None
    if sm:
        frame[f] = max(frame.get(f, 0), int(sm.group(1)))
    tm = re.search(r"\b([0-9a-f]+) <", rest)
    is_jump = op.startswith("b") or op.startswith("c.b") or op in ("j", "jal", "c.j", "c.jal")
    if op in ("jalr", "c.jalr", "jr", "c.jr"):
        # 长调用（auipc + jalr，例如从 Flash 调到 RAM 里的 FLASH_EEPROM_CMD）：
        # objdump 把目标写在行尾注释里。只用来补调用图，不算「段内的直接跳转」。
        lm = re.search(r"#\s*([0-9a-f]+) <", rest)
        if lm:
            lf = func_of(int(lm.group(1), 16))
            if lf is not None and lf != f:
                calls.setdefault(f, set()).add(lf)
    if tm and is_jump:
        t = int(tm.group(1), 16)
        tf = func_of(t)
        if tf is not None and tf != f:
            calls.setdefault(f, set()).add(tf)
        if hot(a) and not hot(t):
            leaks.append(f"{name_at.get(f, '?')} → {name_at.get(tf, hex(t))}")
    if hot(a):
        ninsn += 1
        if op == "auipc":
            auipc.append(line.strip())

chk(ninsn > 500, f"反汇编到段内指令（{ninsn} 条）")
chk(not leaks, "段内的直接跳转 / 调用目标都在段内"
    + ("——这些被调函数要加进链接脚本的热点列表：" + "; ".join(sorted(set(leaks))) if leaks else ""))
chk(not auipc, "段内没有 auipc" + ("：" + " | ".join(auipc[:3]) if auipc else ""))

# 经函数指针的调用，调用图里看不到，手工补上（只用于量栈深）。
def opt(name):
    c = [a for a, s, t, n in syms if n == name and t in "tT"]
    return c[0] if len(c) == 1 else None
mmf, dj = opt("uECC_vli_modMult_fast"), opt("double_jacobian_default")
if mmf is not None:
    calls.setdefault(mmf, set()).add(mmod)          # curve->mmod_fast
else:                                               # 被内联了：挂到每个段内函数上，取保守值
    for a, s, n in inside:
        calls.setdefault(a, set()).add(mmod)
if dj is not None:
    calls.setdefault(mult, set()).add(dj)           # curve->double_jacobian（XYcZ_initial_double 里）

memo = {}
def depth(f, seen=()):
    """从 f 往下，调用链上栈帧之和的最大值（含 f 自己）。"""
    if f in memo:
        return memo[f]
    if f in seen:
        return 0
    d = frame.get(f, 0) + max((depth(c, seen + (f,)) for c in calls.get(f, ())), default=0)
    memo[f] = d
    return d

chain = depth(mult)
chk(need >= chain + IRQ_ALLOWANCE,
    f"ECF_STACK_NEED({need}) >= 标量乘调用链({chain}) + 中断余量({IRQ_ALLOWANCE})")

# 走到跳板时的栈深：
#   main → Main_Circulation → TMOS_SystemProcess → HidEmu_ProcessEvent → 入口 → … → ecf_point_mult
# 前四层之间是长调用 / 经任务表的间接调用，调用图里连不起来，按名字逐个加。
# 2026-11-26 真机校准：测试固件实测的余量（签名 1048、配对第二步 1112）与这里算出的一致。
# 之前漏了 Main_Circulation 的 48 字节，算出来正好多 48。
tramp = sym("ecf_point_mult")[0]
def path_to(f, target, seen=()):
    """f 到 target 的直接调用路径上，栈帧之和的最大值（含两端）；到不了返回 None。"""
    if f == target:
        return frame.get(f, 0)
    if f in seen:
        return None
    best = None
    for c in calls.get(f, ()):
        d = path_to(c, target, seen + (f,))
        if d is not None and (best is None or d > best):
            best = d
    return None if best is None else best + frame.get(f, 0)

base = sum(frame.get(sym(n)[0], 0)
           for n in ("main", "Main_Circulation", "TMOS_SystemProcess", "HidEmu_ProcessEvent"))
floor = work + extent + guard
worst = None
for entry in ("immurok_security_pair_make_key", "immurok_security_pair_compute_secret",
              "immurok_keystore_sign", "immurok_keystore_generate_stage"):
    d = path_to(sym(entry)[0], tramp)
    if d is None:
        chk(False, f"{entry} 到 ecf_point_mult 找不到调用路径")
        continue
    room = stack_top - base - d - floor
    worst = room if worst is None else min(worst, room)
    chk(room >= need, f"{entry}：进入标量乘时栈余量 {room} >= {need}"
                      f"（调用方已用 {base + d}，其中事件分发 {base}）")

if worst is not None:
    print(f"ecc_fast: 最紧的入口余量 {worst}，标量乘自身需要 {chain}，"
          f"留给中断的实际空间 {worst - chain}")

# ---- 整块读改写：连同 Flash 例程的栈帧，必须装在主栈里 ----
# 这些函数从读出整块到写回全程关着中断（各自源码里的 __risc_v_disable_irq），所以这里
# 只算调用链本身，不叠中断现场。
main_stack = stack_top - (work + WORK_SIZE)      # 栈深超过它就写进 work_buf
flash_cmd = sym("FLASH_EEPROM_CMD")[0]
# compute_entries_checksum 不写回，但它把整块读进 work_buf：那一刻栈若在 work_buf 里，
# 被读进来的数据盖掉的就是 Flash 例程自己的返回地址，直接跑飞。同样要查。
rmw = [(a, n) for a, s_, n in text
       if re.match(r"(save_header|write_entry|save_security_data|compute_entries_checksum)(\.|$)"
                   r"|immurok_keystore_reset$", n)]
chk(len(rmw) >= 3, f"找到整块读改写函数 {len(rmw)} 个：" + ", ".join(n for a, n in rmw))
gatt = sum(frame.get(sym(n)[0], 0) for n in ("GATTServApp_ProcessEvent", "gattServApp_ProcessWriteReq",
                                             "GATTServApp_WriteAttr", "immurok_WriteAttrCB"))
dispatch = sum(frame.get(sym(n)[0], 0) for n in ("main", "Main_Circulation", "TMOS_SystemProcess"))
contexts = (("GATT 回调", dispatch + gatt, "HidEmu_ImmurokCommandCB"),
            ("hidEmu 事件", dispatch, "HidEmu_ProcessEvent"),
            ("LED 任务事件", dispatch, "LED_ProcessEvent"))
rmw_worst = None
for cname, prefix, root in contexts:
    r0 = sym(root)[0]
    for x, xname in rmw:
        up = path_to(r0, x)
        down = path_to(x, flash_cmd)
        if up is None or down is None:
            continue
        # root…x 的帧 + x…FLASH_EEPROM_CMD 的帧（x 只算一次）+ FLASH_EEPROM_CMD 往下最深的子调用
        deepest = prefix + up + down - frame.get(x, 0) + depth(flash_cmd) - frame.get(flash_cmd, 0)
        room = main_stack - deepest
        rmw_worst = room if rmw_worst is None else min(rmw_worst, room)
        chk(room >= 0, f"{cname} → {xname}：最深 {deepest} 字节，主栈 {main_stack}，"
                       + (f"余 {room}" if room >= 0 else f"超出 {-room}，会写进 work_buf 里待写回的那一块"))
if rmw_worst is not None:
    print(f"ecc_fast: 整块读改写最紧的路径离主栈底还有 {rmw_worst} 字节")
print("ecc_fast verify:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
