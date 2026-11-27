# firmware/（CH592F 固件）

从根 `CLAUDE.md` 拆出，只在处理 `firmware/` 下的文件时加载。项目全局约定见 `../CLAUDE.md`。

## 硬件 GPIO 引脚 (CH592F)

| 引脚 | VER=0 (原型) | VER=2/3 (Rev.2) | VER=5/6 (Rev.3；**只维护 VER6**) |
|------|-------------|-----------------|-----------------------|
| PA4  | UART3 RX (调试 115200) | ← | NC |
| PA5  | UART3 TX (调试 115200) | ← | ← |
| PA8  | UART1 RX (指纹 57600 8N2) | ← | ← |
| PA9  | UART1 TX (指纹) | ← | ← |
| PA12 | 指纹模块电源 (FP_PWR) | RGB LED GREEN | NC |
| PA13 | 触摸检测 INT | RGB LED BLUE | NC |
| PA14 | 物理按键 | BATT_LEVEL (AIN4, 1/2 分压) | **BATT_LEVEL (AIN4, 1/4 分压 R2=3M/R3=1M)** |
| PA15 | — | — | NC |
| PB4  | — | RGB LED RED | **BTN**（硬件 RC 消抖） |
| PB7  | — | FP_PWR (SENSOR_EN) | **LED RED** |
| PB10 | — | TOUCH (DETECT) | 防拆簧片 ANTI_OPEN（VER6 启用 `HAS_TAMPER_DETECT`） |
| PB11 | — | — | NC |
| PB12 | — | BTN | **FP_PWR (SENSOR_EN)** |
| PB13 | — | — | **TOUCH (DETECT)** |
| PB14 | — | — | 系统调试（PCB 测试点，**不做 GPIO 使用**） |
| PB15 | — | — | 系统调试（PCB 测试点） |
| PB22 | — | — | **LED BLUE** |
| PB23 | — | — | **LED GREEN**（RST 复用需保持禁用） |

- **只关心 VER6，VER5 不再维护**（2026-09-08 决定）：VER6 = Rev.3 硬件 + 防拆检测（`HAS_TAMPER_DETECT`），`firmware/Makefile` 默认 `HW_VER=6`。VER5 与 VER6 引脚完全相同，只差防拆宏。改固件时不必再为 VER5 留兼容分支，也不必检查 `HAS_TAMPER_DETECT=0` 的路径是否成立（例：QC 收尾禁止重广播的门曾只包在 `#if HAS_FACTORY_TEST` 里，VER5 编译掉了——这类问题以后不算 bug，只要 VER6 对即可）
- 三色 LED 全部搬到 GPIOB；BTN 回 PB4；BATT 仍在 PA14 但分压比改为 1/4
- **32.768 kHz 晶振 X2 必须是标称负载 9–12.5 pF 的料**（量产 SC-20S 9 pF C97603；换 12.5 pF 时改 `LSE_LOAD_CAP`）。CH592 内置负载最小 12 pF，2026-09-26 PCB7_RF 批次被替代成 4 pF 的 ABS06-107（C276418）后，静态频率/RSSI 全正常，但 CPU 长阻塞（QC 自动项、ECDH 配对、OTA）后 BLE 必定 6 s 监督超时——32k 时基抖动丢锚点。1.8.5 起固件显式设负载/驱动（`hardware_pins.h`），QC `lse` 项改为 1 s 精确窗口 + 70% 驱动余量测试，专门筛这类料
- 指纹 UART 回到 UART1 (PA8/PA9)；SENSOR_EN 从 PB7 迁移到 PB12
- 防拆簧片 U7 (YTD-M02-AA) → PB10：VER6 构建启用 `HAS_TAMPER_DETECT`，高电平=开盖；已配对设备开盖（运行中上升沿或开机时静态高，后者覆盖关机开盖被 Q2/D1 旁路上电的情况）擦密钥/bond/指纹并红灯停机；未配对设备忽略
- 出厂自检（VER6，`firmware/APP/factory_test.c`）：未配对设备只要 ANTI_OPEN 为高（开盖，开机时或运行中）就进入「开盖保持」：不广播、红灯 1s/1s 慢闪、每 200ms 轮询簧片，合盖自动恢复正常广播；保持态下短按 BTN 进入自检。红/黄/蓝各亮 300ms 后依次测指纹模块、电池 ADC（3.0-4.4V）、DataFlash 擦写、BLE 广播启动；失败停机等断电：红快闪=指纹、黄快闪=电池、绿快闪=flash、蓝快闪=广播、白常亮=残留指纹模板。全过则以固定静态地址 `C0:FA:C7:01:00:01`、名 `im-k1-test` 广播、绿灯 1s/1s 慢闪等测试主机（触摸传感器黄灯闪 200ms；再来一次簧片沿 + 短按 BTN 重跑自检）；bonding 关闭、不记 slot_meta、拒 PAIR_INIT/CONFIRM/OTA，断电即恢复正常

## 32.768 kHz 晶振负载匹配（2026-09-26 事故复盘，**遇到下列症状先查 X2**）

**症状指纹**（任一出现就先怀疑 32k 晶振/负载，别先去查天线、电源、协议栈）：
- 链路在 **CPU 长阻塞之后**必断：写 0x40 后 QC 自动项（~2.6 s）、ECDH 配对 `make_key`（~1.8 s）、OTA 大流量——从阻塞开始算**正好 6 s** 报 `Disconnected.. Reason:8`（监督超时），阻塞结束后 CPU 空闲也救不回来
- 阻塞后设备侧 RSSI 寄存器不再更新（一个包都收不到），空闲时 RSSI / CFO / 开机 `LSE` 1 s 计数（±200 ppm 内）却全都正常
- 同一固件在老板子上完全正常；快连板 OTA 中途断、Windows 服务发现只枚举到前 5 个标准服务
- 快连板日志里 `disc during test (0x208), reconnect` 100% 出现

**根因**：CH592 内置 32k 负载电容最小 12 pF、复位默认 24 pF（`R8_XT32K_TUNE`），晶振标称 CL 必须落在 9–12.5 pF。PCB7_RF 批次 X2 被替代成 4 pF 的 ABS06-107（C276418），静态频率没问题但起振余量不足，CPU 忙时 32k 时基抖动，BLE 协议栈丢连接锚点。老批次用 SC-20S 9 pF（C97603）。**换料只看容值和封装是不够的，32k 晶振的 CL 是硬约束**。

**诊断手段**：开机横幅 `X32K %02X %dpF i%d` 回读寄存器；QC `lse` 项打印 `lse ok/fail ±N tick/1s (~ppm)`（1 tick ≈ 30 ppm，rd 版可见）。

**固件约定**：`hardware_pins.h` 的 `LSE_LOAD_CAP` / `LSE_DRIVE_CURRENT` 按 BOM 显式设置；驱动常驻 200%（复位默认），**不做起振后自动降档**（2026-09-27 决定，待实测功耗后再议）。换 12.5 pF 晶振时改 `LSECap_13p` 并按 QC lse 的 ppm 微调。

**2026-10-25 决定与复盘（1.8.6）**：量产只用 9 pF / 12.5 pF 标称负载的料，**QC 不再筛 4 pF 料**，1.8.5 加的「驱动降到 70% 测起振余量」已删；lse 项只保留 1 s 频率窗（±300 ppm），用于抓停振 / 虚焊 / 装错料。
- 1.8.5 的 QC 在所有量产板上卡死在 lse：根因是 **CH592 进 Sleep 后 SysTick 寄存器被硬件清零**（真机 rd 日志 `ctlr=00000000 cnt=0`，CPU 并未在睡，`g_sleep_inhibit=1`），而 1.8.5 的 lse 以 SysTick 当 1 s 墙钟，永远等不到；循环里仍泵 TMOS，BLE 照常应答 QC_GET，QC 板看到 `phase=1 bitmap=0x1F` 直到 60 s no_result。debug 版 `HAL_SLEEP=FALSE` 和开机瞬间都测不出来，**凡用 SysTick 当时基的代码在 HAL_SLEEP=TRUE 固件里必须先重配、测完校验**，验证一律用 release-debug。1.8.6 的 `qc_lse_measure` 测前 `SysTick_Config`、RTC 3 s 与迭代次数双兜底。
- 1.8.5 把 09-26 的「等触摸阶段睡 1.3 s」归因到 hidkbd 断链覆写 `g_sleep_inhibit`，真实的隐患在 `Profile/hiddev.c` 参数更新回调：timeout ≥ `PARAM_OK_CONN_TIMEOUT` 时**无条件** `g_sleep_inhibit--`，而配对的 `++` 只在 timeout 不够的分支。QC 板给 20 s 永不走 `++`。本次现场参数更新发生在 QC 开始前 1.5 s，没有偷到 QC 的引用，故不是本案原因，**但仍是待修隐患**（可能让指纹模块供电期间意外入睡）。
- **待办（熵源，未修）**：`immurok_entropy.c` 第 3/4 路输入读 SysTick（命令到达时刻 + 32 个「每个 32k 边沿采 SysTick 低 8 位」抖动样本），首次 Sleep 后全为 0，ECDH 临时私钥 / KEY_GENERATE 的随机性退化到只剩温度 ADC 噪声 + RTC/TMOS 时间戳（ECDSA k 已确定性派生，不受影响）。**修法定为方案二**：在 `immurok_entropy_reseed()` 开头检查 `SysTick->CTLR & STE`，未使能则 `SysTick_Config` + 关 IRQ 再采样，不改 SDK/SLEEP.c。可复用 `qc_test.c` 的 `qc_systick_arm()` 思路（抽到公共处）。

## BLE 连接参数（macOS HID 键盘）

Apple Accessory Design Guidelines 要求：
```
Supervision Timeout > Interval Max × (Slave Latency + 1) × 3
```

当前参数：Interval 30-50ms, Latency 29, Timeout 6s。
参数更新需在连接后延迟 30s（等 macOS 完成服务发现后再请求）。

## ECC 标量乘从 RAM 执行（2026-11-26，`APP/immurok_ecc_fast.c`）

CH592 从 Flash 取指很慢：P-256 标量乘在 Flash 上约 2 s，同一段机器码搬进 RAM 约 0.37 s（真机实测 5.4 倍）。配对的两步 ECDH、SSH 签名、SSH 密钥生成都是一次标量乘，放进 RAM 后远小于 macOS 给 HID 键盘的 2000 ms supervision timeout，不再依赖主机肯给长超时。

- **机制**：固件不单独编译 `LIB/uECC.c`，由 `immurok_ecc_fast.c` 包含它（全固件只有一份 micro-ecc）。链接脚本把热点函数排在一起（`_ecc_hot_start ~ _ecc_hot_end`，三个 `.ld` 里的列表必须一致），标量乘前整段（约 2.7 KB）拷进 `immurok_keystore_work_buf` 低端执行，算完即弃。RAM 没有常驻空间，只能这样分时复用。
- **OTA 验签不走这条路**：`uECC_verify` 有自己的循环，仍从 Flash 执行，机器码与单独编译 `uECC.c` 时相同。RAM 路径即使有问题也不妨碍用 OTA 修。
- **改 ECC 相关代码时不能破坏的前提**：
  - **ECC 的回调里不能泵 TMOS**（`immurok_wdt_kick` 只喂狗）。标量乘期间 work_buf 里是正在执行的代码，别的任务一旦插进来用 work_buf 就跑飞。以前「每 56 ms 泵一次保链路」的做法已删，它本来也保不住链路。
  - work_buf 高端是栈溢出缓冲带，代码占了低端，栈和代码共用中间那段。入口函数里的大数组会吃掉余量，放 `immurok_ecc_fast_scratch()` 借用区，别放栈上。
  - 热点段内的代码不能直接调用段外函数（包括编译器偷偷生成的 `memset` / `memcpy` 调用）。
- **`tools/ecc_fast/verify.py` 每次构建自动跑**，检查段是否自包含、栈余量够不够，不通过就不出 bin / hex。它报「要加进热点列表」时，把函数名加到三个链接脚本里；报栈余量不够时，看是哪个入口的调用链变深了。
- **兜底**：布局检查不过、work_buf 被占、栈余量不够时，跳板退回 Flash 上原地执行（慢，约 2 s，不崩）。保护带被写穿过一次就锁存到重启，此后一律走 Flash。`immurok_ecc_fast_available()` 为假时，`hidkbd.c` 里「先把超时谈到 6000 ms」的旧门照常生效。
- **`available()` 为真不等于这一次一定走 RAM**：栈余量是进入时按当前 sp 现算的，构建检查只建模了「事件直接派发」的栈深。所以执行事件在嵌套派发时不做 ECC，改期到外层返回之后（见下一节的 `immurok_tmos_nested()`）。
- **超时门（2026-11-26 审计后）**：等完参数更新后 timeout 仍低于 1000 ms 就拒绝，不再有「高于 300 ms 就照算」——运算期间 0.4–0.6 s 不服务链路，那样的链路上算完必断。拒绝统一走 `long_op_reject()`：配对回 `[PAIR_INIT/CONFIRM, SEC_ERR_INTERNAL]` 并把 ECDH 状态收回 IDLE，签名和密钥生成回 `0xE1`。
- **真机验证（2026-11-26，VER6，1.8.9 + 本改动的 release 测试构建，macOS 27.0.1）**：
  - 签名：6000 ms 链路 5 次、2000 ms 链路（重连后的 override 窗口，15 ms / latency 22）3 次，全部本机验签通过。指纹通过到签名完成约 0.5 s，同条件下官方 1.8.9 是 3.24 s。2000 ms 那 3 次期间没有任何参数协商，链路没断。
  - 密钥生成：1 次（6000 ms），公钥合法，用新密钥签名验签通过。
  - 配对：恢复出厂后重配 1 次，两端密钥一致（身份校验和指纹门都过）。第二步从发出到应答 0.54 s。**当时链路已是 6000 ms**——`PAIR_INIT` 仍会提前申请长超时，macOS 在按键前批了，所以 2000 ms 下的配对没有直接测到。
  - 10 次标量乘全部走 RAM，没有退回 Flash，保护带没被碰过。栈实际用量 400 字节，与 `verify.py` 从反汇编算出的调用链相同；进入时的余量（签名 1048、配对第二步 1112）也与脚本预测一致。中断没有在最深处再叠出可观的栈，预留的 256 字节是保守的。
  - 行为变化：配对时「按键已确认」的通知（`[0x34][0x01]`）现在和设备公钥一起到，晚约 0.4 s——运算期间不处理事件，以前是泵 TMOS 时顺带发出去的。
  - **没测的**：2000 ms 下的配对与密钥生成；release-debug / debug 构建上真机（只确认能编译并过检查）；长时间使用。
- 复测方法：测试构建 `TEST_DEFS=-DECC_FAST_DIAG` 可经 `GET_CONN_PARAMS` 载荷 `[0xEC]` 读出走了哪条路径、栈余量和实际栈用量；App 用测试钩子构建，`TEST:KEY_SIGN` / `TEST:KEY_GENERATE` / `TEST:PAIR` 触发，`TEST:OTA` 刷入和刷回。

## work_buf、主栈与嵌套派发（2026-11-26 审计，**改 Flash 读改写或 ECC 相关代码前先看**）

`immurok_keystore_work_buf`（4096 字节）紧贴在 512 字节主栈下面，身兼三职：整块读改写的缓冲、栈溢出缓冲带、ECC 标量乘时放代码的地方。这三个角色会互相踩：

- **真实发生过的问题（1.8.9 及之前都有）**：指纹冷却期内的 `KEY_COMMIT` / `KEY_DELETE` 在 GATT 回调里直接做整块读改写，调用栈 592 字节，主栈加空隙只有 568。Flash 例程的栈帧落进 work_buf 末 12 字节，而那时 work_buf 里正是待写回的那一块——块尾 12 字节被原样写坏。校验和是写完后重算的，所以**不报错**。API 类目写第 27 个及以后的条目时坏的是第 26 个条目的密钥，OTP 写第 46 个及以后时坏的是第 45 个条目的名称。同类的还有解绑本槽时的 `save_security_data`。代码里多处写的「ECC 之后立刻读写 EEPROM 会把芯片打进 IAP」，很可能也是这一类（推断，未单独验证）。
- **规则**：
  - **GATT 回调里不直接做整块读改写**。回调栈已经 336 字节。冷却期的 `KEY_COMMIT` / `KEY_DELETE` 现在延后到执行事件（`FP_GATE_EXEC_EVT`）里做，应答从那里发。
  - **整块读改写从读出到写回全程关中断**（`save_header` / `write_entry` / `save_security_data` / `immurok_keystore_reset`）。LLE 中断一进来就压 128 字节现场。
  - **中途泵 TMOS 的地方一律用 `TMOS_NESTED_PUMP()`**（现有四处：指纹串口等待两处、VBAT 稳定延时、QC 自检）。嵌套派发出来的事件和 GATT 回调栈深要再加 200–350 字节。做 ECC 或整块读改写的事件处理先看 `immurok_tmos_nested()`，嵌套就把自己改期 5 ms；`immurok_keystore_commit` / `delete`、`save_security_data` 入口自己也查，嵌套时拒绝。
  - 入口函数里别放大的栈上数组（`save_security_data` 原来校验用的 112 字节副本就是这么把栈顶进 work_buf 的）。
- **`tools/ecc_fast/verify.py` 每次构建都查**：work_buf 是不是主栈下面最后一块；每条走到整块读改写（以及把整块读进 work_buf 的 `compute_entries_checksum`）的路径（GATT 回调、hidEmu 事件、LED 任务事件三种上下文）连同 Flash 例程的栈帧能不能装进主栈。现在最紧的一条余 72 字节（GATT 回调里的出厂重置）。它报超出时，要么把那次操作延后到事件里，要么减栈帧。
- **真机结果（2026-11-26，用户设备）**：
  - 修复前（1.9.0.f3a2）复现：一次触摸后在冷却期内连写 47 条 OTP 测试条目，写第 46 条（idx 45）之后，第 45 条（idx 44）的第 24–35 字节由 `75767778797a5334342d4142` 变成 `440000000010000000100f00`——正是预测的那 12 字节，内容是 Flash 例程压进去的寄存器（长度、地址之类）。随后在冷却期内删条目，设备无应答、约 1 秒后重连、条目没删掉——同一处越界的另一种表现（读进来的整块盖掉了栈上的返回地址，推断）。
  - 修复后（同一设备、同样步骤）：47 条写入后全量核对无误；46 条 + 47 条两轮删除正常；签名 3 次、密钥生成往返 1 次全过，5 次标量乘都走 RAM、保护带未触发，全程无断连。
  - **嵌套派发时的改期（同日补测，测试构建 `TEST_DEFS="-DECC_FAST_DIAG -DTMOS_NESTED_DIAG"`）**：
    - 注入（`GET_CONN_PARAMS` 载荷 `[0xED, n, mask]` 让指定位置接下来 n 次答「是嵌套」）13 项全过：执行事件、新密钥落盘事件各被改期 3 次后，签名 / 冷却期写入 / 密钥生成照常完成；写入、删除入口被拒时回错误、数据不变、下一次照常。
    - 压力（冷却期内连写连删 40 条 × 多轮，同时每秒触摸一次）：执行事件真实撞上嵌套 4 次，最长连续改期 4 次（20 ms），都照常完成；没有一次落到「入口拒绝」。
    - `EEPROM_SAVE_EVT`（配对落盘）和 `save_security_data` 入口这两处没有注入测（要动配对）。
    - 测试开关只在显式传 `TEST_DEFS` 时编进去，正式 release 构建加开关前后逐字节相同。带开关的固件不能发：已配对主机能用 `[0xED …]` 让写入被拒绝 / 推迟，最紧的栈路径余量只剩 16 字节（正式构建 72）。`ota/build-ota.sh` 会拒绝打包（查环境变量、`build/.build_flags`、map 里的测试符号）；测试固件直接 `make TEST_DEFS=… BUILD_DIR=<别处>` 再用 `ota-package.py` 打。
  - **没测到的**：解绑本槽 / 重新配对（`save_security_data` 的写入路径，解绑唯一主机等于出厂重置）、超时不足时的拒绝。

## 发送队列满时应答丢失（2026-11-26 压力测试发现，同日修复，**未合并、未随发布包**）

`ImmurokService_SendResponse()` 调一次 `GATT_Notification`，返回非 SUCCESS 就把应答丢掉，不重试。压力测试里（冷却期连写 + 每秒触摸）主机发出 421 条命令，设备命令回调也是 421 次，其中 14 次应答发送失败，状态全是 `0x16 blePending`，与主机侧 14 次 5 秒超时一一对应；55 次触摸里 14 次命中，13 次超时的命令发出前后 2 秒内有指纹匹配通知。

- 丢的是应答，命令本身已经执行：`KEY_COMMIT` 丢应答时条目其实写进去了，主机以为失败（一轮里设备 37 条、主机只确认 33 条）。
- 丢应答的命令有 `0x62`（分块暂存）、`0x22`（匹配确认）这类本次审计修复没碰过的路径，所以判断是原有问题；**但没有在旧固件上做对照**（只读命令对照跑了两次，都没采到触摸）。不触摸时 430 条只读命令没有一次发送失败。
- **机制（同日用测试构建的 `[0xEE …]` 命令确认，全程不需要触摸）**：
  - 发送队列容量 4 条：事件里连发 8 条，前 4 条成功、后 4 条 `blePending`；命令回调里连发 4 条，第 4 条 `blePending`（协议栈自己的写响应占一条）。
  - **一个事件处理函数里排进队列的包，在它返回主循环之前发不出去**：先发 3 条、原地阻塞 100–800 ms、再发 3 条，后 3 条总是只成功 1 条；阻塞期间每 10 ms 泵一次 TMOS 也一样。
  - 「主动触摸」（没有等指纹门）会发唤醒主机的按键：`hidEmuSendCtrlKey()` 一条松开 + 一条按下 Ctrl，80 ms 后再一条松开，匹配成功再发 `0x21` 通知——正好 4 条。触摸处理期间到达的命令，应答是第 5 条。等指纹门的触摸不发按键，所以从不丢。真实触摸路径上队列里是不是恰好这 4 条没有直接测，是按代码和下面的复现推断的。
  - 按这个顺序复现（阻塞前 3 条 + 阻塞 800 ms + 阻塞后 1 条，期间主机发一条只读命令）：应答 8/8 丢失，设备每次记录 1 次 `blePending`；阻塞前改成 2 条则 3/3 到达。这就是修复后的回归用例。
  - 「连发两条通知第二条就失败」是一开始的推测，实验否定了它（事件里连发 2–4 条都成功）。
- `HID_KEY_RELEASE_EVT` 早就为同一个原因加过重试（注释里写着 BLE buffer full），只有命令应答这条路没有。
- **修复**（`Profile/immurokservice.c`，注释里有完整说明）：`ImmurokService_SendResponse()` 遇到可重试的失败（`blePending` / 无缓冲 / 无资源）不再丢，记下长度留在 `immurokRspValue` 里，由 LED 任务的 `RSP_RETRY_EVT` 每 10 ms 调 `ImmurokService_FlushPending()` 重发；上限 2.5 s（主机超时 5 s，再晚会被配给下一条命令），断连即作废。只有一个槽位：槽里有东西时新的先等它发掉，发不掉就丢弃新的并返回 `blePending`。嵌套派发时不重试也不计次数。代价：RAM 2 字节、Flash 260 字节；整块读改写最紧的栈余量 72 → 64。
- **回归结果**（测试构建，不需要触摸）：上面那个 8/8 丢失的用例变成 8/8 到达，每次设备记录「首次失败 1、留待重发 1、重发成功 1、丢弃 0」，应答排在 4 条通知之后；队列没满时不走重发；事件里连发 8 条，主机按顺序收到前 5 条，后 3 条如实返回 `blePending`；连发 150 条只读命令没有触发重发。
- **真实触摸下的验证**（同日，带修复的测试构建）：一次触摸后冷却期内连写 40 条再连删，同时每秒触摸一次（20 次匹配通知）。主机 292 条命令 0 超时（修复前同样的做法 421 条里超时 14 条）；40 条主机与设备一致、内容正确；设备记录留待重发 7 次、重发成功 7 次、丢弃 0。被留下的应答都在一个连接间隔（60 ms）后到达。随后签名 2 次验签通过。
- 这次的日志也纠正了之前的一个说法：触摸处理期间设备**并没有**把命令晾上 0.5–2 秒，命令一直按 120 ms 的节奏在应答；丢的是恰好在「3 条按键 + 匹配通知」还占着队列的那一刻发出的应答。
- **没测的**：断连时作废、次数用完、带指纹门的删除。`0x21` 匹配通知如果在槽位已被占时失败仍会丢（需要一轮里 6 条以上）。
- **debug 构建的 Flash 只剩 408 字节**（修复前 724）。
- 主机侧另有一个问题没动：超时后迟到的应答会被配给下一条命令（macOS App 按到达顺序配对，迟到一条后面全部错位，测试里见过）。

## 双机切换的 bond 存储（SNV 按槽分区）

1.8.1 起 BLE bond 存储（SNV）也按槽分区（`immurok_snv.h`，槽 1 0x7000 / 槽 2 0x7200，基址来自 `SDK/EVT/EXAM/BLE/HAL/include/CONFIG.h`），同一台电脑双启动两个系统可各占一槽；出厂重置/防拆/长按三条擦除路径必须调 `immurok_snv_erase_all()`。

## SDK 版本与待合并的厂商修复（2026-11-25 记录）

- **SDK 入库的是 2025.11 版 EVT 加项目补丁，不能用新版整包覆盖**。项目补丁至少有：`BLE/HAL/SLEEP.c`（`g_sleep_inhibit` 检查、UART3 调试口等待与睡眠超时日志、`PWR_PeriphWakeUpCfg` GPIO 唤醒）、`StdPeriphDriver/inc/CH592SFR.h`（`PRINT` 走 `dbg_printf`）。升级只能逐文件手工合并。
- BLE 协议栈库 `BLE/LIB/libCH59xBLE.a` 是 `CH59x_BLE_LIB_V1.4.4`（取自 2026.10 EVT，头文件与 2025.11 相同）。**本机从 2026-08-14 起就在用 V1.4.4**，2026-11-25 的提交 `9a7152f7` 只是把它补进 git，不是那天才换的库。出货固件 1.7.0 及之前是 V1.4.2，1.7.1 起（含 1.8.x）都是 V1.4.4；旧库备份在 `libCH59xBLE.a.v142.bak`（未入库）。头文件的 `VER_FILE` 只写到 `V1.4`，查某个固件用的库版本要看 bin 里的字符串：`strings -a dist/ota-*.bin | grep CH59x_BLE_LIB_V`。
- **待合并：`CH59x_pwr.c` 的睡眠唤醒加固（2026.10 EVT）**。睡眠时 Flash 断电；新版 `LowPower_Sleep` 在 `__WFI()` 返回后重读一次 MAC，与睡前不一致（Flash 未就绪）就用 RTC 再等 10 个 32k 周期才继续。没有这层保护时，偶发的「Flash 没就绪就执行」会跑飞并由看门狗复位，主机侧表现为断开后重连。
  - **与「macOS 下每隔一两个小时断开重连」的关系：可能有关，未验证。** 空闲时设备约每 1.2 s 睡醒一次（60 ms × latency 20），每小时约 3000 次，极低的单次出错率就能对上这个频率；但监督超时（32k 抖动丢锚点）、macOS 主动断开、参数更新失败也会是同样的现象，这个补丁都管不到。
  - **先确认原因再合**：用 release-debug 挂串口等断开。断开时重新打印开机横幅和 `Reset status` = 设备重启，补丁对症；只有 `Disconnected.. Reason:8/13` 而无开机横幅 = 设备没重启，往链路或 macOS 方向查。
  - 合并时保留上面的项目补丁，合完用 release-debug 真机验证睡眠和唤醒。
- 2026.10 EVT 其余与本固件相关的改动（均未合）：`MCU.c` SNV 写入下标修正（只影响 CH592A 分支）、`CH59x_clk.c` 内部 32k RC 校准常数 1366→1320、宏 `ROM_CFG_VERISON` 改名 `ROM_CFG_VERSION`（`APP/main.c` 还在用旧名）、新增 `GET_CHIP_VERSION()`。

## OTA 烧录布局 (WCH 方式一)
```
0x00000000 - 0x00001000: JumpIAP (4KB)
0x00001000 - 0x00037000: Image A / App (216KB)
0x00037000 - 0x0006D000: Image B / OTA (216KB)
0x0006D000 - 0x00070000: IAP (12KB)
```
