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

## 双机切换的 bond 存储（SNV 按槽分区）

1.8.1 起 BLE bond 存储（SNV）也按槽分区（`immurok_snv.h`，槽 1 0x7000 / 槽 2 0x7200，基址来自 `SDK/EVT/EXAM/BLE/HAL/include/CONFIG.h`），同一台电脑双启动两个系统可各占一槽；出厂重置/防拆/长按三条擦除路径必须调 `immurok_snv_erase_all()`。

## OTA 烧录布局 (WCH 方式一)
```
0x00000000 - 0x00001000: JumpIAP (4KB)
0x00001000 - 0x00037000: Image A / App (216KB)
0x00037000 - 0x0006D000: Image B / OTA (216KB)
0x0006D000 - 0x00070000: IAP (12KB)
```
