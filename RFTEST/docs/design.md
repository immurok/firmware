# RF 测试固件设计（immurok IK-1 / CH592F VER=5）

- 日期：2026-06-16
- 分支：`feat/rf-test-firmware`（基于 `main`）
- 目标硬件：CH592F **VER=5**（latest 之一）
- 状态：设计已与用户确认，待写实现计划

## 1. 背景与目标

为 FCC / SRRC / CE 等射频认证及产线 RF 校准，提供一个**独立的射频测试固件**，让第三方实验室能通过串口直接驱动设备发射/接收特定射频信号。

核心约束（来自用户）：

1. **量产固件零测试代码** —— RF 测试功能做成独立固件 target，量产 `make` 完全不参与编译，二进制内不含任何测试命令字。
2. **不使用指纹传感器** —— 上电即把指纹传感器电源 `SENSOR_EN`（FP_PWR）置 0（断电）。
3. **复用指纹 UART 作命令口** —— VER=5 上指纹 UART = UART1（PA8 RX / PA9 TX），重定向为 RF 测试命令字收发端口。
4. **命令字与响应符合参考文档**（见 §4，对应 Method A — Debug UART Command 截图）。
5. **给出命令字与响应说明文件**（交付物 `firmware/RFTEST/PROTOCOL.md`）。
6. **加入其他必要命令**（见 §4 加粗项）。

### 非目标 / YAGNI

- 不实现 OTA（本固件只用有线烧录）。
- 不实现指纹、HID 键盘、自定义 GATT、PAM、防拆等量产功能。
- 不实现信道自动扫频（实验室自行用脚本循环单条命令即可）。

## 2. 关键安全/合规约束

- **射频前端必须与量产件一致**：同一 `HW_VER=5`、同一 PA / 匹配网络 / 天线、同一功率配置寄存器路径。测试固件只在控制层不同，射频特性须代表量产件，否则认证结果无效。
- **绝不签 OTA、绝不进 OTA 分发**：只用有线 `wlink`(SWD) 烧录给实验室。
- 留版本对应记录：认证固件版本 ↔ 对应量产固件版本，并注明"仅测试控制代码不同、射频特性一致"。

## 3. 架构

### 3.1 代码结构

```
firmware/
├── Makefile.rftest          # 新增:RF 测试固件构建(非 OTA,从 0x0 起,普通 Link.ld)
└── RFTEST/
    ├── rftest_main.c        # 入口:时钟/GPIO/BLE 最小初始化 + TMOS 主循环
    ├── ftm.c / ftm.h        # 命令调度 + RF 控制状态机(依赖 SDK,板上运行)
    ├── ftm_parse.c/.h       # 纯逻辑:分词/参数校验/PRBS 生成/功率映射(可 host 单测)
    ├── test/                # host 编译的纯逻辑单元测试
    └── PROTOCOL.md          # 命令字 & 响应说明文件(交付物)
```

- 产物：`firmware/build_rftest/immurok_CH592F_RFTEST.hex` / `.bin`
- BLE 最小初始化参照 SDK `EVT/EXAM/BLE/RF_PHY` 例程。

### 3.2 依赖的 SDK / BLE LIB API

| API | 用途 |
|-----|------|
| `RF_RoleInit()` / `RF_Config(rfConfig_t*)` | 进入 2.4G 私有 RF 模式,设信道/PHY/白化 |
| `RF_Tx()` / `RF_Rx()` / `RF_Shut()` | 单包发射 / 接收 / 停止 |
| `RF_SetChannel()` / `RF_SetFrequency()` | 设信道 / 精确频率(配合 `LLE_MODE_EX_CHANNEL`) |
| `LL_SingleChannel(ch)` | **未调制 CW 载波** |
| `LL_SetTxPowerLevel(power)` | 运行时设发射功率,宏 `LL_TX_PWR_*_DBM` |
| `rfStatusCB`(`rfConfig_t.rfStatusCB`) | TX 完成 / RX 收包回调(连续发射重装、收包计数) |

功率宏可用档（精度 ±2dBm）：-20 / -15 / -10 / -8 / -5 / -3 / -1 / 0 / +1 / +2 / +3 / +4 / +9 dBm。
**注意：硬件无 -6dBm 档**，截图功率档 2 映射到最近的 -5dBm，并在 PROTOCOL.md 注明偏差。

### 3.3 VER=5 引脚使用

| 引脚 | 用途 |
|------|------|
| PA8 / PA9 | UART1 RX / TX —— **RF 测试命令口 @ 115200 8N1** |
| PB12 | SENSOR_EN(FP_PWR)—— **上电置 0,指纹传感器断电** |
| PB7 | LED RED —— 发射中指示 |
| PB22 | LED BLUE —— 接收中指示 |
| PB23 | LED GREEN —— RST 复用,**保持禁用** |
| PA14 | BATT_LEVEL(AIN4,1/4 分压)—— `vbat` 命令读取 |
| PA5 | UART3 TX —— 可选调试日志输出(命令 I/O 不走此口) |

## 4. 命令集与响应

- 串口：UART1 @ **115200 8N1**
- 行协议：命令以 `\n` 结尾（兼容 `\r\n`），token 以空格分隔
- 成功：`OK ...`；失败：`ERR <原因>`
- 命令回显默认开（`echo` 可关）
- 开机横幅：`[FTM] ready`，随后 `immurok IK-1 RFTEST v1.0 HW=5`

### 4.1 截图原有命令

| 命令 | 行为 | 响应示例 |
|------|------|----------|
| `tx <ch> <power_level>` | 连续调制发射（默认 PRBS9 载荷）；功率档 0=0dBm / 1=-3 / **2=-5(≈-6,注偏差)** / 3=+3 | `OK tx ch=0 pwr=0dBm phy=1M payload=PRBS9` |
| `txcw <ch>` | 未调制 CW 载波（`LL_SingleChannel`） | `OK txcw ch=19 freq=2440MHz` |
| `tx_payload <ch> <pattern>` | 指定载荷发射：0 PRBS9 / 1 0x0F / 2 0x55 / 3 PRBS15 / 4 全1 / 5 全0 / 6 0xF0 / 7 0xAA | `OK tx_payload ch=39 pattern=0x55` |
| `tx_phy <0\|1>` | 后续 tx/tx_payload 用 LE 1M(0) / LE 2M(1) | `OK phy=2M` |
| `rx <ch>` | 进接收模式，累计收包数与 CRC 错误 | `OK rx ch=0 listening` |
| `stop` | 停止收/发；若刚在 rx，顺带打印 `rxstats` | `OK stop`（+ `rxstats ch=0 pkt=1234 crc_err=2`） |
| `reset` | 重启退出测试模式 | `OK reset`（随后复位） |

### 4.2 新增命令

| 命令 | 行为 | 响应示例 |
|------|------|----------|
| `help` | 列出所有命令 | 多行帮助文本 |
| `ver` | 固件版本 / 构建日期 / HW VER / 当前 PHY | `immurok IK-1 RFTEST v1.0 build=20260616 HW=5 phy=1M` |
| `id` | 芯片 MAC / 唯一 ID（实验室记录被测件） | `id MAC=AA:BB:CC:DD:EE:FF` |
| `freq <khz>` | 按精确频率发射（2400000–2483500 kHz），用 `RF_SetFrequency`，测频带边沿/杂散 | `OK freq=2402000kHz` |
| `txpower <dbm>` | 直接设绝对功率，映射到最近硬件档（-20…+4） | `OK txpower=-8dBm` |
| `vbat` | 读 PA14 电池分压电压（VER=5 = 1/4 分压） | `vbat=4096mV` |
| `echo <on\|off>` | 命令回显开关（默认 on） | `OK echo=off` |

### 4.3 错误响应

| 场景 | 响应 |
|------|------|
| 信道越界 | `ERR bad channel (0-39)` |
| 功率档越界 | `ERR bad power (0-3)` |
| pattern 越界 | `ERR bad pattern (0-7)` |
| phy 非 0/1 | `ERR bad phy (0|1)` |
| 频率越界 | `ERR bad freq (2400000-2483500)` |
| 参数缺失 | `ERR bad args` |
| 未知命令 | `ERR unknown cmd` |
| 行超长（>64B） | `ERR line too long` |

## 5. RF 实现要点

- **连续调制发射**：`RF_Tx` 发单包，在 `rfStatusCB` 的 TX 完成回调里自动重装下一包 → 背靠背连续发射；`stop` 置标志位停止重装并 `RF_Shut()`。
- **载荷生成**：PRBS9 / PRBS15 用标准 BLE DTM LFSR 多项式生成（PRBS9: x⁹+x⁵+1；PRBS15: x¹⁵+x¹⁴+1），其余为固定字节填充（0x0F/0x55/0xFF/0x00/0xF0/0xAA）。包长取 BLE DTM 惯例 37 字节。
- **功率**：`LL_SetTxPowerLevel()` + `LL_TX_PWR_*_DBM`；`tx` 的 0–3 档与 `txpower <dbm>` 共用同一 dBm→宏映射函数。
- **PHY 切换**：修改 `LLEMode` BIT4-5（00=1M，01=2M）后重新 `RF_Config`。
- **CW 载波**：`LL_SingleChannel(ch)`，`stop` 用 `RF_Shut()` 退出。
- **互斥**：同一时刻只允许一个收/发任务；启动新任务前自动 `stop` 上一个（响应里提示已停止旧任务）。
- **RX 统计**：在 `rfStatusCB` 里累计成功收包数与 CRC 错误数；`stop`（或 rx 期间）输出 `rxstats`。

## 6. 测试策略

### 6.1 纯逻辑单元测试（host 编译，TDD）

把以下纯逻辑抽到 `ftm_parse.c`，先写测试再实现：

- 命令分词与参数解析（含边界/缺参/超长）
- 各 `ERR` 分支触发
- PRBS9 / PRBS15 LFSR 序列（对已知前若干字节）
- 功率 dBm → 宏映射（含 -6→-5 近似、越界钳位）
- 信道 → 频率换算（f = 2402 + ch×2 MHz）

`firmware/RFTEST/test/` 下用主机 `gcc` 编译运行，不依赖 SDK。

### 6.2 硬件手动测试清单（写入 PROTOCOL.md）

每条命令配预期与仪表项：

- `tx` / `txpower`：频谱仪/功率计读输出功率，对各功率档校准
- `txcw`：频率误差/频偏、载波泄漏、谐波杂散
- `tx_payload`：调制精度、占用带宽（OBW）
- `tx_phy`：1M / 2M 各测一遍
- `rx`：搭配信号源做 PER 灵敏度，看 `rxstats`
- 推荐频点：ch0 / ch19 / ch39（2402 / 2440 / 2480 MHz）

## 7. 构建与烧录

```bash
# 编译 RF 测试固件
cd firmware
make -f Makefile.rftest                 # 默认 VER=5

# 有线烧录(SWD,wlink)——绝不走 OTA
wlink flash build_rftest/immurok_CH592F_RFTEST.hex
```

- 量产构建路径（`make` / `ota/upload-ota.sh`）不受影响，不含任何 RFTEST 源文件。

## 8. 交付物

1. `feat/rf-test-firmware` 分支
2. 独立 RF 测试固件源码（`firmware/RFTEST/` + `firmware/Makefile.rftest`）
3. `firmware/RFTEST/PROTOCOL.md` —— 命令字与响应说明（含 -6→-5 偏差说明、手动测试清单）；实现时可复制一份到 `certificate/resource/` 配合认证资料
4. host 纯逻辑单元测试

## 9. 已确认的设计决策

- 架构：独立固件 target（量产零测试代码）
- 命令口：UART1 @ 115200 8N1
- 功率：保留截图 `tx 0-3` 四档 + 额外 `txpower <dbm>` 全表；-6dBm 映射 -5dBm 并注明
- 附加命令：`help` / `ver` / `id` / `freq` / `txpower` / `vbat` / `echo`
- 响应格式：`OK ...` / `ERR <reason>`，开机 `[FTM] ready`
- 说明文件位置：`firmware/RFTEST/PROTOCOL.md`
