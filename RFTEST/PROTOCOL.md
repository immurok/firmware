# immurok IK-1 RF 测试固件 — 命令字与响应说明

> **安全警告**
>
> 本固件（`immurok_CH592F_RFTEST.hex`）是**独立 RF 测试固件**，与量产 OTA 固件完全分离：
>
> - **必须通过有线 SWD（wlink）烧录**，绝不可签 OTA 包或通过 OTA 渠道下发给已出货设备。
> - 量产构建（`make` / `ota/upload-ota.sh`）不含任何本固件代码，不受影响。
> - **射频前端与量产件一致**：同一 VER=5 硬件、同一 PA / 匹配网络 / 天线，测量结果直接代表量产品。
>
> 适用受众：RF 认证实验室、产线 RF 校准操作员。

---

## 1. 连接方式

| 项目 | 参数 |
|------|------|
| 目标硬件 | CH592F **VER=5**（IK-1 Rev.3） |
| 命令端口 | 指纹 UART = **UART1**，PA8（RX）/ PA9（TX） |
| 波特率 | **115200 8N1** |
| 行终止符 | `\n`（固件同时兼容 `\r\n`，收到 `\r` 或 `\n` 均触发解析） |
| 命令回显 | **默认开启**（每条命令收到后原样回显一行，再回复结果；用 `echo off` 关闭） |
| 最大行长 | 63 字节（不含终止符）；超长行被丢弃并回复 `ERR line too long` |
| 指纹传感器 | 上电即将 PB12（SENSOR_EN）置 0 断电，固件运行期间保持断电 |

---

## 2. 上电横幅

设备上电 / 复位后，UART1 依次输出以下两行（每行以 `\r\n` 结尾，下同）：

```
[FTM] ready
immurok IK-1 RFTEST v1.6.0 HW=5
```

其中 `v1.6.0` 对应 `firmware/APP/include/version.h` 中的 `FW_VERSION_STRING`，版本号随代码更新可能变化；`HW=5` 固定代表 VER=5 硬件。

---

## 3. 全局响应规则

- **成功**：响应以 `OK ` 开头，后跟操作描述（详见各命令）。
- **错误**：响应以 `ERR ` 开头（见第 5 节）。
- `vbat` / `rxstats` / `id` / `ver` / `help` 等查询命令有自定义响应前缀（不以 `OK` 开头），见各命令说明。
- 每条响应以 `\r\n` 结尾。

---

## 4. 命令参考

### 4.1 tx — 连续调制发射（PRBS9 载荷）

**语法**

```
tx <ch> <level>
```

| 参数 | 类型 | 范围 | 说明 |
|------|------|------|------|
| `ch` | 整数 | 0–39 | 信道号；中心频率 = 2402 + ch×2 MHz |
| `level` | 整数 | 0–3 | 功率档（见下表） |

功率档对照：

| level | 请求 dBm | 实际映射 | 备注 |
|-------|----------|----------|------|
| 0 | 0 dBm | 0 dBm | 精确 |
| 1 | −3 dBm | −3 dBm | 精确 |
| 2 | −6 dBm | **−5 dBm** | ⚠ 芯片无 −6 dBm 档，取最近邻 −5 dBm（偏差 +1 dBm） |
| 3 | +3 dBm | +3 dBm | 精确 |

- 载荷固定为 PRBS9，包长 37 字节（BLE DTM 惯例）。
- 发射连续循环，直到收到 `stop` / 下一条发射命令 / `reset`。
- 当前 PHY（1M 或 2M）由 `tx_phy` 设置，不改变功率档。

**响应示例**

```
OK tx ch=0 pwr=0dBm phy=1M payload=PRBS9
OK tx ch=19 pwr=-5dBm phy=2M payload=PRBS9
```

> 注：`level=2` 时，响应中 `pwr=` 显示的是实际映射后的 dBm（`-5dBm`），**不是**请求值 `-6dBm`。

---

### 4.2 txcw — 未调制 CW 载波

**语法**

```
txcw <ch>
```

- 通过 `LL_SingleChannel(ch)` 发射未调制连续波（CW）。
- 功率为最近一次 `tx` 或 `txpower` 设置的值（默认 0 dBm）。
- 持续发射，直到收到 `stop`。

**响应示例**

```
OK txcw ch=19 freq=2440MHz
OK txcw ch=0 freq=2402MHz
OK txcw ch=39 freq=2480MHz
```

---

### 4.3 tx\_payload — 指定载荷连续发射

**语法**

```
tx_payload <ch> <pattern>
```

| pattern | 载荷内容 | 说明 |
|---------|----------|------|
| 0 | PRBS9 | 伪随机序列（x⁹+x⁵+1，BLE DTM 标准 LFSR） |
| 1 | 0x0F | 固定字节 `0x0F` 填充 |
| 2 | 0x55 | 固定字节 `0x55` 填充 |
| 3 | PRBS15 | 伪随机序列（x¹⁵+x¹⁴+1） |
| 4 | all-1 | 固定字节 `0xFF` 填充 |
| 5 | all-0 | 固定字节 `0x00` 填充 |
| 6 | 0xF0 | 固定字节 `0xF0` 填充 |
| 7 | 0xAA | 固定字节 `0xAA` 填充 |

- 发射功率使用最近一次 `tx` 或 `txpower` 命令设置的值；未设置时默认 0 dBm（`ftm_init` 设定）。
- 包长 37 字节，连续循环，直到 `stop`。

**响应示例**（`pattern` 名称字段与源码中 `names[]` 数组完全一致）

```
OK tx_payload ch=39 pattern=PRBS9
OK tx_payload ch=0 pattern=0x0F
OK tx_payload ch=19 pattern=0x55
OK tx_payload ch=0 pattern=PRBS15
OK tx_payload ch=0 pattern=all-1
OK tx_payload ch=0 pattern=all-0
OK tx_payload ch=0 pattern=0xF0
OK tx_payload ch=0 pattern=0xAA
```

---

### 4.4 tx\_phy — 切换 PHY

**语法**

```
tx_phy <0|1>
```

| 参数 | 含义 |
|------|------|
| 0 | LE 1M PHY |
| 1 | LE 2M PHY |

- PHY 设置影响后续所有 `tx` / `tx_payload` / `rx` 命令；`txcw` 通过 `LL_SingleChannel` 不受此设置影响（CW 不涉及 PHY 调制）。
- 上电默认 1M。

**响应**

```
OK phy=1M
OK phy=2M
```

---

### 4.5 rx — 接收模式

**语法**

```
rx <ch>
```

- 进入接收模式，清零包计数与 CRC 错误计数。
- 回调中累计：`rsr==0` → 正确包（`pkt`）；`rsr!=0` → CRC 错误包（`crc_err`）。
- 收到 `stop` 后自动打印 `rxstats`（见 4.6）。

**响应**

```
OK rx ch=0 listening
```

---

### 4.6 stop — 停止发射/接收

**语法**

```
stop
```

- 调用 `RF_Shut()` 停止当前操作，熄灭 LED。
- **若当前处于接收模式**，在 `OK stop` 之后追加一行 `rxstats`：

```
OK stop
rxstats ch=0 pkt=1234 crc_err=2
```

- 若当前处于发射或空闲模式，只输出：

```
OK stop
```

`rxstats` 行格式（字段固定，无 `OK` 前缀）：

```
rxstats ch=<信道> pkt=<正确包数> crc_err=<CRC错误包数>
```

---

### 4.7 reset — 复位

**语法**

```
reset
```

- 输出响应后立即执行软件复位（`SYS_ResetExecute()`），设备重启并重新输出上电横幅。

**响应**

```
OK reset
```

---

### 4.8 help — 命令列表 / 单条命令详细用法

**语法**

```
help
help <cmd>
```

**`help`（无参数）**

输出命令列表共四行（第四行为提示行）：

```
cmds: tx <ch> <0-3> | txcw <ch> | tx_payload <ch> <0-7>
      tx_phy <0|1> | rx <ch> | stop | reset
      freq <khz> | txpower <dbm> | vbat | ver | id | echo <on|off>
      type 'help <cmd>' for detailed usage
```

**`help <cmd>`（带命令名）**

打印该命令的详细用法（语法、参数范围、示例、响应格式），共 1–3 行。
所有 14 条命令均支持：`tx txcw tx_payload tx_phy rx stop reset help ver id freq txpower vbat echo`。

示例：

```
> help tx
tx <ch> <level>  ch=0-39  level=0-3
  level: 0=0dBm  1=-3dBm  2=-5dBm(req -6)  3=+3dBm
  PRBS9 payload, loops until stop.  e.g. tx 19 0

> help rx
rx <ch>  ch=0-39  start receive, clears pkt/crc_err counters
  send stop to end; rxstats printed automatically after stop
  e.g. rx 0  -> OK rx ch=0 listening
```

**`help <unknown>`**

如果 `<cmd>` 不是已知命令名，响应：

```
ERR no such command (try: help)
```

---

### 4.9 ver — 固件版本

**语法**

```
ver
```

输出格式（无 `OK` 前缀）：

```
immurok IK-1 RFTEST v<版本> build=0x<十六进制构建号> HW=5 phy=<1M|2M>
```

实际示例：

```
immurok IK-1 RFTEST v1.6.0 build=0x1A3F HW=5 phy=1M
```

- `版本` = `FW_VERSION_STRING`（当前 `1.6.0`）。
- `build=0x<N>` = Makefile 注入的 git short hash（`FW_BUILD_NUMBER`，`%X` 格式）；IDE 直接编译时为 `0x0`。
- `phy=` 反映当前 `tx_phy` 设置。

> 设计文档示例中的 `build=20260616`（日期格式）与实际实现不符。**实际固件输出 `build=0x<十六进制>`**。

---

### 4.10 id — 芯片 MAC 地址

**语法**

```
id
```

输出格式（无 `OK` 前缀，字节顺序：mac[5]:mac[4]:…:mac[0]，即网络序 MSB 在前）：

```
id MAC=AA:BB:CC:DD:EE:FF
```

用于实验室记录被测件身份，每颗芯片唯一。

---

### 4.11 freq — 精确频率发射

**语法**

```
freq <khz>
```

| 参数 | 类型 | 范围 | 说明 |
|------|------|------|------|
| `khz` | 整数 | 2400000–2483500 | 中心频率（kHz） |

- 使用 `LLE_MODE_EX_CHANNEL` 模式精确指定中心频率，用于测量带边/杂散。
- 载荷固定为 PRBS9，包长 37 字节，连续发射。
- 发射功率使用当前设定值（默认 0 dBm）。

**响应**

```
OK freq=2402000kHz
OK freq=2483500kHz
```

---

### 4.12 txpower — 直接设置发射功率

**语法**

```
txpower <dbm>
```

- 参数为绝对功率（dBm），可为负值（如 `txpower -8`）。
- 映射到芯片最近可用档（见下表），**超出范围钳位到 [−20, +4]**。
- 设置立即生效，影响后续所有发射操作（包括 `tx_payload`、`freq`）。
- 上电默认 0 dBm（`ftm_init` 内设定）。

CH592F 功率档完整表：

| 输入 dBm | 实际输出 | 说明 |
|----------|----------|------|
| ≤−20 | −20 dBm | 钳位下限 |
| −20 | −20 dBm | |
| −15 | −15 dBm | |
| −10 | −10 dBm | |
| −8 | −8 dBm | |
| −6 | **−5 dBm** | ⚠ 无 −6 dBm 档，取最近邻 −5 dBm |
| −5 | −5 dBm | |
| −3 | −3 dBm | |
| −1 | −1 dBm | |
| 0 | 0 dBm | |
| 1 | 1 dBm | |
| 2 | 2 dBm | |
| 3 | 3 dBm | |
| 4 | 4 dBm | |
| ≥5 | **4 dBm** | 钳位上限 |

非精确档（如 −7、−4、−2）取绝对差最小的邻近档。

**响应**（显示实际编程到硬件的 dBm，即最近邻映射后的值）

```
OK txpower=-8dBm
OK txpower=0dBm
OK txpower=4dBm
OK txpower=-5dBm    ← txpower -6 时：无 -6 dBm 档，映射到 -5 dBm
```

---

### 4.13 vbat — 读取电池电压

**语法**

```
vbat
```

- 读取 PA14（AIN4，VER=5 为 1/4 分压电阻网络 R2=3MΩ/R3=1MΩ）的 ADC 值，按粗略公式换算（需实测校准）：
  ```
  mv = adc × (2100 × 4) / 4096   （Vref ≈ 2.1V，12-bit ADC）
  ```
- 响应同时输出换算电压（mV）与原始 ADC 值（无 `OK` 前缀）：

```
vbat=4153mV (raw=2013)
```

> 设计文档示例中的 `vbat=4096mV` 仅为说明格式，**实际固件输出包含 `(raw=<ADC原始值>)` 字段**。当前换算系数为粗略估值，需在真实硬件上校准。

---

### 4.14 echo — 命令回显开关

**语法**

```
echo <on|off>
```

- `on`：每条命令收到后原样回显一行，再输出结果（默认）。
- `off`：关闭回显，仅输出结果，适用于脚本自动化测试。

**响应**

```
OK echo=on
OK echo=off
```

---

## 5. 错误响应

| 触发场景 | 响应字符串 |
|----------|------------|
| 未知命令（含空行） | `ERR unknown cmd` |
| 参数数量不足或无法解析 | `ERR bad args` |
| 信道越界（不在 0–39） | `ERR bad channel (0-39)` |
| tx 功率档越界（不在 0–3） | `ERR bad power (0-3)` |
| tx\_payload pattern 越界（不在 0–7） | `ERR bad pattern (0-7)` |
| tx\_phy 参数非 0/1 | `ERR bad phy (0\|1)` |
| freq 频率越界（不在 2400000–2483500 kHz） | `ERR bad freq (2400000-2483500)` |
| 行超长（输入超过 63 字节未见换行符） | `ERR line too long` |

所有错误响应均以 `ERR ` 开头，后跟固定说明字符串（大小写、标点与上表完全一致）。

---

## 6. 手动实验室测试清单

以下为 RF 认证送测时建议的最小测试步骤，推荐频点为 **ch0（2402 MHz）/ ch19（2440 MHz）/ ch39（2480 MHz）**，覆盖频段低/中/高三点。

### 6.1 准备

1. 通过 SWD 有线烧录 `immurok_CH592F_RFTEST.hex`，确认串口收到上电横幅。
2. 发送 `ver`，记录固件版本与构建号，存入认证记录。
3. 发送 `id`，记录 MAC 地址，对应被测件编号。

### 6.2 输出功率测量（频谱仪 / 功率计）

目的：确认各功率档实际 EIRP，验证最大输出功率符合认证限值。

```
tx 0 0      # ch0，level 0 = 0 dBm，读取功率计示数
tx 0 3      # ch0，level 3 = +3 dBm，读取功率计示数
tx 19 0     # ch19，0 dBm
tx 39 0     # ch39，0 dBm
stop        # 停止发射
```

- 每次发射后等待功率计稳定再读数。
- 记录实测值与标称值的偏差，偏差建议 ≤±2 dBm。
- 注：`level=2` 实际映射为 −5 dBm（非 −6 dBm，偏差 +1 dBm，属已知行为）。

也可使用 `txpower` 直接设置特定 dBm 值：

```
txpower 4   # 最大功率 +4 dBm
tx 0 0      # 以当前功率在 ch0 发射
txpower 0   # 恢复 0 dBm
```

### 6.3 频率误差 / CW 测量（频谱仪）

目的：测量频率误差（ppm）、载波泄漏、谐波杂散。

```
txcw 0      # 2402 MHz CW
```

频谱仪在 2402 MHz 观察：

- 载波频率误差（与标称 2402.000 MHz 的偏差，换算 ppm）
- 谐波：在 4804 MHz / 7206 MHz 观察谐波功率

依次测量 ch0 / ch19 / ch39：

```
txcw 0      # 2402 MHz
stop
txcw 19     # 2440 MHz
stop
txcw 39     # 2480 MHz
stop
```

### 6.4 调制精度 / 占用带宽（频谱仪，OBW 功能）

目的：测量 OBW、调制指数（ΔF₁ / ΔF₂）等。

```
tx_phy 0            # 确保 1M PHY
tx_payload 0 2      # ch0，0x55（01010101 交替，利于调制精度测量）
stop
tx_payload 19 0     # ch19，PRBS9（推荐用于 OBW 测量）
stop
tx_payload 39 0     # ch39，PRBS9
stop
```

### 6.5 2M PHY 测量

切换到 2M PHY 重复上述功率与调制测量：

```
tx_phy 1
tx 0 0
stop
tx_payload 0 0
stop
tx_phy 0            # 测完恢复 1M
```

### 6.6 接收灵敏度 / PER（信号源 + rxstats）

目的：测量 BLE 1M / 2M 接收灵敏度（PER 30.8% 对应灵敏度门限）。

1. 连接校准信号源，输出标准 BLE 1M PRBS9 包，目标频点（如 2402 MHz），包长 37 字节。
2. 执行：

```
rx 0
```

3. 信号源发射 1000 包后发送：

```
stop
```

设备输出：

```
OK stop
rxstats ch=0 pkt=<正确包数> crc_err=<CRC错误包数>
```

4. PER = `crc_err / (pkt + crc_err) × 100%`。逐步降低信号源输出功率，找到 PER=30.8% 对应的输入功率 = 灵敏度。
5. 依次测 ch0 / ch19 / ch39，1M 与 2M PHY。

### 6.7 完成后恢复

```
reset
```

设备重启，UART 输出上电横幅，确认固件运行正常后断开串口。

---

## 7. 烧录说明

```bash
# 编译 RF 测试固件（在 firmware/ 目录下）
make -f Makefile.rftest

# 有线烧录（SWD，wlink）
wlink flash build_rftest/immurok_CH592F_RFTEST.hex
```

**⚠ 本固件仅用于有线烧录，严禁签 OTA 包、严禁通过 OTA 渠道下发到已出货设备。**

---

## 8. 版本对应说明

| 认证测试固件 | 对应量产固件 | 差异说明 |
|-------------|-------------|----------|
| `RFTEST v1.6.0` | 量产 `v1.6.0`（feat/rf-test-firmware 分支） | 控制接口不同（UART 命令替代 BLE HID），射频前端、PA、天线、VER=5 引脚配置完全一致 |

射频特性（载波频率、输出功率、调制、杂散、灵敏度）由硬件决定，与固件控制层无关，测试结果直接适用于量产品。
