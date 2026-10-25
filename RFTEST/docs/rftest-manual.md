immurok IK-1 射频测试固件（RFTEST）使用说明

本手册面向射频认证实验室与产线测试人员，说明 immurok IK-1（CH592F，VER=5 硬件）**独立射频测试固件**的串口命令字与推荐测试流程。

---

## 1. 重要须知

- 本固件是**独立的射频测试固件**，与量产固件完全分离；量产固件内不含任何测试代码。
- 射频前端（PA、匹配网络、天线、VER=5 硬件）与量产件**完全一致**，因此测量结果可代表量产产品。
- 上电后指纹传感器电源被关闭（PB12 / SENSOR_EN 拉低），测试期间指纹模块不工作。
- 认证时请记录本固件版本号（`ver` 命令）与被测件 MAC（`id` 命令），并注明"测试固件与量产固件仅测试控制代码不同、射频特性一致"。

---

## 2. 连接与串口参数

| 项目 | 值 |
|------|----|
| 命令口 | 指纹 UART = **UART1** |
| 接线 | **红线：TX**、**白线：RX**、**黑线：GND** |
| 波特率 | **115200**，数据位 8，无校验，停止位 1（8N1） |
| 行结束符 | `\n`（换行/回车），兼容 `\r\n` |
| 命令回显 | 默认开启，可用 `echo off` 关闭 |

接线：红线（TX）、白线（RX）、黑线（GND）。与 USB-UART 适配器对接时 TX/RX 交叉（设备红线 TX → 适配器 RX，设备白线 RX → 适配器 TX，黑线对接 GND）。打开串口终端（115200 8N1）。

---

## 3. 上电表现

设备上电（或 `reset` 后）会在命令口打印两行横幅：

```
[FTM] ready
immurok IK-1 RFTEST v1.6.0 HW=5
```

随后进入命令等待状态。看到以上两行即表示命令口已就绪。

---

## 4. 命令字总览

每条命令以 `\n` 结尾，参数以空格分隔。成功返回 `OK ...`，失败返回 `ERR <原因>`。

| 命令 | 语法 | 作用 |
|------|------|------|
| tx | `tx <ch> <level>` | 在指定信道连续**调制**发射（PRBS9 载荷），按功率档 |
| txcw | `txcw <ch>` | 在指定信道发射**未调制 CW 载波** |
| tx_payload | `tx_payload <ch> <pattern>` | 按指定载荷图案连续调制发射 |
| tx_phy | `tx_phy <0\|1>` | 选择后续 tx / tx_payload 的 PHY（0=1M，1=2M） |
| rx | `rx <ch>` | 进入接收模式，统计收包数与 CRC 错误 |
| stop | `stop` | 停止当前发射/接收（若刚在 rx，附带打印 rxstats） |
| reset | `reset` | 重启设备，退出测试模式 |
| help | `help` / `help <命令>` | 命令清单 / 单条命令详细用法 |
| ver | `ver` | 固件版本、构建号、硬件版本、当前 PHY |
| id | `id` | 芯片 MAC 地址（登记被测件用） |
| freq | `freq <khz>` | 按精确频率连续发射（测频带边沿/杂散） |
| txpower | `txpower <dbm>` | 设置绝对发射功率（映射到最近硬件档） |
| vbat | `vbat` | 读取电池电压（粗略，未标定，仅供参考） |
| echo | `echo <on\|off>` | 命令回显开关 |

---

## 5. 命令详解

### 5.1 tx —— 连续调制发射

- **语法**：`tx <ch> <level>`，`ch` = 0–39，`level` = 0–3
- **功率档**：

| level | 请求值 | 实际发射 | 说明 |
|-------|--------|----------|------|
| 0 | 0 dBm | 0 dBm | |
| 1 | −3 dBm | −3 dBm | |
| 2 | −6 dBm | **−5 dBm** | 芯片无 −6 dBm 档，取最近邻 −5 dBm（偏差 +1 dBm，已知行为） |
| 3 | +3 dBm | +3 dBm | |

- **载荷**：PRBS9，持续背靠背发射，直到 `stop`。
- **示例 / 响应**：

```
tx 19 0
OK tx ch=19 pwr=0dBm phy=1M payload=PRBS9
```

> 响应里的 `pwr=` 显示的是**实际编程到硬件的功率**（最近邻映射后的值），故 `tx 19 2` 会显示 `pwr=-5dBm`。

### 5.2 txcw —— 未调制 CW 载波

- **语法**：`txcw <ch>`，`ch` = 0–39
- **作用**：单频点纯载波，用于频率误差/频偏、载波泄漏、谐波杂散测量。
- **示例 / 响应**：

```
txcw 19
OK txcw ch=19 freq=2440MHz
```

### 5.3 tx_payload —— 指定载荷发射

- **语法**：`tx_payload <ch> <pattern>`，`ch` = 0–39，`pattern` = 0–7
- **载荷图案编号**：

| pattern | 内容 | pattern | 内容 |
|---------|------|---------|------|
| 0 | PRBS9 | 4 | 全 1（0xFF） |
| 1 | 0x0F | 5 | 全 0（0x00） |
| 2 | 0x55（交替） | 6 | 0xF0 |
| 3 | PRBS15 | 7 | 0xAA |

- **示例 / 响应**：

```
tx_payload 39 2
OK tx_payload ch=39 pattern=0x55
```

### 5.4 tx_phy —— 选择 PHY

- **语法**：`tx_phy <0|1>`，0 = LE 1M，1 = LE 2M
- **作用**：设置后续 `tx` / `tx_payload` 使用的 PHY。**对下一条发射命令生效**。
- **示例 / 响应**：

```
tx_phy 1
OK phy=2M
```

### 5.5 rx —— 接收 / 收包统计

- **语法**：`rx <ch>`，`ch` = 0–39
- **作用**：进入接收模式，并**清零**收包计数与 CRC 错误计数；持续累计直到 `stop`。
- **示例 / 响应**：

```
rx 0
OK rx ch=0 listening
```

`stop` 后会打印统计：

```
rxstats ch=0 pkt=1234 crc_err=2
```

误包率 PER ≈ `crc_err / (pkt + crc_err)`。

### 5.6 stop —— 停止收发

- **语法**：`stop`
- **作用**：停止任何进行中的发射/接收。若停止的是接收，会附带打印 `rxstats`。
- **示例 / 响应**：

```
stop
OK stop
rxstats ch=0 pkt=1234 crc_err=2
```

### 5.7 reset —— 重启

```
reset
OK reset
```

随后设备复位，重新打印 `[FTM] ready` 横幅。

### 5.8 help —— 帮助

- `help`：打印命令清单，末尾提示 `type 'help <cmd>' for detailed usage`。
- `help <命令>`：打印该命令的详细用法，例如：

```
help tx
tx <ch> <level>  ch=0-39  level=0-3
  level: 0=0dBm  1=-3dBm  2=-5dBm(req -6)  3=+3dBm
  PRBS9 payload, loops until stop.  e.g. tx 19 0
```

- `help <未知命令>`：返回 `ERR no such command (try: help)`。

### 5.9 ver —— 版本信息

```
ver
immurok IK-1 RFTEST v1.6.0 build=0x1954 HW=5 phy=1M
```

（`build=` 为 git 短哈希，认证时记录此行。）

### 5.10 id —— 芯片 MAC

```
id
id MAC=AA:BB:CC:DD:EE:FF
```

### 5.11 freq —— 精确频率发射

- **语法**：`freq <khz>`，范围 **2400000–2483500** kHz
- **作用**：按精确频率连续发射 PRBS9，用于测频带边沿、信道栅格外的杂散等。
- **示例 / 响应**：

```
freq 2402000
OK freq=2402000kHz
```

### 5.12 txpower —— 绝对功率设置

- **语法**：`txpower <dbm>`，范围钳位到 **[−20, +4] dBm**，取最近硬件档。
- **可用硬件档**（约 ±2 dBm 精度）：−20 / −15 / −10 / −8 / −5 / −3 / −1 / 0 / +1 / +2 / +3 / +4 dBm。
- **作用**：设置后续发射功率（比 `tx` 的 0–3 档更细）。响应回显映射后的**实际**功率。
- **示例 / 响应**：

```
txpower -8
OK txpower=-8dBm
txpower -6
OK txpower=-5dBm
```

### 5.13 vbat —— 电池电压

```
vbat
vbat=4096mV (raw=2013)
```

> ⚠️ 该换算系数尚未实测标定，仅供大致参考，不作为认证测量项。

### 5.14 echo —— 回显开关

```
echo off
OK echo=off
```

---

## 6. 错误响应表

| 响应 | 触发条件 |
|------|----------|
| `ERR bad channel (0-39)` | 信道超出 0–39 |
| `ERR bad power (0-3)` | `tx` 的功率档超出 0–3 |
| `ERR bad pattern (0-7)` | `tx_payload` 图案超出 0–7 |
| `ERR bad phy (0\|1)` | `tx_phy` 参数非 0/1 |
| `ERR bad freq (2400000-2483500)` | `freq` 超出范围 |
| `ERR bad args` | 参数缺失或格式错误 |
| `ERR unknown cmd` | 未知命令 |
| `ERR no such command (try: help)` | `help <未知命令>` |
| `ERR line too long` | 单行命令超过 64 字节 |

---

## 7. 推荐测试流程

> 通用约定：发射类命令（`tx`/`txcw`/`tx_payload`/`freq`）均为**持续发射**，切换频点/功率/图案前请先 `stop`（直接发新命令也会自动停上一个，但建议显式 `stop`）。推荐测试频点：**ch0 = 2402 MHz / ch19 = 2440 MHz / ch39 = 2480 MHz**（频段低/中/高）。

### 7.1 第一步：冒烟自检（无需仪器）

确认命令口与解析正常：

```
help
ver
id
vbat
bogus        -> ERR unknown cmd
tx 99 0      -> ERR bad channel (0-39)
```

### 7.2 第二步：未调制载波（频率误差 / 载波泄漏 / 谐波杂散）—— 频谱仪

```
txcw 0       -> 2402MHz 一根纯净载波
stop
txcw 19      -> 2440MHz
stop
txcw 39      -> 2480MHz
stop
```

### 7.3 第三步：输出功率（各功率档）—— 功率计 / 频谱仪

```
tx 19 0      -> 功率计读 ≈ 0dBm
stop
tx 19 1      -> ≈ -3dBm
stop
tx 19 2      -> ≈ -5dBm（请求 -6，硬件最近档）
stop
tx 19 3      -> ≈ +3dBm
stop
```

更细的功率扫描用 `txpower`：

```
txpower -8
tx 19 0
stop
```

### 7.4 第四步：调制 / 占用带宽（OBW）—— 频谱仪

```
tx_payload 19 0   -> PRBS9（认证常用）
stop
tx_payload 19 2   -> 0x55 交替谱线
stop
```

### 7.5 第五步：1M / 2M PHY 各测一遍

```
tx_phy 1
tx 19 0           -> 响应显示 phy=2M
stop
tx_phy 0          -> 切回 1M
```

### 7.6 第六步：接收灵敏度 / PER —— 信号源或第二台设备

最简方法用两台本固件设备：

- 设备 A（发射端）：`tx_payload 19 0`（持续发 PRBS9）
- 设备 B（接收端）：

```
rx 19        -> OK rx ch=19 listening
   （让发射端发已知时长）
stop         -> OK stop
                rxstats ch=19 pkt=1234 crc_err=2
```

由 `rxstats` 计算 PER = `crc_err / (pkt + crc_err)`。

### 7.7 频带边沿 / 杂散补充

```
freq 2400000   -> 频段下边沿
stop
freq 2483500   -> 频段上边沿
stop
```

### 7.8 收尾

```
reset          -> OK reset，设备重启回到 [FTM] ready
```

---

## 8. 测量项对照

| 测量项 | 使用命令 | 仪器 |
|--------|----------|------|
| 输出功率 / 各功率档 | `tx` / `txpower` | 功率计 / 频谱仪 |
| 频率误差 / 频偏 / 载波泄漏 | `txcw` | 频谱仪 |
| 谐波 / 杂散辐射 | `txcw` / `freq` | 频谱仪（含频带边沿） |
| 占用带宽 OBW / 调制特性 | `tx_payload` | 频谱仪 |
| 1M / 2M 物理层 | `tx_phy` + `tx` | 频谱仪 |
| 接收灵敏度 / PER | `rx` + 信号源 | 信号源 / 第二台设备 |

---

*文档版本对应固件 RFTEST v1.6.0。命令与响应以设备 `help` 输出为准。*
