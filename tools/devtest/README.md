# devtest — 真机自动化测试

对一台真实 CH592F 设备跑固件功能完整性 + 边界/异常处理测试，需要操作员在场配合
触摸、按键、拨电源、开盖等动作。被测对象是**固件**，macOS App 只是驱动手段。

设计文档：`docs/superpowers/specs/2026-09-20-device-e2e-test-design.md`（协议、
判据、阶段划分的完整设计）。**在设备旁边配合的人看 `OPERATOR.md`**：每一段要做什么、
卡住了怎么救、跑完怎么收尾。

## 准备

1. 部署带测试钩子的构建：
   ```bash
   app-macos/build-deploy.sh -a -s -t
   ```
   `TEST:*` 控制面只在这个构建里编译进去（`-Xswiftc -DTEST_HOOKS`），发行构建
   （不带 `-t`）不含这段代码。`-t` 只在 `build_app` 里生效，必须跟 `-a` 一起传，
   单传 `-t` 不会触发编译。测完换回正常构建：
   ```bash
   app-macos/build-deploy.sh -a -s
   ```
   （`build-deploy.sh` 现在固定给 `swift build` 加 `--build-system native`。）
2. 可选，有 USB 数据线时：`ota/upload-ota.sh release-debug` 烧一份有日志的固件，
   runner 会从 `/dev/cu.usbmodem*` 抄设备日志查复位（栈探针、WDT、启动 banner）。
   没有 USB 日志口时用例仍能跑，只是复位类判据会降级。
3. `pip3 install cryptography`（SSH 签名验证、OTA 包签名用）。

## 跑

```bash
cd firmware/tools/devtest
./devtest.py --list                       # 列用例（D=破坏性 L=耗时 R=记录基线 human=需要操作员）
./devtest.py --phase p1 p2                # 只跑指定阶段
./devtest.py --record --phase p2          # 首次给 expect="record" 的用例定基线
./devtest.py --imfw firmware/dist/x.imfw  # 全跑（P8 需要 --imfw）
./devtest.py --resume                     # 出厂重置/重配后接着跑
./devtest.py --only P3-05 P8-01           # 只跑指定几条
```

完整参数（见 `devtest.py parse_args`）：

| 参数 | 作用 |
|---|---|
| `--phase p0 p1 …` | 只跑指定阶段（`p0`..`p9`） |
| `--only ID …` | 只跑指定用例 ID |
| `--list` | 列出全部用例（配合 `--long` 显示耗时用例） |
| `--record` | 把 `expect="record"` 用例的实际行为写进 `baseline.json` |
| `--resume` | 从 `reports/.state.json` 记录的断点继续（出厂重置/重配后用）；P0 永远重跑 |
| `--long` | 包含耗时用例（锁屏 30 分钟、写满密钥库等） |
| `--yes` | 破坏性用例不再逐项确认（进入 P9 阶段时仍会单独确认一次，无法跳过） |
| `--imfw <path>` | 当前版本的合法 `.imfw`（P8 OTA 用例需要） |
| `--socket <path>` | 覆盖 `cli.sock` 路径 |
| `--no-uart` | 不抓 USB 设备日志 |
| `--reports <dir>` | 报告输出目录（默认 `reports/`） |
| `--baseline <path>` | 基线文件路径（默认 `baseline.json`） |

## 阶段

按破坏性升序，`--phase` 用小写 `p0`..`p9`：

| 阶段 | 内容 | 用例数 |
|---|---|---|
| P0 | 前置检查（App/设备在线、已配对、USB 日志、电池、现场条件、sudo PAM） | 6 |
| P1 | 只读状态命令的格式与合理性 | 6 |
| P2 | 协议边界（无人，畸形帧/越界参数/命令风暴） | 21 |
| P3 | 指纹门（正常/错指/超时/取消/背靠背/并发/冷却/长按/端到端 sudo） | 12 |
| P4 | 指纹登记（完整流程/取消/断链/超时/越界槽/切换指纹专用槽） | 8 |
| P5 | 密钥库（SSH 签名/OTP/API secret/边界/持久化/`imk get` 端到端） | 6 |
| P6 | 双机切换（需要第二台电脑，否则整段 SKIP） | 5 |
| P7 | 连接层（断链重连/深睡唤醒/长时间锁屏稳定性） | 3 |
| P8 | OTA（需要 `--imfw`：同版本重刷/坏签名/低 SVN/中断/断电/IAP 边界） | 7 |
| P9 | 破坏性收尾（出厂重置/配对边界/防拆），逐项 y/n 确认 | 11 |

以上计数用 `./devtest.py --list --long` 核对（该命令只读用例定义，不连接
socket，可以在没有设备时跑）。

## 已知限制

- `TEST:ENROLL` 期间打开 App 的设置窗口会顶掉钩子挂的登记回调——App 自身 UI
  （FingerprintViewModel 等）也会无条件覆盖同一个闭包。测试期间不要开设置窗口。
- 被动 0x21 匹配会触发 App 的"预发回车"（收到指纹信号但没有待处理 PAM 请求时
  先发回车激活认证对话框），这个回车可能落到跑 devtest 的终端窗口里。
- `FPMATCH:<id>` 事件只由独立的 0x21 通知派生；AUTH 门通过时固件只回一字节
  `RX:00`，不会有 0x21，`TEST:GATE` 的判据看不到 FPMATCH。
- `TEST:RX:SUB` 的每条订阅各占一个 GCD 线程，不要在同一进程里无节制地重复订阅。
- `TEST:OTA_RAW:<hex>` 可选第三段覆盖默认 5000ms 超时（`:timeout_ms`），P8-06 的
  END 帧用 15000ms——真机在没发任何 PROM 数据时判定拒绝比正常慢，默认超时偶发
  压线误报 `OK:NORX`。

## 报告 / 基线

报告写到 `reports/`（不入 git）：`<时间戳>.md`（人看）+ `.json`（机器比对）。
`baseline.json`（入 git）是 `expect="record"` 用例的期望值；人工确认某条是固件
bug 后，把用例的 `expect="record"` 改成明确值，就成了回归判据。

## 单元测试

```bash
python3 -m unittest discover -s tests -v
```

App 侧还有一份对 `TestRequest.parse` 的单元测试
`app-macos/Tests/PamMacTests/TestHooksParseTests.swift`；它跟 `TestHooks.swift`
本体一样整份包在 `#if TEST_HOOKS` 里，只有带上编译标志才会跑：

```bash
swift test -Xswiftc -DTEST_HOOKS
```

普通 `swift test`（没有这个标志）看不到这份测试，不代表它被跳过或坏了。
