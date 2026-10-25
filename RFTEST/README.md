# immurok IK-1 射频测试固件（RFTEST）

认证实验室 / 产线用的**独立射频测试固件**：与量产固件完全分离，有线烧录（不走 OTA），
通过指纹 UART（UART1，PA8/PA9，115200 8N1）接收定频发射 / 接收等命令。
射频前端与量产件一致，测量结果可代表量产产品。

原开发在 `feat/rf-test-firmware` 分支（2026-06-16），2026-10-19 整理为本目录并入 main。

## 目录

| 文件 | 说明 |
|------|------|
| `RFTEST使用说明.pdf` | **中文使用说明**（接线、命令字详解、推荐测试流程）—— 给实验室/产线的文档 |
| `PROTOCOL.md` | 串口命令字与响应格式说明 |
| `rftest_main.c` / `ftm.c` / `ftm.h` | 固件入口 + RF 状态机（TX/CW/RX/功率/PHY） |
| `ftm_parse.c` / `ftm_parse.h` | 命令行解析、功率映射、载荷生成（纯逻辑，可在主机上单测） |
| `Makefile` | 固件构建（在本目录执行 `make`） |
| `upload-rftest.sh` | wlink 烧录，失败自动重试 3 次 |
| `test/` | 主机端纯逻辑单测（`cd test && make test`） |
| `docs/rftest-manual.md` | PDF 的 Markdown 源 |
| `docs/build_rftest_manual_pdf.py` | 由 Markdown 重新生成 PDF（需 `markdown` + `weasyprint`） |
| `docs/design.md` / `docs/plan.md` | 设计文档与实现计划 |

## 构建与烧录

```bash
cd firmware/RFTEST
make                 # 产物 build/immurok_CH592F_RFTEST.{elf,hex,bin}
./upload-rftest.sh   # wlink 有线烧录
```

依赖：`../SDK`（CH592 EVT，不入 git）、`../APP/include/version.h`、`../Ld/Link.ld`，
工具链路径与量产固件一致（`TOOLCHAIN_PATH`，默认 `/opt/riscv-wch-gcc`）。
`HW_VER` 默认 5（VER5/VER6 引脚相同），仅有线烧录，**勿走 OTA**。

相关：`certificate/resource/08_bt_frequency_sop.md` 是给实验室的英文定频测试 SOP。
