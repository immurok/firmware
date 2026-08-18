# immurok Firmware (CH592F)

Main application firmware for the immurok device, running on the WCH CH592F RISC-V BLE MCU.

## Repository Layout

The build and flash scripts expect the [`firmware`](https://github.com/immurok/firmware) and [`ota`](https://github.com/immurok/ota) repositories cloned side by side, with exactly these directory names:

```
<workdir>/
├── firmware/     ← this repository
└── ota/          ← build, packaging and flash scripts
```

Cross-repo paths (`../firmware`, `../ota`) are resolved relative to each script's own location, so any parent directory works.

## Prerequisites

- **Toolchain**: RISC-V GCC for WCH (MounRiver or standalone)
- **SDK**: WCH CH592 EVT SDK (see below)
- **Python**: `pip3 install cryptography` (OTA key generation and packaging)
- **Flash tool**: [`wchisp`](https://github.com/ch32-rs/wchisp) for serial ISP, or [`wlink`](https://github.com/ch32-rs/wlink) with a WCH-LinkE — see [Flashing](#flashing)

## SDK Setup

The firmware depends on the official WCH CH592 SDK, which is not included in this repository.

### Download

Get the SDK from the [WCH official site](https://www.wch.cn/downloads/CH592EVT_ZIP.html) or the [GitHub mirror](https://github.com/openwch/ch592).

### Install

Extract the SDK so that the directory structure looks like this:

```
firmware/
├── SDK/                          ← extract here
│   ├── EVT/
│   │   └── EXAM/
│   │       ├── BLE/              ← BLE stack and HAL
│   │       │   ├── HAL/
│   │       │   ├── LIB/
│   │       │   └── ...
│   │       └── SRC/              ← peripheral drivers
│   │           ├── Startup/
│   │           ├── StdPeriphDriver/
│   │           └── ...
│   ├── Datasheet/
│   └── README.md
├── APP/                          ← application source code
├── Makefile
└── ...
```

If you cloned the GitHub mirror:

```bash
cd firmware
git clone https://github.com/openwch/ch592.git SDK
```

### Verify

The Makefile expects the SDK at `SDK/EVT/EXAM/`. You can verify with:

```bash
ls firmware/SDK/EVT/EXAM/BLE/LIB/
# Should show: CH59xBLE.lib, ...
```

## Toolchain

Set the `TOOLCHAIN_PATH` environment variable to your RISC-V GCC installation:

```bash
export TOOLCHAIN_PATH="/path/to/RISC-V Embedded GCC12"
```

The Makefile defaults to `/opt/riscv-wch-gcc` if unset.

## Generate OTA Keys (first build only)

The firmware embeds OTA update keys at build time. `APP/include/ota_keys.h` is intentionally not in this repository — generate your own set once before the first build:

```bash
pip3 install cryptography
python3 ../ota/generate_ota_keys.py
```

This writes `firmware/APP/include/ota_keys.h` (AES key + ECDSA public key for the firmware) and the matching signing keys in `../ota/`. Without it, `make` fails with `ota_keys.h: No such file or directory`.

Self-generated keys are yours alone: a device running official immurok firmware will reject OTA packages signed with them. See [Self-built firmware & OTA keys](https://github.com/immurok/ota#self-built-firmware--ota-keys) before flashing your own build onto a retail device.

## Hardware Versions

Pass `VER=<n>` to select the GPIO mapping for your board revision. The default is `VER=6`, the current production hardware:

| VER | Board | Notes |
|-----|-------|-------|
| 6 | Production (Rev.3, tamper switch) | current retail hardware — default |
| 5 | Rev.3 pre-production | same pinout, no tamper-switch handling |
| 0/2/3 | Internal prototypes | different pinouts, not publicly available |

The LED, button and sensor-enable pins differ between revisions, so firmware built for the wrong `VER` leaves the device apparently dead. If unsure, use the default.

## Build

```bash
make                    # Debug (serial output, no sleep)
make RELEASE_DEBUG=1    # Release-debug (serial output + sleep)
make RELEASE=1          # Release (no serial, sleep enabled)
make RELEASE=1 VER=5    # Build for a specific hardware revision
```

This produces the application image only. For a complete flashable image (JumpIAP + application + IAP bootloader combined) and the `.imfw` OTA package, use `../ota/build-ota.sh` — see [ota/README.md](https://github.com/immurok/ota#readme).

## Flashing

Production devices expose a serial debug header with a **BOOT** pad. There are two wired flashing paths; both write the combined image `build/immurok_OTA_Combined.hex` produced by `../ota/build-ota.sh`.

### Serial ISP via the debug header (production devices)

The CH592F ROM bootloader accepts firmware over **UART1 (PA8 = RX, PA9 = TX)** when the **BOOT** pin (PB22) is held low at power-on. The production PCB exposes pads labeled **VCC5 / TXD1 / RXD1 / DEBUG / GND** on the back side, plus a separate **BOOT** pad with its own **GND** next to the power switch. UART1 is shared with the fingerprint sensor, but the sensor is unpowered while the bootloader runs, so the lines are free during ISP.

1. Connect a 3.3 V USB-serial adapter: adapter TX → **RXD1**, adapter RX → **TXD1**, GND ↔ **GND**. The serial pins of a WCH-LinkE work fine as the adapter.
2. Short **BOOT to GND**, then power the device on. BOOT is sampled only at power-up; it shares PB22 with the blue LED, so the LED may glow faintly while held — harmless.
3. Flash with [`wchisp`](https://github.com/ch32-rs/wchisp) (`cargo install wchisp`):

   ```bash
   wchisp -s -p /dev/tty.usbserial-XXXX flash build/immurok_OTA_Combined.hex
   ```

   On Windows, WCH's official WCHISPTool in serial mode also works.
4. Release BOOT and power-cycle the device.

USB ISP is **not** available on this hardware: the USB-C port is power-only, with no data lines.

### 2-wire debug interface (WCH-LinkE + wlink, development boards)

The WCH 2-wire debug interface lives on PB14 (SWDIO) / PB15 (SWCLK) and requires **both** lines plus GND, with a **WCH-LinkE** — specifically the "E" model; the original WCH-Link does not support the CH59x family. The production PCB does not expose PB14/PB15 (the DEBUG pad is the log serial, not SWDIO), so on production devices use serial ISP instead; this path is for development boards with both test points wired out:

```bash
cargo install --git https://github.com/ch32-rs/wlink
../ota/upload-ota.sh release      # build + flash
../ota/upload-ota.sh -f           # flash only (existing build)
```

### Debug serial output

`debug` and `release-debug` builds print logs on **UART3 TX (PA5), 115200 8N1** — the pad labeled **DEBUG** on the production PCB. Connect it to any serial adapter's RX to watch the log stream (a WCH-LinkE's RX pin works).

## Documentation

- [docs/protocol.md](https://github.com/immurok/immurok/blob/main/docs/protocol.md) — BLE GATT protocol: commands, notifications, packet formats, connection parameters
- [docs/security.md](https://github.com/immurok/immurok/blob/main/docs/security.md) — Security architecture: ECDH pairing, HMAC signing, key storage, threat model
- [hardware/README.md](https://github.com/immurok/hardware#readme) — Hardware design: component selection, GPIO pinout, wiring diagram
- [ota/README.md](https://github.com/immurok/ota#readme) — OTA update: flash layout, boot sequence, .imfw package format
