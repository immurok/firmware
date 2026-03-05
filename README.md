# immurok Firmware (CH592F)

Main application firmware for the immurok device, running on the WCH CH592F RISC-V BLE MCU.

## Prerequisites

- **Toolchain**: RISC-V GCC for WCH (MounRiver or standalone)
- **Flash tool**: [`wlink`](https://github.com/ch32-rs/wlink) (`cargo install --git https://github.com/ch32-rs/wlink`)
- **SDK**: WCH CH592 EVT SDK (see below)

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

## Build

```bash
make                    # Debug (serial output, no sleep)
make RELEASE_DEBUG=1    # Release-debug (serial output + sleep)
make RELEASE=1          # Release (no serial, sleep enabled)
```

For OTA builds and flashing, see [ota/README.md](../ota/README.md).

## Toolchain

Set the `TOOLCHAIN_PATH` environment variable to your RISC-V GCC installation:

```bash
export TOOLCHAIN_PATH="/path/to/RISC-V Embedded GCC12"
```

The Makefile defaults to `/opt/riscv-wch-gcc` if unset.

## Documentation

- [docs/protocol.md](../docs/protocol.md) — BLE GATT protocol: commands, notifications, packet formats, connection parameters
- [docs/security.md](../docs/security.md) — Security architecture: ECDH pairing, HMAC signing, key storage, threat model
- [hardware/README.md](../hardware/README.md) — Hardware design: component selection, GPIO pinout, wiring diagram
- [ota/README.md](../ota/README.md) — OTA update: flash layout, boot sequence, .imfw package format
