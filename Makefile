# immurok CH592F Firmware Makefile
# Using official SDK HID_Keyboard example
#
# Build modes:
#   make          - Debug build (with serial output, no sleep)
#   make release  - Release build (no serial, low power sleep)
#   make ota      - OTA V1 build (starts at 0x1000, 216KB max)
#   make ota-release - OTA V1 release build
#   make ota-v2   - OTA V2 build (starts at 0x4000, IAP at 0x0000)
#   make ota-v2-release - OTA V2 release build

# Project name
TARGET = immurok_CH592F

# Toolchain (path with spaces requires quoting in commands)
TOOLCHAIN_PATH ?= /opt/riscv-wch-gcc
TOOLCHAIN_BIN = $(TOOLCHAIN_PATH)/bin
CC = "$(TOOLCHAIN_BIN)/riscv-wch-elf-gcc"
OBJCOPY = "$(TOOLCHAIN_BIN)/riscv-wch-elf-objcopy"
OBJDUMP = "$(TOOLCHAIN_BIN)/riscv-wch-elf-objdump"
SIZE = "$(TOOLCHAIN_BIN)/riscv-wch-elf-size"

# SDK paths
SDK_PATH = SDK/EVT/EXAM
SRC_PATH = $(SDK_PATH)/SRC
BLE_PATH = $(SDK_PATH)/BLE

# Directories
BUILD_DIR = build
APP_DIR = APP
PROFILE_DIR = Profile

# Source files (pure SDK HID_Keyboard)
C_SOURCES = \
	$(APP_DIR)/main.c \
	$(APP_DIR)/hidkbd.c \
	$(APP_DIR)/fingerprint.c \
	$(APP_DIR)/immurok_security.c \
	$(APP_DIR)/immurok_keystore.c \
	$(APP_DIR)/ws2812.c \
	LIB/sha1.c \
	LIB/sha256.c \
	LIB/aes128.c \
	LIB/uECC.c \
	$(PROFILE_DIR)/hidkbdservice.c \
	$(PROFILE_DIR)/hiddev.c \
	$(PROFILE_DIR)/battservice.c \
	$(PROFILE_DIR)/devinfoservice.c \
	$(PROFILE_DIR)/scanparamservice.c \
	$(PROFILE_DIR)/immurokservice.c \
	$(PROFILE_DIR)/otaprofile.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_gpio.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_sys.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_clk.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_uart1.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_uart3.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_pwr.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_adc.c \
	$(SRC_PATH)/RVMSIS/core_riscv.c \
	$(BLE_PATH)/HAL/MCU.c \
	$(BLE_PATH)/HAL/RTC.c \
	$(BLE_PATH)/HAL/SLEEP.c \
	$(BLE_PATH)/HAL/KEY.c

# ASM sources - use OTA-specific startup for OTA builds
ifdef OTA_V2
ASM_SOURCES = \
	Startup/startup_CH592_OTA.S \
	$(BLE_PATH)/LIB/ble_task_scheduler.S
else ifdef OTA
ASM_SOURCES = \
	Startup/startup_CH592_OTA.S \
	$(BLE_PATH)/LIB/ble_task_scheduler.S
else
ASM_SOURCES = \
	$(SRC_PATH)/Startup/startup_CH592.S \
	$(BLE_PATH)/LIB/ble_task_scheduler.S
endif

# Include paths
C_INCLUDES = \
	-I$(BLE_PATH)/HAL/include \
	-I$(BLE_PATH)/LIB \
	-I$(APP_DIR)/include \
	-I$(PROFILE_DIR)/include \
	-I$(SRC_PATH)/StdPeriphDriver/inc \
	-I$(SRC_PATH)/RVMSIS

# Hardware version (default: 0)
# Usage: make VER=0 or make VER=1
ifdef VER
HW_VER = $(VER)
endif
HW_VER ?= 0

# Common defines
C_DEFS_COMMON = \
	-DHARDWARE_VER$(HW_VER) \
	-DCH592 \
	-DBLE_MAC=FALSE \
	-DDCDC_ENABLE=TRUE \
	-DBLE_MEMHEAP_SIZE=6144 \
	-DBLE_BUFF_MAX_LEN=251 \
	-DCLK_OSC32K=0 \
	-DWAKE_UP_RTC_MAX_TIME=164 \
	-DuECC_PLATFORM=uECC_arch_other \
	-DuECC_WORD_SIZE=4 \
	-DuECC_OPTIMIZATION_LEVEL=2 \
	-DuECC_SUPPORTS_secp160r1=0 \
	-DuECC_SUPPORTS_secp192r1=0 \
	-DuECC_SUPPORTS_secp224r1=0 \
	-DuECC_SUPPORTS_secp256r1=1 \
	-DuECC_SUPPORTS_secp256k1=1 \
	-DuECC_SUPPORT_COMPRESSED_POINT=1 \
	-DuECC_VLI_NATIVE_LITTLE_ENDIAN=1

# Debug build: serial output enabled, sleep disabled, higher TX power
C_DEFS_DEBUG = \
	$(C_DEFS_COMMON) \
	-DDEBUG=3 \
	-DHAL_SLEEP=FALSE \
	-DBLE_TX_POWER=LL_TX_POWEER_4_DBM

# Release build: no serial output, sleep enabled, lower TX power
C_DEFS_RELEASE = \
	$(C_DEFS_COMMON) \
	-DHAL_SLEEP=TRUE \
	-DBLE_TX_POWER=LL_TX_POWEER_0_DBM

# Release-debug build: sleep enabled WITH serial output (for diagnosing sleep issues)
C_DEFS_RELEASE_DEBUG = \
	$(C_DEFS_COMMON) \
	-DDEBUG=3 \
	-DHAL_SLEEP=TRUE \
	-DBLE_TX_POWER=LL_TX_POWEER_0_DBM

# Select build mode (default: debug)
ifdef RELEASE_DEBUG
    C_DEFS = $(C_DEFS_RELEASE_DEBUG)
    BUILD_MODE = release-debug
else ifdef RELEASE
    C_DEFS = $(C_DEFS_RELEASE)
    BUILD_MODE = release
else
    C_DEFS = $(C_DEFS_DEBUG)
    BUILD_MODE = debug
endif

# Compiler flags
MCU_FLAGS = -march=rv32imac_zicsr -mabi=ilp32 -msmall-data-limit=8

CFLAGS = $(MCU_FLAGS) $(C_DEFS) $(C_INCLUDES)
CFLAGS += -std=gnu99 -Os -ffunction-sections -fdata-sections -fno-common
CFLAGS += -Wall -Wno-unused-function
ifndef RELEASE
    CFLAGS += -g
endif

ASFLAGS = $(MCU_FLAGS) $(C_DEFS) $(C_INCLUDES)
ASFLAGS += -x assembler-with-cpp

# Linker flags
# Use appropriate linker script based on build mode:
# - OTA V1: 0x1000 start (separate bootloader at 0x0000)
# - OTA V2: 0x4000 start (IAP bootloader at 0x0000)
# - Normal: 0x0000 start (no OTA)
ifdef OTA_V2
    LDSCRIPT = Ld/Link_OTA_V2.ld
else ifdef OTA
    LDSCRIPT = Ld/Link_OTA.ld
else
    LDSCRIPT = Ld/Link.ld
endif
LIBS = -L$(BLE_PATH)/LIB -L$(SRC_PATH)/StdPeriphDriver -lCH59xBLE -lISP592 -lm
LDFLAGS = $(MCU_FLAGS)
LDFLAGS += -T$(LDSCRIPT)
LDFLAGS += -nostartfiles -Xlinker --gc-sections
LDFLAGS += -Wl,-Map=$(BUILD_DIR)/$(TARGET).map,--cref
LDFLAGS += --specs=nano.specs --specs=nosys.specs
LDFLAGS += $(LIBS)

# Object files
OBJECTS = $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
vpath %.c $(sort $(dir $(C_SOURCES)))

OBJECTS += $(addprefix $(BUILD_DIR)/,$(notdir $(ASM_SOURCES:.S=.o)))
vpath %.S $(sort $(dir $(ASM_SOURCES)))

# Track build flags — auto-clean when flags change
BUILD_FLAGS_FILE = $(BUILD_DIR)/.build_flags
CURRENT_FLAGS = $(BUILD_MODE) HW_VER=$(HW_VER)
$(shell mkdir -p $(BUILD_DIR))
$(shell if [ ! -f $(BUILD_FLAGS_FILE) ] || [ "$$(cat $(BUILD_FLAGS_FILE))" != "$(CURRENT_FLAGS)" ]; then \
	rm -f $(BUILD_DIR)/*.o; \
	echo "$(CURRENT_FLAGS)" > $(BUILD_FLAGS_FILE); \
fi)

# Build targets
all: $(BUILD_DIR)/$(TARGET).elf $(BUILD_DIR)/$(TARGET).hex $(BUILD_DIR)/$(TARGET).bin size
	@echo "Build mode: $(BUILD_MODE), HW: VER$(HW_VER)"

$(BUILD_DIR)/%.o: %.c Makefile | $(BUILD_DIR)
	@echo "CC $<"
	@$(CC) -c $(CFLAGS) $< -o $@

$(BUILD_DIR)/%.o: %.S Makefile | $(BUILD_DIR)
	@echo "AS $<"
	@$(CC) -c $(ASFLAGS) $< -o $@

$(BUILD_DIR)/$(TARGET).elf: $(OBJECTS) Makefile
	@echo "LD $@"
	@$(CC) $(OBJECTS) $(LDFLAGS) -o $@

$(BUILD_DIR)/$(TARGET).hex: $(BUILD_DIR)/$(TARGET).elf
	@echo "HEX $@"
	@$(OBJCOPY) -O ihex $< $@

$(BUILD_DIR)/$(TARGET).bin: $(BUILD_DIR)/$(TARGET).elf
	@echo "BIN $@"
	@$(OBJCOPY) -O binary -S $< $@

$(BUILD_DIR):
	@mkdir -p $@

size: $(BUILD_DIR)/$(TARGET).elf
	@echo ""
	@echo "=== Memory Usage ==="
	@$(SIZE) $<

clean:
	@rm -rf $(BUILD_DIR)
	@echo "Clean done"

# Release build target
release:
	@$(MAKE) RELEASE=1 HW_VER=$(HW_VER) clean all

# Release-debug build target (sleep + serial output for diagnostics)
release-debug:
	@$(MAKE) RELEASE_DEBUG=1 HW_VER=$(HW_VER) clean all

# OTA V1 build targets (application starts at 0x1000)
ota:
	@$(MAKE) OTA=1 HW_VER=$(HW_VER) clean all
	@echo ""
	@echo "=== OTA V1 Build Complete ==="
	@echo "Flash layout: 0x1000 - 0x37000 (216KB max)"

ota-release:
	@$(MAKE) OTA=1 RELEASE=1 HW_VER=$(HW_VER) clean all
	@echo ""
	@echo "=== OTA V1 Release Build Complete ==="

# OTA V2 build targets (application starts at 0x4000, IAP at 0x0000)
ota-v2:
	@$(MAKE) OTA_V2=1 HW_VER=$(HW_VER) clean all
	@echo ""
	@echo "=== OTA V2 Build Complete ==="
	@echo "Flash layout: 0x4000 - 0x3A000 (216KB max)"

ota-v2-release:
	@$(MAKE) OTA_V2=1 RELEASE=1 HW_VER=$(HW_VER) clean all
	@echo ""
	@echo "=== OTA V2 Release Build Complete ==="

# Flash using WCHISPTool (macOS)
flash: $(BUILD_DIR)/$(TARGET).hex
	@echo "Please use WCHISPTool to flash $(BUILD_DIR)/$(TARGET).hex"

# Disassembly
disasm: $(BUILD_DIR)/$(TARGET).elf
	@$(OBJDUMP) -d -S $< > $(BUILD_DIR)/$(TARGET).lst

.PHONY: all clean flash disasm size release release-debug ota ota-release ota-v2 ota-v2-release
