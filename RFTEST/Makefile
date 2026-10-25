# immurok CH592F RF 测试固件(认证/产线用,非 OTA,有线烧录)
# 在本目录执行 make;依赖 ../SDK(CH592 EVT)与 ../APP/include/version.h
TARGET = immurok_CH592F_RFTEST

TOOLCHAIN_PATH ?= /opt/riscv-wch-gcc
TOOLCHAIN_BIN = $(TOOLCHAIN_PATH)/bin
CC = "$(TOOLCHAIN_BIN)/riscv-wch-elf-gcc"
OBJCOPY = "$(TOOLCHAIN_BIN)/riscv-wch-elf-objcopy"
SIZE = "$(TOOLCHAIN_BIN)/riscv-wch-elf-size"

SDK_PATH = ../SDK/EVT/EXAM
SRC_PATH = $(SDK_PATH)/SRC
BLE_PATH = $(SDK_PATH)/BLE
BUILD_DIR = build

C_SOURCES = \
	rftest_main.c \
	ftm.c \
	ftm_parse.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_gpio.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_sys.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_clk.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_uart1.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_uart3.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_pwr.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_adc.c \
	$(SRC_PATH)/StdPeriphDriver/CH59x_flash.c \
	$(SRC_PATH)/RVMSIS/core_riscv.c \
	$(BLE_PATH)/HAL/MCU.c \
	$(BLE_PATH)/HAL/RTC.c \
	$(BLE_PATH)/HAL/SLEEP.c

ASM_SOURCES = \
	$(SRC_PATH)/Startup/startup_CH592.S \
	$(BLE_PATH)/LIB/ble_task_scheduler.S

C_INCLUDES = \
	-I$(BLE_PATH)/HAL/include \
	-I$(BLE_PATH)/LIB \
	-I. \
	-I../APP/include \
	-I$(SRC_PATH)/StdPeriphDriver/inc \
	-I$(SRC_PATH)/RVMSIS

HW_VER ?= 5

# Build number from git (same as production Makefile)
GIT_HASH := $(shell git rev-parse --short=4 HEAD 2>/dev/null || echo "0000")
BUILD_NUMBER := 0x$(GIT_HASH)

BLE_MEMHEAP = 5632

C_DEFS = \
	-DFW_BUILD_NUMBER=$(BUILD_NUMBER) \
	-DHARDWARE_VER$(HW_VER) \
	-DCH592 \
	-DHAL_SLEEP=FALSE \
	-DBLE_MAC=FALSE \
	-DDCDC_ENABLE=TRUE \
	-DBLE_MEMHEAP_SIZE=$(BLE_MEMHEAP) \
	-DBLE_BUFF_MAX_LEN=251 \
	-DBLE_TX_NUM_EVENT=1 \
	-DCLK_OSC32K=0 \
	-DWAKE_UP_RTC_MAX_TIME=164 \
	-DBLE_TX_POWER=LL_TX_POWEER_0_DBM \
	-DRFTEST_BUILD=1

MCU_FLAGS = -march=rv32imac_zicsr -mabi=ilp32 -msmall-data-limit=8
CFLAGS = $(MCU_FLAGS) $(C_DEFS) $(C_INCLUDES)
CFLAGS += -std=gnu99 -Os -ffunction-sections -fdata-sections -fno-common
CFLAGS += -Wall -Wno-unused-function -g

ASFLAGS = $(MCU_FLAGS) $(C_DEFS) $(C_INCLUDES) -x assembler-with-cpp

LDSCRIPT = ../Ld/Link.ld
LIBS = -L$(BLE_PATH)/LIB -L$(SRC_PATH)/StdPeriphDriver -lCH59xBLE -lISP592 -lm
LDFLAGS = $(MCU_FLAGS) -T$(LDSCRIPT)
LDFLAGS += -nostartfiles -Xlinker --gc-sections
LDFLAGS += -Wl,-Map=$(BUILD_DIR)/$(TARGET).map,--cref
LDFLAGS += --specs=nano.specs --specs=nosys.specs
LDFLAGS += $(LIBS)

OBJECTS = $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
vpath %.c $(sort $(dir $(C_SOURCES)))
OBJECTS += $(addprefix $(BUILD_DIR)/,$(notdir $(ASM_SOURCES:.S=.o)))
vpath %.S $(sort $(dir $(ASM_SOURCES)))

$(shell mkdir -p $(BUILD_DIR))

all: $(BUILD_DIR)/$(TARGET).elf $(BUILD_DIR)/$(TARGET).hex $(BUILD_DIR)/$(TARGET).bin
	$(SIZE) $(BUILD_DIR)/$(TARGET).elf
	@echo "RFTEST 固件: HW VER$(HW_VER) — 仅有线烧录,勿走 OTA"

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	@echo "CC $<"
	@$(CC) -c $(CFLAGS) $< -o $@

$(BUILD_DIR)/%.o: %.S | $(BUILD_DIR)
	@echo "AS $<"
	@$(CC) -c $(ASFLAGS) $< -o $@

$(BUILD_DIR)/$(TARGET).elf: $(OBJECTS)
	@echo "LD $@"
	@$(CC) $(OBJECTS) $(LDFLAGS) -o $@

$(BUILD_DIR)/$(TARGET).hex: $(BUILD_DIR)/$(TARGET).elf
	@$(OBJCOPY) -O ihex $< $@

$(BUILD_DIR)/$(TARGET).bin: $(BUILD_DIR)/$(TARGET).elf
	@$(OBJCOPY) -O binary $< $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
