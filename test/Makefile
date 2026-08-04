# 主机侧固件单元测试。用系统 cc，与 firmware/ 的 RISC-V 交叉编译互不影响。
# 跑法：cd firmware/test && make
CC      ?= cc
CFLAGS  := -std=c11 -Wall -Wextra -Werror -g -O0 \
           -I. -I../APP/include -DIMMUROK_HOST_TEST
SRC     := fake_eeprom.c
TESTS   := test_smoke test_slots test_slot_meta

.PHONY: all clean
all: $(TESTS)
	@for t in $(TESTS); do echo "== $$t"; ./$$t || exit 1; done

test_smoke: test_smoke.c $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

test_slots: test_slots.c $(SRC) ../APP/immurok_slots.c
	$(CC) $(CFLAGS) -o $@ $^

test_slot_meta: test_slot_meta.c $(SRC) ../APP/slot_meta.c ../LIB/sha256.c
	$(CC) $(CFLAGS) -I../LIB -o $@ $^

clean:
	rm -f $(TESTS)
