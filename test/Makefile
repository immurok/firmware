# 主机侧固件单元测试。用系统 cc，与 firmware/ 的 RISC-V 交叉编译互不影响。
# 跑法：cd firmware/test && make
CC      ?= cc
CFLAGS  := -std=c11 -Wall -Wextra -Werror -g -O0 \
           -I. -I../APP/include -DIMMUROK_HOST_TEST
SRC     := fake_eeprom.c
TESTS   := test_smoke test_slots test_slot_meta test_snv test_tick test_fp_policy test_sha256 test_rng test_pair_policy test_totp test_ecc_ram_policy test_ecc_fast

.PHONY: all clean
all: $(TESTS)
	@for t in $(TESTS); do echo "== $$t"; ./$$t || exit 1; done

test_smoke: test_smoke.c $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

test_slots: test_slots.c $(SRC) ../APP/immurok_slots.c
	$(CC) $(CFLAGS) -o $@ $^

test_slot_meta: test_slot_meta.c $(SRC) ../APP/slot_meta.c ../LIB/sha256.c
	$(CC) $(CFLAGS) -I../LIB -o $@ $^

test_snv: test_snv.c $(SRC) ../APP/immurok_snv.c
	$(CC) $(CFLAGS) -o $@ $^

test_tick: test_tick.c
	$(CC) $(CFLAGS) -o $@ $^

test_fp_policy: test_fp_policy.c
	$(CC) $(CFLAGS) -o $@ $^

test_sha256: test_sha256.c ../LIB/sha256.c
	$(CC) $(CFLAGS) -I../LIB -o $@ $^

test_rng: test_rng.c ../APP/immurok_rng.c ../LIB/sha256.c
	$(CC) $(CFLAGS) -I../LIB -o $@ $^

test_pair_policy: test_pair_policy.c
	$(CC) $(CFLAGS) -o $@ $^

test_totp: test_totp.c ../APP/totp_core.c ../LIB/sha1.c
	$(CC) $(CFLAGS) -I../LIB -o $@ $^

test_ecc_ram_policy: test_ecc_ram_policy.c
	$(CC) $(CFLAGS) -o $@ $^

# micro-ecc 不是按 -Wextra -Werror 写的，两份拷贝单独用宽松选项编；宏定义与固件 Makefile 一致。
UECC_DEFS := -DuECC_PLATFORM=uECC_arch_other -DuECC_WORD_SIZE=4 -DuECC_OPTIMIZATION_LEVEL=2 \
             -DuECC_SUPPORTS_secp160r1=0 -DuECC_SUPPORTS_secp192r1=0 -DuECC_SUPPORTS_secp224r1=0 \
             -DuECC_SUPPORTS_secp256r1=1 -DuECC_SUPPORTS_secp256k1=1 \
             -DuECC_SUPPORT_COMPRESSED_POINT=1 -DuECC_VLI_NATIVE_LITTLE_ENDIAN=1
UECC_CFLAGS := -std=gnu99 -w -g -O1 -I. -I../APP/include -I../LIB -DIMMUROK_HOST_TEST $(UECC_DEFS)

test_ecc_fast: test_ecc_fast.c test_ecc_fast_ref.c ../APP/immurok_ecc_fast.c ../LIB/uECC.c
	$(CC) $(UECC_CFLAGS) -c ../APP/immurok_ecc_fast.c -o test_ecc_fast.fast.o
	$(CC) $(UECC_CFLAGS) -c test_ecc_fast_ref.c -o test_ecc_fast.ref.o
	$(CC) $(CFLAGS) -I../LIB $(UECC_DEFS) -o $@ test_ecc_fast.c test_ecc_fast.fast.o test_ecc_fast.ref.o

clean:
	rm -f $(TESTS) *.o
