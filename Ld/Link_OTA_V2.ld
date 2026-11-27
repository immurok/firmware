/*
 * Linker Script for immurok CH592F OTA Application (V2 Layout)
 *
 * Flash Layout (V2 - IAP at 0x0000):
 *   0x00000000 - 0x00004000: IAP Bootloader (16KB)
 *   0x00004000 - 0x0003A000: Image A / Application (216KB) <- This image
 *   0x0003A000 - 0x00070000: Image B / OTA Target (216KB)
 *
 * RAM Layout:
 *   0x20000000 - 0x20004000: .highcode / vector table (~16KB)
 *   0x20004000 - 0x20006800: .data / .bss / heap / stack
 *
 * IMPORTANT: The App's vector table is placed at RAM 0x20000000.
 * IAP must NOT use this region (IAP uses RAM from 0x20004000).
 */

ENTRY( _start )

__stack_size = 512;

PROVIDE( _stack_size = __stack_size );

MEMORY
{
    /* Application starts at 0x4000 (16KB offset for IAP bootloader) */
    FLASH (rx) : ORIGIN = 0x00004000, LENGTH = 216K
    /* Full RAM access - App owns this region */
    RAM (xrw) : ORIGIN = 0x20000000, LENGTH = 26K
}

SECTIONS
{
    .init :
    {
        _sinit = .;
        . = ALIGN(4);
        KEEP(*(SORT_NONE(.init)))
        . = ALIGN(4);
        _einit = .;
    } >FLASH AT>FLASH

    .highcodelalign :
    {
        . = ALIGN(4);
        PROVIDE(_highcode_lma = .);
    } >FLASH AT>FLASH

    .highcode :
    {
        . = ALIGN(4);
        PROVIDE(_highcode_vma_start = .);
        *(.vector);
        KEEP(*(SORT_NONE(.vector_handler)))
        *(.highcode);
        *(.highcode.*);
        . = ALIGN(4);
        PROVIDE(_highcode_vma_end = .);
    } >RAM AT>FLASH

    .text :
    {
        . = ALIGN(4);
        KEEP(*(SORT_NONE(.handle_reset)))
        /* P-256 标量乘的热点函数排在一起：运算前整段拷进 RAM 执行（APP/immurok_ecc_fast.c）。
           名字后带 .* 的是编译器可能生成的克隆（.constprop / .isra）。这里漏列的函数如果被
           段内代码直接调用，搬走后会跳错地方——tools/ecc_fast/verify.py 每次构建都查，
           查到就不出固件。三个链接脚本里的这一段必须保持一致。 */
        . = ALIGN(4);
        _ecc_hot_start = .;
        *immurok_ecc_fast.o(.text.EccPoint_mult .text.EccPoint_mult.*)
        *immurok_ecc_fast.o(.text.XYcZ_addC .text.XYcZ_addC.*)
        *immurok_ecc_fast.o(.text.XYcZ_add .text.XYcZ_add.*)
        *immurok_ecc_fast.o(.text.XYcZ_initial_double .text.XYcZ_initial_double.*)
        *immurok_ecc_fast.o(.text.apply_z .text.apply_z.*)
        *immurok_ecc_fast.o(.text.vli_mmod_fast_secp256r1 .text.vli_mmod_fast_secp256r1.*)
        *immurok_ecc_fast.o(.text.uECC_vli_modMult_fast .text.uECC_vli_modMult_fast.*)
        *immurok_ecc_fast.o(.text.uECC_vli_modSquare_fast .text.uECC_vli_modSquare_fast.*)
        *immurok_ecc_fast.o(.text.uECC_vli_mult .text.uECC_vli_mult.*)
        *immurok_ecc_fast.o(.text.muladd .text.muladd.*)
        *immurok_ecc_fast.o(.text.uECC_vli_modAdd .text.uECC_vli_modAdd.*)
        *immurok_ecc_fast.o(.text.uECC_vli_modSub .text.uECC_vli_modSub.*)
        *immurok_ecc_fast.o(.text.uECC_vli_modInv .text.uECC_vli_modInv.*)
        *immurok_ecc_fast.o(.text.vli_modInv_update .text.vli_modInv_update.*)
        *immurok_ecc_fast.o(.text.uECC_vli_add .text.uECC_vli_add.*)
        *immurok_ecc_fast.o(.text.uECC_vli_sub .text.uECC_vli_sub.*)
        *immurok_ecc_fast.o(.text.uECC_vli_cmp_unsafe .text.uECC_vli_cmp_unsafe.*)
        *immurok_ecc_fast.o(.text.uECC_vli_rshift1 .text.uECC_vli_rshift1.*)
        *immurok_ecc_fast.o(.text.uECC_vli_set .text.uECC_vli_set.*)
        *immurok_ecc_fast.o(.text.uECC_vli_clear .text.uECC_vli_clear.*)
        *immurok_ecc_fast.o(.text.uECC_vli_isZero .text.uECC_vli_isZero.*)
        *immurok_ecc_fast.o(.text.uECC_vli_testBit .text.uECC_vli_testBit.*)
        _ecc_hot_end = .;
        *(.text)
        *(.text.*)
        *(.rodata)
        *(.rodata*)
        *(.sdata2.*)
        *(.glue_7)
        *(.glue_7t)
        *(.gnu.linkonce.t.*)
        . = ALIGN(4);
    } >FLASH AT>FLASH

    .fini :
    {
        KEEP(*(SORT_NONE(.fini)))
        . = ALIGN(4);
    } >FLASH AT>FLASH

    PROVIDE( _etext = . );
    PROVIDE( _eitcm = . );

    .preinit_array  :
    {
      PROVIDE_HIDDEN (__preinit_array_start = .);
      KEEP (*(.preinit_array))
      PROVIDE_HIDDEN (__preinit_array_end = .);
    } >FLASH AT>FLASH

    .init_array     :
    {
      PROVIDE_HIDDEN (__init_array_start = .);
      KEEP (*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
      KEEP (*(.init_array EXCLUDE_FILE (*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o ) .ctors))
      PROVIDE_HIDDEN (__init_array_end = .);
    } >FLASH AT>FLASH

    .fini_array     :
    {
      PROVIDE_HIDDEN (__fini_array_start = .);
      KEEP (*(SORT_BY_INIT_PRIORITY(.fini_array.*) SORT_BY_INIT_PRIORITY(.dtors.*)))
      KEEP (*(.fini_array EXCLUDE_FILE (*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o ) .dtors))
      PROVIDE_HIDDEN (__fini_array_end = .);
    } >FLASH AT>FLASH

    .ctors          :
    {
      KEEP (*crtbegin.o(.ctors))
      KEEP (*crtbegin?.o(.ctors))
      KEEP (*(EXCLUDE_FILE (*crtend.o *crtend?.o ) .ctors))
      KEEP (*(SORT(.ctors.*)))
      KEEP (*(.ctors))
    } >FLASH AT>FLASH

    .dtors          :
    {
      KEEP (*crtbegin.o(.dtors))
      KEEP (*crtbegin?.o(.dtors))
      KEEP (*(EXCLUDE_FILE (*crtend.o *crtend?.o ) .dtors))
      KEEP (*(SORT(.dtors.*)))
      KEEP (*(.dtors))
    } >FLASH AT>FLASH

    .dalign    :
    {
        . = ORIGIN(RAM) + SIZEOF(.highcode);
    } >RAM AT>FLASH

    .dlalign :
    {
        . = ALIGN(4);
        PROVIDE(_data_lma = .);
    } >FLASH AT>FLASH

    .data :
    {
        . = ALIGN(4);
        PROVIDE(_data_vma = .);
        *(.gnu.linkonce.r.*)
        *(.data .data.*)
        *(.gnu.linkonce.d.*)
        . = ALIGN(8);
        PROVIDE( __global_pointer$ = . + 0x800 );
        *(.sdata .sdata.*)
        *(.gnu.linkonce.s.*)
        . = ALIGN(8);
        *(.srodata.cst16)
        *(.srodata.cst8)
        *(.srodata.cst4)
        *(.srodata.cst2)
        *(.srodata .srodata.*)
        . = ALIGN(4);
        PROVIDE( _edata = .);
    } >RAM AT>FLASH

    .bss :
    {
        . = ALIGN(4);
        PROVIDE( _sbss = .);
        *(.sbss*)
        *(.gnu.linkonce.sb.*)
        *(.bss*)
        *(.gnu.linkonce.b.*)
        *(COMMON*)
        . = ALIGN(4);
        PROVIDE( _ebss = .);
    } >RAM AT>FLASH

    PROVIDE( _end = _ebss);
    PROVIDE( end = . );

    /* Stack guard: large buffers placed between BSS and stack.
     * Stack overflow goes into this area rather than corrupting .bss.
     * （与 Link_OTA.ld / Link.ld 一致。这个脚本原来没有这一段，immurok_keystore_work_buf
     *  成了孤儿段，被排到 .data 和 .bss 之间，栈下面紧挨着的是 BLE 库的状态。） */
    .stack_guard (NOLOAD) :
    {
        . = ALIGN(4);
        *(.stack_guard)
        *(.stack_guard.*)
        . = ALIGN(4);
    } >RAM

    .stack ORIGIN(RAM) + LENGTH(RAM) - __stack_size :
    {
        PROVIDE( _heap_end = . );
        . = ALIGN(4);
        PROVIDE(_susrstack = . );
        . = . + __stack_size;
        PROVIDE( _eusrstack = .);
    } >RAM
}
