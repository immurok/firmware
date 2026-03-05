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

    .stack ORIGIN(RAM) + LENGTH(RAM) - __stack_size :
    {
        PROVIDE( _heap_end = . );
        . = ALIGN(4);
        PROVIDE(_susrstack = . );
        . = . + __stack_size;
        PROVIDE( _eusrstack = .);
    } >RAM
}
