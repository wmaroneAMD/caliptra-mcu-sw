/* Licensed under the Apache-2.0 license */
/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright Tock Contributors 2023. */

/*
 * This is the generic linker script for Tock. For most developers, it should
 * be sufficient to define {ROM/PROG/RAM}_{ORIGIN/LENGTH} (6 variables, the
 * start and length for each) and PAGE_SIZE (the size of a flash page).
 * If undefined, PAGE_SIZE uses the default value of 512 bytes.
 *
 * --------------------------------------------------------------------------
 *
 * If you wish to create your own linker script from scratch, you must define
 * the following symbols:
 *
 * `_etext`, `_srelocate`, `_erelocate`
 *    The `_etext` symbol marks the end of data stored in flash that should
 *    stay in flash. `_srelocate` and `_erelocate` mark the address range in
 *    SRAM that mutable program data is copied to.
 *
 *    Tock will copy `_erelocate` - `_srelocate` bytes of data from the
 *    `_etext` pointer to the `_srelocate` pointer.
 *
 * `_szero`, `_ezero`
 *
 *    The `_szero` and `_ezero` symbols define the range of the BSS, SRAM that
 *    Tock will zero on boot.
 *
 * `_sapps`, `_eapps`
 *
 *    The `_sapps` symbol marks the beginning of application memory in flash.
 *    The `_eapps` symbol marks the end of application memory in flash by
 *    pointing to next address after application flash.
 *
 * `_sappmem`, `_eappmem`
 *
 *    The `_sappmem` symbol marks the beginning of application memory in RAM.
 *    The `_eappmem` symbol marks the end of application memory in RAM by
 *    pointing to next address after application RAM.
 */

PAGE_SIZE = DEFINED(PAGE_SIZE) ? PAGE_SIZE : 512;

SECTIONS
{
   .stack (NOLOAD) :
    {
        /* Kernel stack.
         *
         * Tock places the kernel stack at the bottom of SRAM so that the
         * kernel will trigger memory fault if it exceeds its stack depth,
         * rather than silently overwriting valuable data.
         */
        . = ALIGN(8);
         _sstack = .;

         /* For GNU LD, we can just advance the location pointer (".") here to
          * reserve space for the stack. That, however, doesn't seem to work
          * for LLVM LLD. The resulting ELF has a stack section that shows the
          * correct size, but the next section (in our case .relocate) is not
          * moved down as well, instead it sits at the same address as .stack.
          * To work around this, we declare a dummy buffer and then insert it
          * here in the .stack section. This sets the stack size correctly and
          * places the .relocate section at the correct address. */
         KEEP(*(.stack_buffer))
         /*. = . + 0x1000;*/  /*This is the original method. */

         . = ALIGN(8);
         _estack = .;
    } > ram


    /* STATIC ELEMENTS FOR TOCK KERNEL */
    .text :
    {
        . = ALIGN(4);
        _textstart = .;         /* Symbol expected by some MS build toolchains */
        _stext = .;         /* First of standard s,e (start/end) pair */

        /* Place vector table at the beginning of ROM.
         *
         * The first 16 entries in the ARM vector table are defined by ARM and
         * are common among all ARM chips. The remaining entries are
         * chip-specific, which Tock defines in a separate .irqs section
         *
         * http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0553a/BABIFJFG.html
         */
        KEEP(*(.vectors .vectors.*))
        KEEP(*(.irqs))

        /* RISC-V
         * There is no vector table in RISCV, so .vectors and .irqs will be
         * empty. Instead, the _start function needs to be first in the binary
         * for it to correctly be executed. We also need to include the trap
         * handler assembly function.
         *
         * These are expected to just be empty on other platforms so they
         * shouldn't have any effect.
         */
        KEEP(*(.riscv.start));
        /* For RISC-V we need the `_start_trap` function to be 256 byte aligned,
         * and that function is at the start of the .riscv.trap section. If that
         * function does not exist (as for non-RISC-V platforms) then we do not
         * need any unusual alignment.
         * The allignment is implementation specific, so we currently use 256 to
         * work with the lowRISC CPUs.
         */
        . = DEFINED(_start_trap) ? ALIGN(256) : ALIGN(1);
        KEEP(*(.riscv.trap_vectored));
        KEEP(*(.riscv.trap));

        /* .text and .rodata hold most program code and immutable constants */
        /* .gnu.linkonce hold C++ elements with vague linkage
                https://gcc.gnu.org/onlinedocs/gcc/Vague-Linkage.html */
        *(.text .text.* .gnu.linkonce.t.*)

        _srodata = .;
        *(.rodata .rodata.* .gnu.linkonce.r.*)

        /* C++ exception unwinding information */
        *(.ARM.extab* .gnu.linkonce.armextab.*)

        /* glue_7 and glue_7t hold helper functions emitted by the compiler to
           support interworking (linking between functions in ARM and THUMB
           mode). Note that Cortex-M's do not support ARM mode, but this is left
           here to save someone headache if they ever attempt to port Tock to a
           Cortex-A core.  */
        *(.glue_7t) *(.glue_7)


        /* Constructor and destructor sections:

           - init/fini
              Defined by ELF as sections that hold `process
              initialization/termination code`
           - {pre}{init/fini}_array_{start/end}
              Symbols used by the C runtime for initialization / termination
           - ctors/dtors
              Symbols used by the C++ runtime for initialization / termination
        */
        . = ALIGN(4);
        KEEP(*(.init))
        . = ALIGN(4);
        __preinit_array_start = .;
        KEEP (*(.preinit_array))
        __preinit_array_end = .;

        . = ALIGN(4);
        __init_array_start = .;
        KEEP (*(SORT(.init_array.*)))
        KEEP (*(.init_array))
        __init_array_end = .;

        . = ALIGN(4);
        KEEP (*crtbegin.o(.ctors))
        KEEP (*(EXCLUDE_FILE (*crtend.o) .ctors))
        KEEP (*(SORT(.ctors.*)))
        KEEP (*crtend.o(.ctors))

        . = ALIGN(4);
        KEEP(*(.fini))

        . = ALIGN(4);
        __fini_array_start = .;
        KEEP (*(.fini_array))
        KEEP (*(SORT(.fini_array.*)))
        __fini_array_end = .;

        KEEP (*crtbegin.o(.dtors))
        KEEP (*(EXCLUDE_FILE (*crtend.o) .dtors))
        KEEP (*(SORT(.dtors.*)))
        KEEP (*crtend.o(.dtors))
        /* End constructor/destructor */
    } > rom

    /* Mark the end of static elements */
    . = ALIGN(4);
    _erodata = .;
    _etext = .;
    _textend = .;   /* alias for _etext expected by some MS toolchains */


    /* Customer configuration is most often located at the end of the rom. It is
     * conditional, and won't be written if not specified in the board specific
     * linker file.
     */
    .ccfg : {
        KEEP(*(.ccfg))
    } > ccfg


    /* Section for application binaries in flash.
     *
     * This section is put into the "prog" memory, which is reserved for
     * applications. This section is not used for the kernel, but including it
     * in the .elf file allows for concatenating application binaries with the
     * kernel.
     */
    .apps :
    {
        /* _sapps symbol used by Tock to look for first application. */
        . = ALIGN(4);
        _sapps = .;

    } > prog
    /* _eapps symbol used by tock to calculate the length of app flash */
    _eapps = _sapps + LENGTH(prog);


    /* Kernel data that must be relocated. This is program data that is
     * expected to live in SRAM, but is initialized with a value. This data is
     * physically placed into flash and is copied into SRAM by Tock. The
     * symbols here will be defined with addresses in SRAM.
     *
     * Tock assumes the relocation section follows all static elements and will
     * copy (_erelocate - _srelocate) bytes from _etext to _srelocate.
     */
    .relocate : AT (_etext)
    {
        . = ALIGN(4);
        _srelocate = .;

        /* The Global Pointer is used by the RISC-V architecture to provide
         * "gp-relative" addressing. The global pointer is set to the gp
         * register once on boot, and the linker can then take advantage of this
         * when emitting instructions by using offsets relative to this known
         * value. Since RISC-V has only 12 bit immediates, this can help reduce
         * code size.
         *
         * The standard is to set the global pointer to 0x800 past the beginning
         * of the data section in RAM. This allows instructions to use 12 bit
         * immediates to access the first 4KB of data memory. In theory the GP
         * can be set to any value, but it should be placed near actual data for
         * the compiler to actually be able to use it.
         *
         * Per convention, the variable _must_ be called __global_pointer$ for
         * the linker to actually take advantage of it.
         */
        PROVIDE(__global_pointer$ = . + 0x800);

        *(.ramfunc .ramfunc.*);
        *(.sdata .sdata.* .gnu.linkonce.r.*)
        *(.data .data.*);

        . = ALIGN(4);
        _erelocate = .;
    } > ram


    .sram (NOLOAD) :
    {
        /* Kernel BSS section. Memory that is expected to be initialized to
         * zero.
         *
         * Elements in this section do not contribute to the binary size. Tock
         * initialization will write zeros to the memory between _szero and
         * _ezero.
         *
         * Elements placed in the .bss and .COMMON sections are simply used to
         * measure amount of memory to zero out.
         */
        . = ALIGN(4);
        _szero = .;

        /* In addition to the traditional .bss section, RISC-V splits out a "small data" section
         * see: https://github.com/riscv/riscv-pk/blob/a3e4ac61d2b1ff37a22b9193b85d3b94273e80cb/pk/pk.lds#L84
         */
        *(.sbss .sbss.* .bss .bss.*);
        *(COMMON)

        . = ALIGN(4);
        _ezero = .;

        /* Application Memory.
         *
         * Tock uses the remainder of SRAM for application memory.
         *
         * Currently, Tock allocates a fixed array of application memory at
         * compile-time, and that array is simply placed here. A possible
         * future enhancement may allow the kernel to parcel this memory space
         * dynamically, requiring changes to this section.
         */
         . = ALIGN(4096); /* align to page boundary due to lld limitation */
        _sappmem = .;
        *(.app_memory)
    } > ram

    _eappmem = ORIGIN(ram) + LENGTH(ram);


    /* Place attributes at the end of the kernel ROM region. These will be used
     * for host-side tools to learn about the installed kernel.
     *
     * Attributes are stored as TLVs, but going backwards in flash.
     *
     *                           2 byte   2 byte   3 byte     1 byte    4 byte
     * -----------+------------+--------+--------+----------+---------+---------+ Start
     *            | Value...   | Type   | Length | Reserved | Version | TOCK    | of
     * -----------+------------+--------+--------+----------+---------+---------+ `prog`
     * <-TLVs...-> <-----TLV--------------------> <----Header--------> <-Sentl->
     *
     * The TLV `Length` specifies the size of the TLV value (i.e. not including
     * the TLV header).
     */
    /*.attributes : AT (ORIGIN(rom) + LENGTH(rom) - SIZEOF(.attributes))*/
    /*{*/
        /* TLV: Kernel Flash
         * This indicates the start address of the kernel flash and the size of
         * the kernel binary.
         */
        /*LONG(ORIGIN(rom))*/ /* Address of start of kernel binary. */
        /*LONG((LOADADDR(.relocate) + (_erelocate - _srelocate)) - ORIGIN(rom))*/ /* Length of kernel binary. */
        /*SHORT(0x0102)*/ /* Type = Kernel Flash = 0x0102 */
        /*SHORT(8)*/      /* Length = 8 bytes */

        /* TLV: App Memory
         * This indicates the start address and size of RAM available for
         * userspace apps.
         */
        /*LONG(_sappmem)*/ /* Address of start of app memory. */
        /*LONG(_eappmem - _sappmem)*/ /* Length of app memory. */
        /*SHORT(0x0101)*/ /* Type = App RAM Region = 0x0101 */
        /*SHORT(8)*/      /* Length = 8 bytes */

        /* Version and Reserved. Current version is 0x01.
         */
        /*BYTE(0)*/ /* Reserved */
        /*BYTE(0)*/ /* Reserved */
        /*BYTE(0)*/ /* Reserved */
        /*BYTE(1)*/ /* Version = 0x01 */

        /* Sentinel.
         */
        /*BYTE(84)*/ /* T */
        /*BYTE(79)*/ /* O */
        /*BYTE(67)*/ /* C */
        /*BYTE(75)*/ /* K */
    /*}  > rom*/


    /* Discard RISC-V relevant .eh_frame, we are not doing unwind on panic
       so it is not needed. */
    /DISCARD/ :
    {
      *(.eh_frame*);
    }

    /* Region for non-volatile storage used by kernel. 
     *
     * Align on PAGE_SIZE number of bytes. Volumes within this region are
     * allocated with the storage_volume! macro in utils.rs.
     */
    .storage (NOLOAD):
    {
      . = ALIGN(PAGE_SIZE);
      _sstorage = .;
      KEEP*(.storage* storage*)
      _estorage = .;
      . = ALIGN(PAGE_SIZE);
    } > flash
    . = ALIGN(PAGE_SIZE);

}

/* LOADADDR: Return the absolute load address of the named section. This is
 * normally the same as ADDR, but it may be different if the AT keyword is used
 * in the section definition. */
/*_sattributes = LOADADDR(.attributes);
_eattributes = LOADADDR(.attributes) + SIZEOF(.attributes);*/
_sattributes = 0;
_eattributes = 0;
_srom = ORIGIN(rom);
_erom = ORIGIN(rom) + LENGTH(rom);
_sprog = ORIGIN(prog);
_eprog = ORIGIN(prog) + LENGTH(prog);
_ssram = ORIGIN(ram);
_esram = ORIGIN(ram) + LENGTH(ram);

/* Reserve space for the PIC vector table */
_pic_vector_table = ORIGIN(dccm) + LENGTH(dccm) - 1024;

/* Direct read flash region */
_sstorage = ORIGIN(flash);
_estorage = ORIGIN(flash) + LENGTH(flash);


/* This.. this is a dirty, not-fully-understood, hack. In some way, linking is
 * a multi-pass process. i.e., if you were to ASSERT(0, "how many links")
 * you'll get three assertions printed for one invocation of rust-lld.
 *
 * Empirically, in the first pass, _eattributes ends up at
 *     _erom + SIZEOF(.attributes)
 * So, we need to allow that case.
 *
 * That's really not the dream, since we can't identify passes. We really only
 * want to let the wrong location through on the first pass. Thus, the _best_
 * solution would be to extract the _erom and _eattributes symbols with readelf
 * or similar and verify they're equal, but that would be yet-one-more-tool.
 * Maybe something we can do in CI at some point, and remove this assert.
 */
/*ASSERT((_eattributes == _erom) || (_eattributes == _erom + SIZEOF(.attributes)), "Kernel attributes are not at the end of ROM.")*/

/* This assert works out because even though some of the relative positions are
 * off, the sizes are sane in each pass. */
/*ASSERT((_etext - _stext) + (_erelocate - _srelocate) + (_eattributes - _sattributes) < LENGTH(rom),
"Text plus relocations plus attributes exceeds the available ROM space.");*/
