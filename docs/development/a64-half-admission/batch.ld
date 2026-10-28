ENTRY(_start)
SECTIONS {
  . = 0x40200000;
  .text : { *(.text*) }
  .rodata : { *(.rodata*) }
  /DISCARD/ : { *(.comment) *(.note*) }
}
