ENTRY(_start)
SECTIONS {
  . = 0x40200000;
  .text : { *(.text*) }
  /DISCARD/ : { *(.comment) *(.note*) }
}
