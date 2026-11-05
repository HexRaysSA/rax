ENTRY(_start)
PHDRS { image PT_LOAD FLAGS(7); }
SECTIONS { . = 0x40200000; .text : { *(.text*) *(.rodata*) *(.data*) } :image }
