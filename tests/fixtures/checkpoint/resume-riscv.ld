ENTRY(_start)
PHDRS { text PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }
SECTIONS {
    . = 0x80000000;
    .text : { *(.text*) } :text
    . = 0x80001000;
    .tohost : { *(.tohost*) } :data
}
