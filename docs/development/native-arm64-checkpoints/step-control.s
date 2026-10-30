.text
 mrs x4,mdscr_el1
 mrs x3,daif
 msr mdscr_el1,x5
 udf #0
 mov x4,#99
 hvc #0
 b .
