.data

helloStr .ascii "Hello World"

.text

ADDIU $v0, $1, 4
LUI $at, 1001
ORI $a0, $at, helloStr
SYSCALL