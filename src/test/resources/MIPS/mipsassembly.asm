.data

string .ascii "Hello, World"



.text


	ADDIU $v0, zero, 4
	LUI $at, 1001
	ORI $a0, $at, string
	syscall








