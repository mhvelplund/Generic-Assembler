.data


.text

		ADD ecx, eax
		ADD edi, [ebx]
loop	ADD ebx, [ebp+1]
		ADD ebp, [5+eax*1]
		ADD edx, 120
		ADD ecx, [ebx+edi*4]
	    JMP loop
