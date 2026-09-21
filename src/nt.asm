.code

NtReadVirtualMemory_Sys PROC
    mov r10, rcx
    mov eax, 3Fh
    syscall
    ret
NtReadVirtualMemory_Sys ENDP

END
