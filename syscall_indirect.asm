.data
    wSystemCall DWORD 0000h		; The SSN (wSSN)
    qSyscallAddr QWORD 0000h  	; ntdll syscall address

.code 

SetSSn PROC
    mov wSystemCall, ecx
    mov qSyscallAddr, rdx
    ret
SetSSn ENDP

RunSyscall PROC
    mov r10, rcx
    mov eax, wSystemCall
    jmp qword ptr [qSyscallAddr]
RunSyscall ENDP

end
