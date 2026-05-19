.data
    g_NtOpenProcessSysNum DWORD 0
    g_NtReadVirtualMemorySysNum DWORD 0
    g_NtQueryVirtualMemorySysNum DWORD 0
    g_NtQuerySystemInformationSysNum DWORD 0
    g_NtQueryInformationThreadSysNum DWORD 0

.code

; --- C++ Katmanından Numaraları Alan Fonksiyonlar ---
SetNtOpenProcessSysNum PROC
    mov g_NtOpenProcessSysNum, ecx
    ret
SetNtOpenProcessSysNum ENDP

SetNtReadVirtualMemorySysNum PROC
    mov g_NtReadVirtualMemorySysNum, ecx
    ret
SetNtReadVirtualMemorySysNum ENDP

SetNtQueryVirtualMemorySysNum PROC
    mov g_NtQueryVirtualMemorySysNum, ecx
    ret
SetNtQueryVirtualMemorySysNum ENDP

SetNtQuerySystemInformationSysNum PROC
    mov g_NtQuerySystemInformationSysNum, ecx
    ret
SetNtQuerySystemInformationSysNum ENDP

SetNtQueryInformationThreadSysNum PROC
    mov g_NtQueryInformationThreadSysNum, ecx
    ret
SetNtQueryInformationThreadSysNum ENDP


; --- DİNAMİK SYSCALL ÇAĞRILARI ---

MyNtOpenProcess PROC
    mov r10, rcx
    mov eax, g_NtOpenProcessSysNum
    syscall
    ret
MyNtOpenProcess ENDP

MyNtReadVirtualMemory PROC
    mov r10, rcx
    mov eax, g_NtReadVirtualMemorySysNum
    syscall
    ret
MyNtReadVirtualMemory ENDP

MyNtQueryVirtualMemory PROC
    mov r10, rcx
    mov eax, g_NtQueryVirtualMemorySysNum
    syscall
    ret
MyNtQueryVirtualMemory ENDP

MyNtQuerySystemInformation PROC
    mov r10, rcx
    mov eax, g_NtQuerySystemInformationSysNum
    syscall
    ret
MyNtQuerySystemInformation ENDP

MyNtQueryInformationThread PROC
    mov r10, rcx
    mov eax, g_NtQueryInformationThreadSysNum
    syscall
    ret
MyNtQueryInformationThread ENDP

END