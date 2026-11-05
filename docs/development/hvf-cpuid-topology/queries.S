.intel_syntax noprefix
.text
.global topology_queries
topology_queries:
    mov eax, 1
    mov ecx, 0
    cpuid
    mov dword ptr [0x18000], eax
    mov dword ptr [0x18004], ebx
    mov dword ptr [0x18008], ecx
    mov dword ptr [0x1800c], edx
    mov eax, 4
    mov ecx, 0
    cpuid
    mov dword ptr [0x18010], eax
    mov dword ptr [0x18014], ebx
    mov dword ptr [0x18018], ecx
    mov dword ptr [0x1801c], edx
    mov eax, 4
    mov ecx, 1
    cpuid
    mov dword ptr [0x18020], eax
    mov dword ptr [0x18024], ebx
    mov dword ptr [0x18028], ecx
    mov dword ptr [0x1802c], edx
    mov eax, 4
    mov ecx, 2
    cpuid
    mov dword ptr [0x18030], eax
    mov dword ptr [0x18034], ebx
    mov dword ptr [0x18038], ecx
    mov dword ptr [0x1803c], edx
    mov eax, 4
    mov ecx, 3
    cpuid
    mov dword ptr [0x18040], eax
    mov dword ptr [0x18044], ebx
    mov dword ptr [0x18048], ecx
    mov dword ptr [0x1804c], edx
    mov eax, 4
    mov ecx, 4
    cpuid
    mov dword ptr [0x18050], eax
    mov dword ptr [0x18054], ebx
    mov dword ptr [0x18058], ecx
    mov dword ptr [0x1805c], edx
    mov eax, 11
    mov ecx, 0
    cpuid
    mov dword ptr [0x18060], eax
    mov dword ptr [0x18064], ebx
    mov dword ptr [0x18068], ecx
    mov dword ptr [0x1806c], edx
    mov eax, 11
    mov ecx, 1
    cpuid
    mov dword ptr [0x18070], eax
    mov dword ptr [0x18074], ebx
    mov dword ptr [0x18078], ecx
    mov dword ptr [0x1807c], edx
    mov eax, 11
    mov ecx, 2
    cpuid
    mov dword ptr [0x18080], eax
    mov dword ptr [0x18084], ebx
    mov dword ptr [0x18088], ecx
    mov dword ptr [0x1808c], edx
    mov eax, 11
    mov ecx, 3
    cpuid
    mov dword ptr [0x18090], eax
    mov dword ptr [0x18094], ebx
    mov dword ptr [0x18098], ecx
    mov dword ptr [0x1809c], edx
    mov eax, 11
    mov ecx, 255
    cpuid
    mov dword ptr [0x180a0], eax
    mov dword ptr [0x180a4], ebx
    mov dword ptr [0x180a8], ecx
    mov dword ptr [0x180ac], edx
    mov eax, 11
    mov ecx, 256
    cpuid
    mov dword ptr [0x180b0], eax
    mov dword ptr [0x180b4], ebx
    mov dword ptr [0x180b8], ecx
    mov dword ptr [0x180bc], edx
    mov eax, 11
    mov ecx, 4294967295
    cpuid
    mov dword ptr [0x180c0], eax
    mov dword ptr [0x180c4], ebx
    mov dword ptr [0x180c8], ecx
    mov dword ptr [0x180cc], edx
    mov eax, 31
    mov ecx, 0
    cpuid
    mov dword ptr [0x180d0], eax
    mov dword ptr [0x180d4], ebx
    mov dword ptr [0x180d8], ecx
    mov dword ptr [0x180dc], edx
