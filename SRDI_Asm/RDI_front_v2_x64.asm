;----------------------------------------------------------------------------------
; Author: oneday
; Language: MASM x64
; Details:
;   Front-style SRDI loader core v2.
;
; Calling convention:
;   RCX = pointer to RDI2 payload header.
;
; Final shellcode layout is produced by the Convert2Shellcode converter API:
;   [bootstrap][this .text][RDI2 header][raw PE][optional user data]
;----------------------------------------------------------------------------------

option casemap:none

; RDI2 payload header offsets.
HDR_MAGIC          equ 00h
HDR_FLAGS          equ 06h
HDR_PE_OFFSET      equ 08h
HDR_PE_SIZE        equ 0Ch
HDR_USER_OFFSET    equ 10h
HDR_USER_SIZE      equ 14h
HDR_EXPORT_HASH    equ 18h

RDI2_MAGIC         equ 32494452h        ; "RDI2"
RDI_FLAG_EXPORT    equ 0001h            ; call DLL export after DLL_PROCESS_ATTACH

; Stack context offsets. Access as [rbp - CTX_*].
CTX_HEADER         equ 008h
CTX_SRC_BASE       equ 010h
CTX_DST_BASE       equ 018h
CTX_SRC_NT         equ 020h
CTX_DST_NT         equ 028h
CTX_DELTA          equ 030h
CTX_USER_PTR       equ 038h
CTX_USER_LEN       equ 040h
CTX_FLAGS          equ 048h
CTX_EXPORT_HASH    equ 050h
CTX_OLD_PROTECT    equ 058h
CTX_TMP            equ 060h
CTX_ENTRY          equ 098h             ; saved OEP/DllMain during header scrub
CTX_NTDLL_BASE     equ 0A8h
CTX_API_RGV        equ 0B0h             ; RtlGetVersion
CTX_WIN_BUILD      equ 0B8h
CTX_LDRP_TLS       equ 0C8h
CTX_PATTERN_LEN    equ 0D0h
CTX_PATTERN_BUF    equ 0E0h             ; 16 bytes
CTX_VERSION_BUF    equ 100h             ; OSVERSIONINFOEXW scratch
CTX_FAKE_LDR       equ 230h             ; fake LDR_DATA_TABLE_ENTRY scratch

CTX_API_VA         equ 068h             ; VirtualAlloc
CTX_API_VP         equ 070h             ; VirtualProtect
CTX_API_LL         equ 078h             ; LoadLibraryA
CTX_API_GPA        equ 080h             ; GetProcAddress
CTX_API_RAF        equ 088h             ; RtlAddFunctionTable
CTX_API_NFIC       equ 090h             ; NtFlushInstructionCache

CTX_SIZE           equ 400h

; module+function ROR13 hashes used by the existing project.
HASH_VirtualAlloc  equ 0FBFA86AFh
HASH_VirtualProtect equ 0E3918276h
HASH_LoadLibraryA  equ 056590AE9h
HASH_GetProcAddress equ 0E658B905h
HASH_RtlAddFunctionTable equ 08D46D2BCh
HASH_NtFlushInstructionCache equ 090467315h
HASH_RtlGetVersion equ 0DBBEEF9h
HASH_NTDLL_MODULE  equ 03CFA685Dh

BUILD_WIN7         equ 7600
BUILD_WIN8         equ 9200
BUILD_WIN81        equ 9600
BUILD_WIN10_RS2    equ 15063
BUILD_WIN10_RS4    equ 17134
BUILD_WIN10_19H1   equ 18362
BUILD_WIN11_BETA   equ 21996

.code

RdiMain proc
    cld

    ; Save non-volatile registers. Keep rbp as a stable context anchor.
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    mov  rbp, rsp
    sub  rsp, CTX_SIZE + 8               ; keep existing bootstrap-compatible alignment

    ; Validate and unpack RDI2 payload header.
    cmp  dword ptr [rcx + HDR_MAGIC], RDI2_MAGIC
    jne  RdiExit

    mov  [rbp - CTX_HEADER], rcx

    mov  eax, dword ptr [rcx + HDR_PE_OFFSET]
    add  rax, rcx
    mov  [rbp - CTX_SRC_BASE], rax

    mov  edx, dword ptr [rcx + HDR_USER_OFFSET]
    test edx, edx
    jz   Init_NoUser
    mov  rax, rdx
    add  rax, rcx
    mov  [rbp - CTX_USER_PTR], rax
    jmp  Init_UserDone

Init_NoUser:
    xor  eax, eax
    mov  [rbp - CTX_USER_PTR], rax

Init_UserDone:
    xor  eax, eax
    mov  eax, dword ptr [rcx + HDR_USER_SIZE]
    mov  [rbp - CTX_USER_LEN], rax

    movzx eax, word ptr [rcx + HDR_FLAGS]
    mov  [rbp - CTX_FLAGS], rax

    mov  eax, dword ptr [rcx + HDR_EXPORT_HASH]
    mov  [rbp - CTX_EXPORT_HASH], rax

    ; Locate source NT headers.
    mov  rdx, [rbp - CTX_SRC_BASE]
    cmp  word ptr [rdx], 5A4Dh           ; MZ
    jne  RdiExit
    mov  eax, dword ptr [rdx + 3Ch]
    add  rax, rdx
    cmp  dword ptr [rax], 00004550h      ; PE\0\0
    jne  RdiExit
    cmp  word ptr [rax + 18h], 020Bh     ; PE32+
    jne  RdiExit
    mov  [rbp - CTX_SRC_NT], rax

    call ResolveCoreApis
    test rax, rax
    jz   RdiExit

    call MapImage
    test rax, rax
    jz   RdiExit

    call ClearSourcePe
    call ApplyRelocations
    call ResolveImports
    test rax, rax
    jz   RdiExit

    call ProtectSections
    call FlushInstructionCache
    call RegisterExceptionTable
    call HandleTlsData
    call RunTlsCallbacks
    call CallImageEntry

RdiExit:
    mov  rsp, rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbp
    pop  rbx
    ret
RdiMain endp

;----------------------------------------------------------------------------------
; Shared null-terminated ANSI string ROR13 hash helper.
; Input:  RSI = string pointer
; Output: R11D = hash
; Clobbers: RAX, RSI
;----------------------------------------------------------------------------------
Ror13HashNTStr proc
    xor  r11d, r11d
Ror13NT_Loop:
    xor  eax, eax
    lodsb
    test al, al
    jz   Ror13NT_Done
    ror  r11d, 0Dh
    add  r11d, eax
    jmp  Ror13NT_Loop
Ror13NT_Done:
    ret
Ror13HashNTStr endp

;----------------------------------------------------------------------------------
; Resolve and cache APIs needed by the loader.
; Returns RAX=1 on success, RAX=0 on failure.
;----------------------------------------------------------------------------------
ResolveCoreApis proc
    mov  r10d, HASH_VirtualAlloc
    call ResolveApiByHash
    test rax, rax
    jz   ResolveCoreApis_Fail
    mov  [rbp - CTX_API_VA], rax

    mov  r10d, HASH_VirtualProtect
    call ResolveApiByHash
    test rax, rax
    jz   ResolveCoreApis_Fail
    mov  [rbp - CTX_API_VP], rax

    mov  r10d, HASH_LoadLibraryA
    call ResolveApiByHash
    test rax, rax
    jz   ResolveCoreApis_Fail
    mov  [rbp - CTX_API_LL], rax

    mov  r10d, HASH_GetProcAddress
    call ResolveApiByHash
    test rax, rax
    jz   ResolveCoreApis_Fail
    mov  [rbp - CTX_API_GPA], rax

    mov  r10d, HASH_RtlAddFunctionTable
    call ResolveApiByHash
    mov  [rbp - CTX_API_RAF], rax

    mov  r10d, HASH_NtFlushInstructionCache
    call ResolveApiByHash
    mov  [rbp - CTX_API_NFIC], rax

    mov  r10d, HASH_RtlGetVersion
    call ResolveApiByHash
    mov  [rbp - CTX_API_RGV], rax

    mov  eax, 1
    ret

ResolveCoreApis_Fail:
    xor  eax, eax
    ret
ResolveCoreApis endp

;----------------------------------------------------------------------------------
; Map headers and sections into a new RWX image allocation.
;----------------------------------------------------------------------------------
MapImage proc
    mov  r12, [rbp - CTX_SRC_NT]

    xor  rcx, rcx                         ; lpAddress
    mov  eax, dword ptr [r12 + 0B0h]      ; Base relocation directory RVA
    or   eax, dword ptr [r12 + 0B4h]      ; Base relocation directory size
    jnz  MapImage_Allocate
    mov  rcx, qword ptr [r12 + 30h]       ; non-relocatable: require ImageBase
MapImage_Allocate:
    mov  edx, dword ptr [r12 + 50h]       ; SizeOfImage
    mov  r8d, 3000h                       ; MEM_COMMIT | MEM_RESERVE
    mov  r9d, 40h                         ; PAGE_EXECUTE_READWRITE
    sub  rsp, 20h
    call qword ptr [rbp - CTX_API_VA]
    add  rsp, 20h
    test rax, rax
    jz   MapImage_Fail
    mov  [rbp - CTX_DST_BASE], rax

    ; Copy headers.
    mov  ecx, dword ptr [r12 + 54h]       ; SizeOfHeaders
    mov  rsi, [rbp - CTX_SRC_BASE]
    mov  rdi, [rbp - CTX_DST_BASE]
    rep  movsb

    ; Locate destination NT headers.
    mov  rdx, [rbp - CTX_DST_BASE]
    mov  eax, dword ptr [rdx + 3Ch]
    add  rax, rdx
    mov  [rbp - CTX_DST_NT], rax

    ; Copy section raw data.
    movzx eax, word ptr [rax + 14h]       ; SizeOfOptionalHeader
    mov  r12, [rbp - CTX_DST_NT]
    lea  r14, [r12 + rax + 18h]           ; first section header
    movzx r13d, word ptr [r12 + 6]        ; NumberOfSections

MapImage_NextSection:
    test r13d, r13d
    jz   MapImage_Done

    mov  ecx, dword ptr [r14 + 10h]       ; SizeOfRawData
    test ecx, ecx
    jz   MapImage_Advance

    mov  esi, dword ptr [r14 + 14h]       ; PointerToRawData
    add  rsi, [rbp - CTX_SRC_BASE]
    mov  edi, dword ptr [r14 + 0Ch]       ; VirtualAddress
    add  rdi, [rbp - CTX_DST_BASE]
    rep  movsb

MapImage_Advance:
    add  r14, 28h
    dec  r13d
    jmp  MapImage_NextSection

MapImage_Done:
    mov  eax, 1
    ret

MapImage_Fail:
    xor  eax, eax
    ret
MapImage endp

;----------------------------------------------------------------------------------
; Clear the raw PE stored behind the SRDI header. The mapped image already owns all
; bytes needed after MapImage succeeds.
;----------------------------------------------------------------------------------
ClearSourcePe proc
    mov  rdi, [rbp - CTX_SRC_BASE]
    mov  rax, [rbp - CTX_HEADER]
    mov  ecx, dword ptr [rax + HDR_PE_SIZE]
    xor  eax, eax
    rep  stosb
    ret
ClearSourcePe endp

;----------------------------------------------------------------------------------
; Hide mapped-image PE header metadata after loader-only consumers are finished.
; This removes MZ/PE signatures, data directories, and section table names.
;----------------------------------------------------------------------------------
ScrubMappedPeHeaders proc
    mov  rbx, [rbp - CTX_DST_NT]
    mov  r12d, dword ptr [rbx + 54h]      ; SizeOfHeaders
    test r12d, r12d
    jz   ScrubMappedPeHeaders_Done

    mov  rdi, [rbp - CTX_DST_BASE]
    mov  ecx, r12d
    xor  eax, eax
    rep  stosb

    mov  rcx, [rbp - CTX_DST_BASE]
    mov  edx, r12d
    mov  r8d, 02h                         ; PAGE_READONLY
    lea  r9, [rbp - CTX_OLD_PROTECT]
    sub  rsp, 20h
    call qword ptr [rbp - CTX_API_VP]
    add  rsp, 20h

ScrubMappedPeHeaders_Done:
    ret
ScrubMappedPeHeaders endp

;----------------------------------------------------------------------------------
; Apply IMAGE_REL_BASED_DIR64 base relocations.
;----------------------------------------------------------------------------------
ApplyRelocations proc
    mov  rax, [rbp - CTX_DST_NT]
    mov  rbx, [rbp - CTX_DST_BASE]
    sub  rbx, qword ptr [rax + 30h]       ; delta = new base - ImageBase
    mov  [rbp - CTX_DELTA], rbx
    test rbx, rbx
    jz   Reloc_Done

    mov  edx, dword ptr [rax + 0B0h]      ; Base relocation directory RVA
    mov  ecx, dword ptr [rax + 0B4h]      ; directory size
    test edx, edx
    jz   Reloc_Done
    test ecx, ecx
    jz   Reloc_Done

    add  rdx, [rbp - CTX_DST_BASE]
    mov  r13, rdx
    add  r13, rcx                         ; end of relocation directory

Reloc_NextBlock:
    cmp  rdx, r13
    jae  Reloc_Done
    mov  eax, dword ptr [rdx]             ; VirtualAddress
    test eax, eax
    jz   Reloc_Done

    mov  ecx, dword ptr [rdx + 4]         ; SizeOfBlock
    cmp  ecx, 8
    jb   Reloc_Done

    lea  rsi, [rdx + 8]
    mov  r12, rdx
    add  r12, rcx                         ; current block end

Reloc_NextEntry:
    cmp  rsi, r12
    jae  Reloc_AdvanceBlock

    movzx eax, word ptr [rsi]
    mov  ebx, eax
    shr  ebx, 12
    cmp  ebx, 0Ah                         ; IMAGE_REL_BASED_DIR64
    jne  Reloc_AdvanceEntry

    and  eax, 0FFFh
    add  eax, dword ptr [rdx]
    add  rax, [rbp - CTX_DST_BASE]
    mov  rbx, [rax]
    add  rbx, [rbp - CTX_DELTA]
    mov  [rax], rbx

Reloc_AdvanceEntry:
    add  rsi, 2
    jmp  Reloc_NextEntry

Reloc_AdvanceBlock:
    mov  eax, dword ptr [rdx + 4]
    add  rdx, rax
    jmp  Reloc_NextBlock

Reloc_Done:
    ret
ApplyRelocations endp

;----------------------------------------------------------------------------------
; Initialize static TLS data for the current thread.
; This covers the important PELoader-style path:
;   AddressOfIndex + raw TLS data copy + TEB->ThreadLocalStoragePointer[index].
;
; First version intentionally supports the normal low TLS index range (< 64).
;----------------------------------------------------------------------------------
;----------------------------------------------------------------------------------
; Initialize static TLS data for the current thread.
; Delegates entirely to ntdll!LdrpHandleTlsData (no manual fallback).
;----------------------------------------------------------------------------------
HandleTlsData proc
    call TryLdrpHandleTlsData
    ret
HandleTlsData endp

; malefic-style TLS handling: find and call ntdll!LdrpHandleTlsData.
; Returns EAX=1 on success, EAX=0 on failure.
;----------------------------------------------------------------------------------
TryLdrpHandleTlsData proc
    ; No target TLS directory: treat as success/no-op.
    mov  rax, [rbp - CTX_DST_NT]
    mov  edx, dword ptr [rax + 0D0h]
    mov  ecx, dword ptr [rax + 0D4h]
    test edx, edx
    jz   TryLdrp_Success
    test ecx, ecx
    jz   TryLdrp_Success

    ; Locate ntdll.
    mov  r10d, HASH_NTDLL_MODULE
    call FindModuleBaseByHash
    test rax, rax
    jz   TryLdrp_Fail
    mov  [rbp - CTX_NTDLL_BASE], rax

    ; RtlGetVersion is optional but required for pattern choice.
    mov  rax, [rbp - CTX_API_RGV]
    test rax, rax
    jz   TryLdrp_Fail

    lea  rcx, [rbp - CTX_VERSION_BUF]
    mov  dword ptr [rcx], 11Ch
    sub  rsp, 20h
    call qword ptr [rbp - CTX_API_RGV]
    add  rsp, 20h

    mov  eax, dword ptr [rbp - CTX_VERSION_BUF + 0Ch]
    mov  [rbp - CTX_WIN_BUILD], rax

    cmp  eax, BUILD_WIN11_BETA
    jae  TryLdrp_Win11

    call SelectLdrpTlsPattern
    test eax, eax
    jz   TryLdrp_Fail

    ; Find ntdll .text.
    mov  rcx, [rbp - CTX_NTDLL_BASE]
    mov  r10d, 07865742Eh                 ; ".tex"
    mov  r11b, 074h                       ; "t"
    call FindSectionByName
    test rax, rax
    jz   TryLdrp_Fail
    test rdx, rdx
    jz   TryLdrp_Fail

    mov  rcx, rax
    ; RDX already holds text size.
    lea  r8, [rbp - CTX_PATTERN_BUF]
    movzx r9d, byte ptr [rbp - CTX_PATTERN_LEN]
    call ScanPattern
    test rax, rax
    jz   TryLdrp_Fail

    push rax                                ; save pattern match address
    mov  rcx, [rbp - CTX_NTDLL_BASE]        ; ntdll base
    mov  rax, rcx                           ; rax = ntdll base for NT headers calc
    mov  rdx, rcx                           ; copy for NT headers calc
    movzx edx, word ptr [rcx + 3Ch]        ; e_lfanew
    add  rdx, rax                           ; rdx = ntdll NT headers
    pop  r8                                 ; r8 = pattern match address
    call FindRuntimeFunctionStart
    test rax, rax
    jz   TryLdrp_Fail
    mov  [rbp - CTX_LDRP_TLS], rax
    jmp  TryLdrp_Call

TryLdrp_Win11:
    call FindLdrpHandleTlsWin11
    test rax, rax
    jz   TryLdrp_Fail
    mov  [rbp - CTX_LDRP_TLS], rax

TryLdrp_Call:
    lea  rdi, [rbp - CTX_FAKE_LDR]
    xor  eax, eax
    mov  ecx, 120h
    rep  stosb

    ; Match malefic-srdi's minimal x64 LDR_DATA_TABLE_ENTRY model:
    ; zeroed entry + DllBase only. Loader internals derive TLS metadata
    ; from the mapped image itself.
    mov  rax, [rbp - CTX_DST_BASE]
    mov  [rbp - CTX_FAKE_LDR + 30h], rax  ; DllBase

    lea  rcx, [rbp - CTX_FAKE_LDR]
    mov  rax, [rbp - CTX_LDRP_TLS]
    sub  rsp, 20h
    call rax
    add  rsp, 20h
    test eax, eax
    js   TryLdrp_Fail

    ; AddressOfIndex is optional, but when present it must point into image.
    mov  rax, [rbp - CTX_DST_NT]
    mov  edx, dword ptr [rax + 0D0h]
    add  rdx, [rbp - CTX_DST_BASE]
    mov  rdx, qword ptr [rdx + 10h]       ; IMAGE_TLS_DIRECTORY64.AddressOfIndex
    test rdx, rdx
    jz   TryLdrp_Success
    mov  r8, [rbp - CTX_DST_BASE]
    cmp  rdx, r8
    jb   TryLdrp_Fail
    sub  rdx, r8                          ; RVA of AddressOfIndex
    mov  eax, dword ptr [rax + 50h]       ; SizeOfImage
    cmp  eax, 4
    jb   TryLdrp_Fail
    sub  eax, 4
    cmp  rdx, rax
    ja   TryLdrp_Fail

TryLdrp_Success:
    mov  eax, 1
    ret

TryLdrp_Fail:
    xor  eax, eax
    ret
TryLdrpHandleTlsData endp

;----------------------------------------------------------------------------------
; Select malefic x64 LdrpHandleTlsData pattern for Win7-Win10.
; Returns EAX=1 if pattern selected.
;----------------------------------------------------------------------------------
SelectLdrpTlsPattern proc
    mov  eax, dword ptr [rbp - CTX_WIN_BUILD]
    cmp  eax, BUILD_WIN10_19H1
    jae  Pattern_Win10_19H1
    cmp  eax, BUILD_WIN10_RS4
    jae  Pattern_Win10_RS4
    cmp  eax, BUILD_WIN10_RS2
    jae  Pattern_Win10_RS2
    cmp  eax, BUILD_WIN81
    jae  Pattern_Win81
    cmp  eax, BUILD_WIN8
    jae  Pattern_Win8
    cmp  eax, BUILD_WIN7
    jae  Pattern_Win7
    xor  eax, eax
    ret

Pattern_Win10_19H1:
    jmp  Pattern_Win10_Common

Pattern_Win10_RS4:
    jmp  Pattern_Win10_Common

Pattern_Win10_RS2:

Pattern_Win10_Common:
    lea  rdi, [rbp - CTX_PATTERN_BUF]
    mov  dword ptr [rdi], 08D443374h
    mov  word ptr [rdi + 4], 0943h
    mov  byte ptr [rbp - CTX_PATTERN_LEN], 6
    mov  eax, 1
    ret

Pattern_Win81:
    lea  rdi, [rbp - CTX_PATTERN_BUF]
    mov  rax, 244C8D4C09438D44h
    mov  qword ptr [rdi], rax
    mov  byte ptr [rdi + 8], 038h
    mov  byte ptr [rbp - CTX_PATTERN_LEN], 9
    mov  eax, 1
    ret

Pattern_Win8:
    lea  rdi, [rbp - CTX_PATTERN_BUF]
    mov  rax, 01668D4530798B48h
    mov  qword ptr [rdi], rax
    mov  byte ptr [rbp - CTX_PATTERN_LEN], 8
    mov  eax, 1
    ret

Pattern_Win7:
    lea  rdi, [rbp - CTX_PATTERN_BUF]
    mov  rax, 08D4800000009B841h
    mov  qword ptr [rdi], rax
    mov  dword ptr [rdi + 7], 3824448Dh
    mov  byte ptr [rbp - CTX_PATTERN_LEN], 11
    mov  eax, 1
    ret
SelectLdrpTlsPattern endp



FindLdrpHandleTlsWin11 proc
    mov  r12, [rbp - CTX_NTDLL_BASE]
    test r12, r12
    jz   Win11_Fail

    ; Find ntdll .rdata and locate "LdrpInitializeTls\0".
    mov  rcx, r12
    mov  r10d, 06164722Eh                 ; ".rda"
    mov  r11b, 074h                       ; "t"
    call FindSectionByName
    test rax, rax
    jz   Win11_Fail
    test rdx, rdx
    jz   Win11_Fail
    mov  r14, rax                         ; rdata start
    mov  r15, rdx                         ; rdata size

    lea  rdi, [rbp - CTX_PATTERN_BUF]
    mov  rax, 74696E497072644Ch
    mov  qword ptr [rdi], rax
    mov  rax, 6C54657A696C6169h
    mov  qword ptr [rdi + 8], rax
    mov  word ptr [rdi + 10h], 073h

    mov  rcx, r14
    mov  rdx, r15
    lea  r8, [rbp - CTX_PATTERN_BUF]
    mov  r9d, 18
    call ScanPattern
    test rax, rax
    jz   Win11_Fail
    mov  r13, rax                         ; string absolute address

    ; Find ntdll .text.
    mov  rcx, r12
    mov  r10d, 07865742Eh                 ; ".tex"
    mov  r11b, 074h                       ; "t"
    call FindSectionByName
    test rax, rax
    jz   Win11_Fail
    test rdx, rdx
    jz   Win11_Fail
    mov  r14, rax                         ; text start
    mov  r15, rdx                         ; text size

    ; Find RIP-relative reference to the string.
    mov  rcx, r14
    mov  rdx, r15
    mov  r8, r13
    call FindRipLeaXref
    test rax, rax
    jz   Win11_Fail
    mov  r13, rax                         ; xref instruction

    ; Find first call after xref, then the next call after that.
    mov  rcx, r13
    mov  edx, 30h
    call FindFirstCall
    test rax, rax
    jz   Win11_Fail
    lea  rcx, [rax + 5]
    mov  edx, 30h
    call FindFirstCall
    test rax, rax
    jz   Win11_Fail
    mov  r13, rax                         ; call LdrAllocateTlsEntry

    ; Decode target of second call.
    mov  rcx, r13
    call DecodeCallTarget
    test rax, rax
    jz   Win11_Fail

    ; Find another call to LdrAllocateTlsEntry; its containing function is LdrpHandleTlsData.
    mov  rcx, r14
    mov  rdx, r15
    mov  r8, rax
    mov  r9, r13
    call FindCallToTarget
    test rax, rax
    jz   Win11_Fail

    push rax                                ; save call_xref
    mov  rcx, [rbp - CTX_NTDLL_BASE]        ; ntdll base
    mov  rax, rcx
    movzx edx, word ptr [rcx + 3Ch]        ; e_lfanew
    add  rdx, rax                           ; rdx = ntdll NT headers
    pop  r8                                 ; r8 = call_xref
    call FindRuntimeFunctionStart
    test rax, rax
    jz   Win11_Fail
    ret

Win11_Fail:
    xor  eax, eax
    ret
FindLdrpHandleTlsWin11 endp

;----------------------------------------------------------------------------------
; Find a loaded module by module-name ROR13 hash.
; Input:  R10D = module hash
; Output: RAX  = module base or 0
;----------------------------------------------------------------------------------
FindModuleBaseByHash proc
    xor  edx, edx
    mov  rdx, gs:[rdx + 60h]              ; PEB
    mov  rdx, [rdx + 18h]                 ; PEB->Ldr
    lea  r15, [rdx + 20h]                 ; InMemoryOrderModuleList head
    mov  rdx, [r15]

FindMod_Next:
    cmp  rdx, r15
    je   FindMod_Fail

    mov  rsi, [rdx + 50h]                 ; BaseDllName.Buffer
    movzx ecx, word ptr [rdx + 48h]       ; BaseDllName.Length
    xor  r8d, r8d

FindMod_Hash:
    xor  eax, eax
    lodsb
    cmp  al, 'a'
    jl   FindMod_Char
    sub  al, 20h
FindMod_Char:
    ror  r8d, 0Dh
    add  r8d, eax
    dec  ecx
    jnz  FindMod_Hash

    cmp  r8d, r10d
    je   FindMod_Found
    mov  rdx, [rdx]
    jmp  FindMod_Next

FindMod_Found:
    mov  rax, [rdx + 20h]                 ; DllBase
    jmp  FindMod_Done

FindMod_Fail:
    xor  eax, eax

FindMod_Done:
    ret
FindModuleBaseByHash endp

;----------------------------------------------------------------------------------
; Find a PE section by first four name bytes plus optional fifth byte.
; Input:  RCX = module base, R10D = first 4 name bytes, R11B = fifth byte or 0
; Output: RAX = section VA, RDX = virtual size. Both 0 on failure.
;----------------------------------------------------------------------------------
FindSectionByName proc
    push r12
    push r13

    xor  eax, eax
    xor  edx, edx
    test rcx, rcx
    jz   FindSec_Done
    cmp  word ptr [rcx], 5A4Dh
    jne  FindSec_Done

    mov  eax, dword ptr [rcx + 3Ch]
    add  rax, rcx
    cmp  dword ptr [rax], 00004550h
    jne  FindSec_Fail

    movzx ebx, word ptr [rax + 14h]
    lea  r12, [rax + rbx + 18h]
    movzx r13d, word ptr [rax + 6]

FindSec_Next:
    test r13d, r13d
    jz   FindSec_Fail

    cmp  dword ptr [r12], r10d
    jne  FindSec_Advance
    test r11b, r11b
    jz   FindSec_Found
    cmp  byte ptr [r12 + 4], r11b
    jne  FindSec_Advance

FindSec_Found:
    mov  edx, dword ptr [r12 + 8]         ; VirtualSize
    mov  eax, dword ptr [r12 + 0Ch]       ; VirtualAddress
    add  rax, rcx
    jmp  FindSec_Done

FindSec_Advance:
    add  r12, 28h
    dec  r13d
    jmp  FindSec_Next

FindSec_Fail:
    xor  eax, eax
    xor  edx, edx

FindSec_Done:
    pop  r13
    pop  r12
    ret
FindSectionByName endp

;----------------------------------------------------------------------------------
; Naive byte-pattern scan.
; Input:  RCX = start, RDX = size, R8 = pattern, R9D = pattern length
; Output: RAX = first match or 0
;----------------------------------------------------------------------------------
ScanPattern proc
    test rcx, rcx
    jz   Scan_Fail
    test rdx, rdx
    jz   Scan_Fail
    test r8, r8
    jz   Scan_Fail
    test r9d, r9d
    jz   Scan_Fail
    cmp  rdx, r9
    jb   Scan_Fail

    mov  r10, rcx                         ; current
    mov  r11, rcx
    add  r11, rdx
    sub  r11, r9                           ; last legal start

Scan_Outer:
    cmp  r10, r11
    ja   Scan_Fail
    xor  edi, edi
    mov  rsi, r8

Scan_Inner:
    cmp  edi, r9d
    jae  Scan_Found
    mov  al, byte ptr [r10 + rdi]
    cmp  al, byte ptr [rsi + rdi]
    jne  Scan_Next
    inc  edi
    jmp  Scan_Inner

Scan_Next:
    inc  r10
    jmp  Scan_Outer

Scan_Found:
    mov  rax, r10
    jmp  Scan_Done

Scan_Fail:
    xor  eax, eax

Scan_Done:
    ret
ScanPattern endp

;----------------------------------------------------------------------------------
; Decode x64 E8 rel32 call target.
; Input:  RCX = address of E8
; Output: RAX = absolute target or 0
;----------------------------------------------------------------------------------
DecodeCallTarget proc
    cmp  byte ptr [rcx], 0E8h
    jne  DecodeCall_Fail
    movsxd rax, dword ptr [rcx + 1]
    lea  rdx, [rcx + 5]
    add  rax, rdx
    ret

DecodeCall_Fail:
    xor  eax, eax
    ret
DecodeCallTarget endp

;----------------------------------------------------------------------------------
; Find an E8 rel32 call to target inside a text section.
; Input: RCX=text start, RDX=text size, R8=target, R9=skip call address or 0
; Output: RAX=call address or 0
;----------------------------------------------------------------------------------
FindCallToTarget proc
    test rcx, rcx
    jz   FindCall_Fail
    cmp  rdx, 5
    jb   FindCall_Fail

    mov  r10, rcx
    mov  r11, rcx
    add  r11, rdx
    sub  r11, 5

FindCall_Next:
    cmp  r10, r11
    ja   FindCall_Fail
    cmp  byte ptr [r10], 0E8h
    jne  FindCall_Advance
    cmp  r10, r9
    je   FindCall_Advance

    mov  rcx, r10
    call DecodeCallTarget
    cmp  rax, r8
    je   FindCall_Found

FindCall_Advance:
    inc  r10
    jmp  FindCall_Next

FindCall_Found:
    mov  rax, r10
    jmp  FindCall_Done

FindCall_Fail:
    xor  eax, eax

FindCall_Done:
    ret
FindCallToTarget endp

;----------------------------------------------------------------------------------
; Find first E8 call in a bounded range.
; Input: RCX=start, RDX=size
; Output: RAX=call address or 0
;----------------------------------------------------------------------------------
FindFirstCall proc
    test rcx, rcx
    jz   FindFirstCall_Fail
    test rdx, rdx
    jz   FindFirstCall_Fail
    mov  r10, rcx
    mov  r11, rcx
    add  r11, rdx

FindFirstCall_Next:
    cmp  r10, r11
    jae  FindFirstCall_Fail
    cmp  byte ptr [r10], 0E8h
    je   FindFirstCall_Found
    inc  r10
    jmp  FindFirstCall_Next

FindFirstCall_Found:
    mov  rax, r10
    ret

FindFirstCall_Fail:
    xor  eax, eax
    ret
FindFirstCall endp

;----------------------------------------------------------------------------------
; Find "4C 8D 05 rel32" that references target.
; Input: RCX=text start, RDX=text size, R8=target absolute address
; Output: RAX=instruction address or 0
;----------------------------------------------------------------------------------
FindRipLeaXref proc
    test rcx, rcx
    jz   FindXref_Fail
    cmp  rdx, 7
    jb   FindXref_Fail

    mov  r10, rcx
    mov  r11, rcx
    add  r11, rdx
    sub  r11, 7

FindXref_Next:
    cmp  r10, r11
    ja   FindXref_Fail
    cmp  byte ptr [r10 + 0], 04Ch
    jne  FindXref_Advance
    cmp  byte ptr [r10 + 1], 08Dh
    jne  FindXref_Advance
    cmp  byte ptr [r10 + 2], 005h
    jne  FindXref_Advance

    movsxd rax, dword ptr [r10 + 3]
    lea  rdx, [r10 + 7]
    add  rax, rdx
    cmp  rax, r8
    je   FindXref_Found

FindXref_Advance:
    inc  r10
    jmp  FindXref_Next

FindXref_Found:
    mov  rax, r10
    ret

FindXref_Fail:
    xor  eax, eax
    ret
FindRipLeaXref endp

;----------------------------------------------------------------------------------
; Approximate function start by walking back to int3/nop padding.
; Input: RCX=text start, RDX=text size, R8=address inside function
; Output: RAX=function start or 0
;----------------------------------------------------------------------------------
; FindRuntimeFunctionStart
;   Resolve a code address to its containing function entry by looking up
;   the PE's .pdata (IMAGE_DIRECTORY_ENTRY_EXCEPTION) RUNTIME_FUNCTION table.
;   This is the authoritative function-boundary source for x64 PEs.
;
; Input:  RCX = PE base (ntdll), RDX = NT headers, R8 = address inside function
; Output: RAX = function start address, or 0 on failure
;----------------------------------------------------------------------------------
;----------------------------------------------------------------------------------
; FindRuntimeFunctionStart
;   Resolve a code address to its containing function entry by looking up
;   the PE .pdata (IMAGE_DIRECTORY_ENTRY_EXCEPTION) RUNTIME_FUNCTION table.
;   This is the authoritative function-boundary source for x64 PEs.
;
; Input:  RCX = PE base (ntdll), RDX = NT headers, R8 = address inside function
; Output: RAX = function start address, or 0 on failure
;----------------------------------------------------------------------------------
FindRuntimeFunctionStart proc
    test rcx, rcx
    jz   RFS_Fail
    test rdx, rdx
    jz   RFS_Fail
    test r8, r8
    jz   RFS_Fail

    ; Exception directory: DataDirectory[3] at NT+0xA0 (RVA), NT+0xA4 (Size)
    mov  r9d, dword ptr [rdx + 0A0h]       ; exception directory RVA (NT+0x18+0x88)
    test r9d, r9d
    jz   RFS_Fail
    mov  r10d, dword ptr [rdx + 0A4h]       ; exception directory size (NT+0x18+0x8C)
    cmp  r10d, 0Ch                         ; sizeof(RUNTIME_FUNCTION) = 12
    jb   RFS_Fail

    ; Compute address RVA = address - pe_base
    mov  rax, r8
    sub  rax, rcx
    jb   RFS_Fail
    ; RAX = target RVA

    ; R10 = functions array = pe_base + exception_rva
    add  r9, rcx                           ; r9 = functions array base

    ; R11 = count = size / 12
    mov  r11d, r10d                        ; size
    xor  r10d, r10d                        ; count = 0
RFS_Div:
    cmp  r11d, 0Ch
    jb   RFS_DivDone
    sub  r11d, 0Ch
    inc  r10d
    jmp RFS_Div
RFS_DivDone:
    ; R10 = count, R9 = functions array, RAX = target RVA

RFS_Loop:
    test r10, r10
    jz   RFS_Fail

    ; functions[i].BeginAddress
    mov  r11d, dword ptr [r9]              ; BeginAddress
    cmp  r11d, eax                         ; BeginAddress <= RVA?
    ja   RFS_Next

    ; functions[i].EndAddress
    mov  r11d, dword ptr [r9 + 4]          ; EndAddress
    cmp  eax, r11d                         ; RVA < EndAddress?
    jae  RFS_Next

    ; Found: return pe_base + BeginAddress
    mov  r11d, dword ptr [r9]              ; BeginAddress
    mov  rax, rcx                          ; pe_base
    add  rax, r11
    ret

RFS_Next:
    add  r9, 0Ch                           ; next RUNTIME_FUNCTION (12 bytes)
    dec  r10
    jmp  RFS_Loop

RFS_Fail:
    xor  eax, eax
    ret
FindRuntimeFunctionStart endp



;----------------------------------------------------------------------------------
; Resolve normal imports. Supports OriginalFirstThunk == 0 fallback.
; Returns RAX=1 on success, RAX=0 on failure.
;----------------------------------------------------------------------------------
ResolveImports proc
    mov  rax, [rbp - CTX_DST_NT]
    mov  edx, dword ptr [rax + 90h]       ; Import directory RVA
    mov  ecx, dword ptr [rax + 94h]       ; Import directory size
    test edx, edx
    jz   Imports_Done
    test ecx, ecx
    jz   Imports_Done

    add  rdx, [rbp - CTX_DST_BASE]
    mov  r12, rdx                         ; IMAGE_IMPORT_DESCRIPTOR*

Imports_NextDll:
    cmp  dword ptr [r12 + 0Ch], 0         ; Name RVA
    je   Imports_Done

    mov  ecx, dword ptr [r12 + 0Ch]
    add  rcx, [rbp - CTX_DST_BASE]
    sub  rsp, 20h
    call qword ptr [rbp - CTX_API_LL]
    add  rsp, 20h
    test rax, rax
    jz   Imports_Fail
    mov  rbx, rax                         ; module handle

    mov  esi, dword ptr [r12]             ; OriginalFirstThunk
    test esi, esi
    jnz  Imports_HaveLookup
    mov  esi, dword ptr [r12 + 10h]       ; fallback to FirstThunk

Imports_HaveLookup:
    add  rsi, [rbp - CTX_DST_BASE]
    mov  edi, dword ptr [r12 + 10h]       ; FirstThunk/IAT
    add  rdi, [rbp - CTX_DST_BASE]

Imports_NextThunk:
    cmp  qword ptr [rsi], 0
    je   Imports_AdvanceDll

    mov  rax, qword ptr [rsi]
    mov  rdx, rax
    test rax, rax
    js   Imports_ByOrdinal

Imports_ByName:
    mov  rcx, rbx
    add  rdx, [rbp - CTX_DST_BASE]
    add  rdx, 2                           ; skip Hint
    sub  rsp, 20h
    call qword ptr [rbp - CTX_API_GPA]
    add  rsp, 20h
    jmp  Imports_WriteIat

Imports_ByOrdinal:
    and  rdx, 0FFFFh
    mov  rcx, rbx
    sub  rsp, 20h
    call qword ptr [rbp - CTX_API_GPA]
    add  rsp, 20h

Imports_WriteIat:
    test rax, rax
    jz   Imports_Fail
    mov  [rdi], rax
    add  rsi, 8
    add  rdi, 8
    jmp  Imports_NextThunk

Imports_AdvanceDll:
    add  r12, 14h
    jmp  Imports_NextDll

Imports_Done:
    mov  eax, 1
    ret

Imports_Fail:
    xor  eax, eax
    ret
ResolveImports endp

;----------------------------------------------------------------------------------
; Apply final section protections.
;----------------------------------------------------------------------------------
ProtectSections proc
    mov  rbx, [rbp - CTX_DST_NT]
    movzx eax, word ptr [rbx + 14h]
    lea  r12, [rbx + rax + 18h]
    movzx r13d, word ptr [rbx + 6]

Protect_NextSection:
    test r13d, r13d
    jz   Protect_Done

    mov  edx, dword ptr [r12 + 8]         ; VirtualSize
    mov  eax, dword ptr [r12 + 10h]       ; SizeOfRawData
    cmp  edx, eax
    jae  Protect_HaveSize
    mov  edx, eax

Protect_HaveSize:
    test edx, edx
    jz   Protect_Advance

    mov  eax, dword ptr [r12 + 24h]       ; Characteristics
    and  eax, 0E0000000h
    shr  eax, 29
    call Protect_GetValue
Protect_Table:
    db 01h, 10h, 02h, 20h, 08h, 80h, 04h, 40h

Protect_GetValue:
    pop  r11
    movzx r8d, byte ptr [r11 + rax]       ; flNewProtect

    mov  ecx, dword ptr [r12 + 0Ch]       ; VirtualAddress
    add  rcx, [rbp - CTX_DST_BASE]
    lea  r9, [rbp - CTX_OLD_PROTECT]
    sub  rsp, 20h
    call qword ptr [rbp - CTX_API_VP]
    add  rsp, 20h

Protect_Advance:
    add  r12, 28h
    dec  r13d
    jmp  Protect_NextSection

Protect_Done:
    ret
ProtectSections endp

;----------------------------------------------------------------------------------
; Flush CPU instruction cache after changing final section protections.
;----------------------------------------------------------------------------------
FlushInstructionCache proc
    mov  rax, [rbp - CTX_API_NFIC]
    test rax, rax
    jz   Flush_Done
    mov  rcx, -1
    xor  edx, edx
    xor  r8d, r8d
    sub  rsp, 20h
    call rax
    add  rsp, 20h
Flush_Done:
    ret
FlushInstructionCache endp

;----------------------------------------------------------------------------------
; Register x64 exception directory (.pdata) with the runtime.
; This matters for C++/Rust code that may touch unwind-aware runtime paths.
;----------------------------------------------------------------------------------
RegisterExceptionTable proc
    mov  rax, [rbp - CTX_API_RAF]
    test rax, rax
    jz   Exception_Done

    mov  rbx, [rbp - CTX_DST_NT]
    mov  edx, dword ptr [rbx + 0A0h]      ; Exception directory RVA
    mov  ecx, dword ptr [rbx + 0A4h]      ; Exception directory size
    test edx, edx
    jz   Exception_Done
    test ecx, ecx
    jz   Exception_Done

    mov  r11, [rbp - CTX_DST_BASE]
    add  rdx, r11                         ; FunctionTable
    mov  eax, ecx
    xor  edx, edx
    mov  ecx, 0Ch                         ; sizeof(RUNTIME_FUNCTION)
    div  ecx
    test eax, eax
    jz   Exception_Done

    ; RCX=FunctionTable, EDX=EntryCount, R8=BaseAddress.
    mov  rcx, [rbp - CTX_DST_NT]
    mov  edx, dword ptr [rcx + 0A0h]
    add  rdx, [rbp - CTX_DST_BASE]
    mov  rcx, rdx
    mov  edx, eax
    mov  r8, [rbp - CTX_DST_BASE]
    mov  rax, [rbp - CTX_API_RAF]
    sub  rsp, 20h
    call rax
    add  rsp, 20h

Exception_Done:
    ret
RegisterExceptionTable endp

;----------------------------------------------------------------------------------
; Execute TLS callbacks, if any.
;----------------------------------------------------------------------------------
RunTlsCallbacks proc
    mov  rax, [rbp - CTX_DST_NT]
    mov  edx, dword ptr [rax + 0D0h]      ; TLS directory RVA
    mov  ecx, dword ptr [rax + 0D4h]      ; TLS directory size
    test edx, edx
    jz   Tls_Done
    test ecx, ecx
    jz   Tls_Done

    add  rdx, [rbp - CTX_DST_BASE]
    mov  rdi, qword ptr [rdx + 18h]       ; AddressOfCallBacks VA
    test rdi, rdi
    jz   Tls_Done

Tls_Next:
    mov  rax, qword ptr [rdi]
    test rax, rax
    jz   Tls_Done

    mov  rcx, [rbp - CTX_DST_BASE]
    mov  edx, 1                           ; DLL_PROCESS_ATTACH
    xor  r8d, r8d
    sub  rsp, 20h
    call rax
    add  rsp, 20h

    add  rdi, 8
    jmp  Tls_Next

Tls_Done:
    ret
RunTlsCallbacks endp

;----------------------------------------------------------------------------------
; Call DLL DllMain then an optional export, or call the EXE OEP.
;----------------------------------------------------------------------------------
CallImageEntry proc
    mov  rsi, [rbp - CTX_DST_NT]
    mov  ax, word ptr [rsi + 16h]         ; FileHeader.Characteristics
    mov  ecx, dword ptr [rbp - CTX_FLAGS]
    test cx, RDI_FLAG_EXPORT
    jz   Entry_Default
    mov  r10d, dword ptr [rbp - CTX_EXPORT_HASH]
    test r10d, r10d
    jz   Entry_Default
    test ax, 2000h                        ; requested exports are DLL-only
    jz   Entry_Export_Fail

    mov  ebx, dword ptr [rsi + 28h]       ; AddressOfEntryPoint
    add  rbx, [rbp - CTX_DST_BASE]
    mov  [rbp - CTX_ENTRY], rbx
    call ResolveExportByHash
    test rax, rax
    jz   Entry_Export_Fail

    mov  [rbp - CTX_TMP], rax
    call ScrubMappedPeHeaders
    mov  rbx, [rbp - CTX_ENTRY]
    mov  rcx, [rbp - CTX_DST_BASE]
    mov  edx, 1                           ; DLL_PROCESS_ATTACH
    xor  r8d, r8d
    sub  rsp, 20h
    call rbx
    add  rsp, 20h
    test eax, eax
    jz   Entry_Export_Fail

    mov  rax, [rbp - CTX_TMP]
    mov  rcx, [rbp - CTX_DST_BASE]
    mov  rdx, [rbp - CTX_USER_PTR]
    mov  r8d, dword ptr [rbp - CTX_USER_LEN]
    sub  rsp, 20h
    call rax
    add  rsp, 20h
    ret

Entry_Export_Fail:
    xor  eax, eax
    ret

Entry_Default:
    mov  ax, word ptr [rsi + 16h]         ; FileHeader.Characteristics
    test ax, 2000h                        ; IMAGE_FILE_DLL
    jz   Entry_Exe

Entry_Dll:
    mov  ebx, dword ptr [rsi + 28h]       ; AddressOfEntryPoint
    add  rbx, [rbp - CTX_DST_BASE]
    mov  [rbp - CTX_TMP], rbx
    call ScrubMappedPeHeaders
    mov  rbx, [rbp - CTX_TMP]
    mov  rcx, [rbp - CTX_DST_BASE]
    mov  edx, 1                           ; DLL_PROCESS_ATTACH
    xor  r8d, r8d
    sub  rsp, 20h
    call rbx
    add  rsp, 20h
    ret

Entry_Exe:
    mov  ebx, dword ptr [rsi + 28h]       ; AddressOfEntryPoint
    add  rbx, [rbp - CTX_DST_BASE]
    mov  [rbp - CTX_TMP], rbx
    call ScrubMappedPeHeaders
    mov  rbx, [rbp - CTX_TMP]
    xor  ecx, ecx
    mov  edx, 1                           ; DLL_PROCESS_ATTACH-style EXE mode
    xor  r8d, r8d
    sub  rsp, 20h
    call rbx
    add  rsp, 20h
    ret
CallImageEntry endp

;----------------------------------------------------------------------------------
; Resolve an export from the mapped image by ROR13 function-name hash.
; Input:  R10D = function-name hash
; Output: RAX  = function VA or 0
;----------------------------------------------------------------------------------
ResolveExportByHash proc
    mov  rbx, [rbp - CTX_DST_BASE]
    mov  rax, [rbp - CTX_DST_NT]
    mov  edx, dword ptr [rax + 88h]       ; export RVA
    mov  ecx, dword ptr [rax + 8Ch]       ; export size
    test edx, edx
    jz   Export_Fail
    test ecx, ecx
    jz   Export_Fail

    add  rdx, rbx
    mov  r12, rdx                         ; IMAGE_EXPORT_DIRECTORY
    mov  ecx, dword ptr [r12 + 18h]       ; NumberOfNames
    mov  r8d, dword ptr [r12 + 20h]       ; AddressOfNames
    add  r8, rbx

Export_NextName:
    test ecx, ecx
    jz   Export_Fail
    dec  ecx

    mov  esi, dword ptr [r8 + rcx * 4]
    add  rsi, rbx
    call Ror13HashNTStr

    cmp  r11d, r10d
    jne  Export_NextName

    mov  r9d, dword ptr [r12 + 24h]       ; AddressOfNameOrdinals
    add  r9, rbx
    movzx ecx, word ptr [r9 + rcx * 2]
    mov  r9d, dword ptr [r12 + 1Ch]       ; AddressOfFunctions
    add  r9, rbx
    mov  eax, dword ptr [r9 + rcx * 4]
    add  rax, rbx
    jmp  Export_Done

Export_Fail:
    xor  eax, eax

Export_Done:
    ret
ResolveExportByHash endp

;----------------------------------------------------------------------------------
; Resolve loaded-module API by module+function ROR13 hash.
; Input:  R10D = module hash + function hash
; Output: RAX  = function VA or 0
;----------------------------------------------------------------------------------
ResolveApiByHash proc
    xor  edx, edx
    mov  rdx, gs:[rdx + 60h]              ; PEB
    mov  rdx, [rdx + 18h]                 ; PEB->Ldr
    lea  r15, [rdx + 20h]                 ; InMemoryOrderModuleList head
    mov  rdx, [r15]                       ; first entry

Api_NextModule:
    mov  rsi, [rdx + 50h]                 ; BaseDllName.Buffer
    movzx ecx, word ptr [rdx + 48h]       ; BaseDllName.Length
    xor  r8d, r8d

Api_ModuleHash:
    xor  eax, eax
    lodsb
    cmp  al, 'a'
    jl   Api_ModuleChar
    sub  al, 20h
Api_ModuleChar:
    ror  r8d, 0Dh
    add  r8d, eax
    dec  ecx
    jnz  Api_ModuleHash

    push rdx
    push r8

    mov  rbx, [rdx + 20h]                 ; DllBase
    mov  eax, dword ptr [rbx + 3Ch]
    add  rax, rbx
    cmp  word ptr [rax + 18h], 020Bh
    jne  Api_AdvanceModule

    mov  eax, dword ptr [rax + 88h]       ; export RVA
    test eax, eax
    jz   Api_AdvanceModule
    add  rax, rbx
    mov  r12, rax                         ; IMAGE_EXPORT_DIRECTORY

    mov  ecx, dword ptr [r12 + 18h]       ; NumberOfNames
    mov  r9d, dword ptr [r12 + 20h]       ; AddressOfNames
    add  r9, rbx

Api_NextFunction:
    test ecx, ecx
    jz   Api_AdvanceModule
    dec  ecx

    mov  esi, dword ptr [r9 + rcx * 4]
    add  rsi, rbx
    call Ror13HashNTStr                    ; R11D = function hash
    add  r11d, dword ptr [rsp]            ; add module hash
    cmp  r11d, r10d
    jne  Api_NextFunction

    mov  r9d, dword ptr [r12 + 24h]       ; AddressOfNameOrdinals
    add  r9, rbx
    movzx ecx, word ptr [r9 + rcx * 2]
    mov  r9d, dword ptr [r12 + 1Ch]       ; AddressOfFunctions
    add  r9, rbx
    mov  eax, dword ptr [r9 + rcx * 4]
    add  rax, rbx
    add  rsp, 10h                         ; drop saved module list/hash
    jmp  Api_Done

Api_AdvanceModule:
    pop  r8
    pop  rdx
    mov  rdx, [rdx]                       ; FLINK
    cmp  rdx, r15
    je   Api_Fail
    jmp  Api_NextModule

Api_Fail:
    xor  eax, eax

Api_Done:
    ret
ResolveApiByHash endp

end
