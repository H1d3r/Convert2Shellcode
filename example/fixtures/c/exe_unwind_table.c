#include "test_common.h"

extern IMAGE_DOS_HEADER __ImageBase;

typedef PRUNTIME_FUNCTION (WINAPI *RtlLookupFunctionEntryFn)(
    DWORD64 control_pc,
    PDWORD64 image_base,
    PUNWIND_HISTORY_TABLE history_table);

void Entry(void)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    RtlLookupFunctionEntryFn lookup;
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION function;

    if (ntdll == NULL) {
        TEST_WRITE_LITERAL("[rdi-test] exe_unwind_table fail\n");
        return;
    }

    lookup = (RtlLookupFunctionEntryFn)GetProcAddress(ntdll, "RtlLookupFunctionEntry");
    if (lookup == NULL) {
        TEST_WRITE_LITERAL("[rdi-test] exe_unwind_table fail\n");
        return;
    }

    function = lookup((DWORD64)(ULONG_PTR)&Entry, &image_base, NULL);
    if (function != NULL && image_base == (DWORD64)(ULONG_PTR)&__ImageBase) {
        TEST_WRITE_LITERAL("[rdi-test] exe_unwind_table ok\n");
    } else {
        TEST_WRITE_LITERAL("[rdi-test] exe_unwind_table fail\n");
    }
}
