#include "test_common.h"

extern IMAGE_DOS_HEADER __ImageBase;

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    if (instance == (HINSTANCE)&__ImageBase &&
        reason == DLL_PROCESS_ATTACH &&
        reserved == NULL) {
        TEST_WRITE_LITERAL("[rdi-test] dll_entry_context ok\n");
    } else {
        TEST_WRITE_LITERAL("[rdi-test] dll_entry_context fail\n");
    }
    return TRUE;
}
