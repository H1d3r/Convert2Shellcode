#include "test_common.h"

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH) {
        TEST_WRITE_LITERAL("[rdi-test] dll_basic attach\n");
    }
    return TRUE;
}
