#include "test_common.h"

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH) {
        TEST_WRITE_LITERAL("[rdi-test] dll_export attach\n");
    }
    return TRUE;
}

__declspec(dllexport) void TestExport(void* image_base, const char* user_data, int user_len)
{
    (void)image_base;

    TEST_WRITE_LITERAL("[rdi-test] dll_export export user=");
    if (user_data && user_len > 0) {
        test_write(user_data, (DWORD)user_len);
    }
    TEST_WRITE_LITERAL("\n");
}
