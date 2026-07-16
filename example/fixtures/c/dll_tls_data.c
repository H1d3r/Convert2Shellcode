#include "test_common.h"

__declspec(thread) int g_tls_counter = 0x11223344;

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH) {
        if (g_tls_counter == 0x11223344) {
            TEST_WRITE_LITERAL("[rdi-test] dll_tls_data initial ok\n");
            g_tls_counter = 0x44332211;
        } else {
            TEST_WRITE_LITERAL("[rdi-test] dll_tls_data initial fail\n");
        }

        if (g_tls_counter == 0x44332211) {
            TEST_WRITE_LITERAL("[rdi-test] dll_tls_data write ok\n");
        } else {
            TEST_WRITE_LITERAL("[rdi-test] dll_tls_data write fail\n");
        }
    }
    return TRUE;
}
