#include "test_common.h"

extern IMAGE_DOS_HEADER __ImageBase;

__declspec(thread) int g_tls_counter = 0x12345678;
__declspec(thread) int g_tls_callback_seen = 0;

static void NTAPI TlsCallback(PVOID module, DWORD reason, PVOID reserved)
{
    if (module == &__ImageBase && reason == DLL_PROCESS_ATTACH && reserved == NULL) {
        if (g_tls_counter == 0x12345678) {
            g_tls_callback_seen = 1;
            TEST_WRITE_LITERAL("[rdi-test] exe_full tls callback ok\n");
        } else {
            TEST_WRITE_LITERAL("[rdi-test] exe_full tls callback fail\n");
        }
    }
}

#if defined(_M_X64)
#pragma comment(linker, "/INCLUDE:_tls_used")
#elif defined(_M_IX86)
#pragma comment(linker, "/INCLUDE:__tls_used")
#endif

#if defined(_M_X64) || defined(_M_IX86)
#pragma const_seg(push)
#pragma const_seg(".CRT$XLB")
const PIMAGE_TLS_CALLBACK g_tls_callback = TlsCallback;
#pragma const_seg(pop)
#endif

void Entry(void)
{
    if (g_tls_callback_seen == 1 && g_tls_counter == 0x12345678) {
        TEST_WRITE_LITERAL("[rdi-test] exe_full tls data initial ok\n");
        g_tls_counter = (int)0x87654321;
    } else {
        TEST_WRITE_LITERAL("[rdi-test] exe_full tls data initial fail\n");
    }

    if (g_tls_counter == (int)0x87654321) {
        TEST_WRITE_LITERAL("[rdi-test] exe_full tls data write ok\n");
    } else {
        TEST_WRITE_LITERAL("[rdi-test] exe_full tls data write fail\n");
    }
}
