#include "test_common.h"

static void NTAPI TlsCallback(PVOID module, DWORD reason, PVOID reserved)
{
    (void)module;
    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH) {
        TEST_WRITE_LITERAL("[rdi-test] exe_tls tls\n");
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
    TEST_WRITE_LITERAL("[rdi-test] exe_tls entry\n");
}
