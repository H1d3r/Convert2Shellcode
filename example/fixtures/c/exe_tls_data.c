#include "test_common.h"

__declspec(thread) int g_tls_counter = 0x12345678;

void Entry(void)
{
    if (g_tls_counter == 0x12345678) {
        TEST_WRITE_LITERAL("[rdi-test] exe_tls_data initial ok\n");
        g_tls_counter = 0x87654321;
    } else {
        TEST_WRITE_LITERAL("[rdi-test] exe_tls_data initial fail\n");
    }

    if (g_tls_counter == (int)0x87654321) {
        TEST_WRITE_LITERAL("[rdi-test] exe_tls_data write ok\n");
    } else {
        TEST_WRITE_LITERAL("[rdi-test] exe_tls_data write fail\n");
    }
}
