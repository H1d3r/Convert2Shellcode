#include "test_common.h"

__declspec(thread) unsigned int g_tls_value = 0x13572468;
static volatile LONG g_worker_ok;

static DWORD WINAPI TlsWorker(LPVOID parameter)
{
    (void)parameter;

    if (g_tls_value != 0x13572468) {
        TEST_WRITE_LITERAL("[rdi-test] exe_tls_thread worker initial fail\n");
        return 1;
    }

    TEST_WRITE_LITERAL("[rdi-test] exe_tls_thread worker initial ok\n");
    g_tls_value = 0x24681357;
    if (g_tls_value != 0x24681357) {
        TEST_WRITE_LITERAL("[rdi-test] exe_tls_thread worker write fail\n");
        return 1;
    }

    g_worker_ok = 1;
    TEST_WRITE_LITERAL("[rdi-test] exe_tls_thread worker write ok\n");
    return 0;
}

void Entry(void)
{
    HANDLE thread;

    if (g_tls_value == 0x13572468) {
        TEST_WRITE_LITERAL("[rdi-test] exe_tls_thread current ok\n");
    } else {
        TEST_WRITE_LITERAL("[rdi-test] exe_tls_thread current fail\n");
        return;
    }

    thread = CreateThread(NULL, 0, TlsWorker, NULL, 0, NULL);
    if (thread == NULL) {
        TEST_WRITE_LITERAL("[rdi-test] exe_tls_thread create fail\n");
        return;
    }

    if (WaitForSingleObject(thread, INFINITE) != WAIT_OBJECT_0) {
        TEST_WRITE_LITERAL("[rdi-test] exe_tls_thread wait fail\n");
        CloseHandle(thread);
        return;
    }
    CloseHandle(thread);

    if (g_worker_ok == 1) {
        TEST_WRITE_LITERAL("[rdi-test] exe_tls_thread complete ok\n");
    } else {
        TEST_WRITE_LITERAL("[rdi-test] exe_tls_thread complete fail\n");
    }
}
