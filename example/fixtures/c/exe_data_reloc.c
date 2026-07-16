#include "test_common.h"

static const char g_relocated_text[] = "relocation";
static const char* g_relocated_ptr = g_relocated_text;
static unsigned int g_initialized_value = 0x11223344;
static unsigned int g_zero_fill_value;

void Entry(void)
{
    if (g_initialized_value == 0x11223344 &&
        g_zero_fill_value == 0 &&
        g_relocated_ptr == g_relocated_text &&
        g_relocated_ptr[0] == 'r') {
        TEST_WRITE_LITERAL("[rdi-test] exe_data_reloc initial ok\n");
    } else {
        TEST_WRITE_LITERAL("[rdi-test] exe_data_reloc initial fail\n");
    }

    g_initialized_value = 0x44332211;
    g_zero_fill_value = 0x55667788;
    if (g_initialized_value == 0x44332211 && g_zero_fill_value == 0x55667788) {
        TEST_WRITE_LITERAL("[rdi-test] exe_data_reloc write ok\n");
    } else {
        TEST_WRITE_LITERAL("[rdi-test] exe_data_reloc write fail\n");
    }
}
