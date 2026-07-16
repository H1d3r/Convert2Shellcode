#include "test_common.h"

extern IMAGE_DOS_HEADER __ImageBase;

void Entry(void)
{
    if (__ImageBase.e_magic == 0) {
        TEST_WRITE_LITERAL("[rdi-test] exe_header_scrub ok\n");
    } else {
        TEST_WRITE_LITERAL("[rdi-test] exe_header_scrub fail\n");
    }
}
