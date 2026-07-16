#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static void test_write(const char* s, DWORD len)
{
    DWORD written = 0;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE) {
        WriteFile(h, s, len, &written, NULL);
    }
}

#define TEST_WRITE_LITERAL(s) test_write((s), (DWORD)(sizeof(s) - 1))
