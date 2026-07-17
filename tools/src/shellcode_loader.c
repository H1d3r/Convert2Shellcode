#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
    HANDLE h;
    LARGE_INTEGER li;
    DWORD read_bytes;
    DWORD tid;
    DWORD wait_ms = INFINITE;
    uint8_t* buf = NULL;
    void* mem;
    HANDLE thread;

    if (argc < 2) {
        printf("usage: %s <shellcode.bin> [timeout_ms]\n", argv[0]);
        return 1;
    }
    if (argc >= 3) {
        wait_ms = (DWORD)strtoul(argv[2], NULL, 0);
    }
    h = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFileA failed: %lu\n", GetLastError());
        return 1;
    }
    if (!GetFileSizeEx(h, &li) || li.QuadPart <= 0 || li.QuadPart > 0xffffffffu) {
        printf("[-] invalid file size\n");
        CloseHandle(h);
        return 1;
    }

    buf = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)li.QuadPart);
    if (!buf) {
        CloseHandle(h);
        return 1;
    }
    if (!ReadFile(h, buf, (DWORD)li.QuadPart, &read_bytes, NULL) ||
        read_bytes != (DWORD)li.QuadPart) {
        printf("[-] ReadFile failed: %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, buf);
        CloseHandle(h);
        return 1;
    }
    CloseHandle(h);

    mem = VirtualAlloc(NULL, (SIZE_T)li.QuadPart, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        printf("[-] VirtualAlloc failed: %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, buf);
        return 1;
    }
    CopyMemory(mem, buf, (SIZE_T)li.QuadPart);
    HeapFree(GetProcessHeap(), 0, buf);

    printf("[*] shellcode: %s (%lu bytes)\n", argv[1], (DWORD)li.QuadPart);
    printf("[*] running shellcode at %p\n", mem);

    thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, &tid);
    if (!thread) {
        printf("[-] CreateThread failed: %lu\n", GetLastError());
        return 1;
    }
    printf("[*] thread id: %lu\n", tid);

    if (WaitForSingleObject(thread, wait_ms) == WAIT_TIMEOUT) {
        printf("[*] timeout reached; shellcode thread is still running\n");
        CloseHandle(thread);
        return 0;
    }

    {
        DWORD code = 0;
        GetExitCodeThread(thread, &code);
        printf("[*] shellcode thread returned: %lu\n", code);
    }
    CloseHandle(thread);
    return 0;
}

