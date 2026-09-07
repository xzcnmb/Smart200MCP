// inject_native.cpp —— 原生 LoadLibrary 注入器（x86，零依赖）。
// 用法: inject_native <pid> <dll路径>
#include <windows.h>
#include <cstdio>

int main(int argc, char** argv) {
    if (argc < 3) { printf("usage: inject_native <pid> <dll>\n"); return 1; }
    DWORD pid = (DWORD)atoi(argv[1]);
    const char* dll = argv[2];
    printf("inject '%s' -> pid %u\n", dll, pid);

    HANDLE h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!h) { printf("OpenProcess fail %d\n", GetLastError()); return 1; }

    size_t len = strlen(dll) + 1;
    void* mem = VirtualAllocEx(h, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { printf("VirtualAllocEx fail %d\n", GetLastError()); return 1; }
    SIZE_T written = 0;
    if (!WriteProcessMemory(h, mem, dll, len, &written)) { printf("WriteProcessMemory fail %d\n", GetLastError()); return 1; }

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    FARPROC loadLib = GetProcAddress(k32, "LoadLibraryA");
    printf("kernel32=0x%p LoadLibraryA=0x%p (injector is %d-bit)\n", (void*)k32, (void*)loadLib, (int)(sizeof(void*) * 8));

    HANDLE th = CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)loadLib, mem, 0, NULL);
    if (!th) { printf("CreateRemoteThread fail %d\n", GetLastError()); return 1; }
    WaitForSingleObject(th, 15000);
    DWORD exit = 0;
    GetExitCodeThread(th, &exit);
    printf("remote thread exit=0x%x (0x0 表示 LoadLibrary 成功返回了模块句柄)\n", (unsigned)exit);
    return 0;
}
