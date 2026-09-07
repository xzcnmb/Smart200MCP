// probe_v28.cpp —— 第20版：完整 SYMSET 逻辑（创建表+地址解析+算行号+改名+保存）。
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstdarg>
#include <cctype>

#define WM_RUN (WM_APP + 0x1235)
static char g_result[MAX_PATH] = {0};
static void InitPaths(HINSTANCE hSelf) {
    char dir[MAX_PATH] = {0};
    GetModuleFileNameA(hSelf, dir, MAX_PATH);
    char* slash = strrchr(dir, '\\');
    if (slash) *(slash + 1) = 0; else dir[0] = 0;
    sprintf_s(g_result, "%sprobe_v28_result.txt", dir);
}
static void Log(const char* fmt, ...) {
    char buf[1500]; va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    HANDLE h = CreateFileA(g_result, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(h, buf, (DWORD)strlen(buf), &w, nullptr); WriteFile(h, "\r\n", 2, &w, nullptr); CloseHandle(h); }
}
struct U8 {
    char b[1024];
    explicit U8(const char* gbk) {
        b[0] = 0; if (!gbk) return;
        wchar_t w[512];
        int n = MultiByteToWideChar(936, 0, gbk, -1, w, 512);
        if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w, -1, b, sizeof(b), nullptr, nullptr);
        else strncpy_s(b, gbk, sizeof(b) - 1);
    }
    const char* c() const { return b; }
};
struct CStr {
    uint8_t* block; char** slot;
    CStr(const char* s, int refs = -1) {
        int n = (int)strlen(s);
        block = (uint8_t*)malloc(16 + n + 1);
        *(void**)block = nullptr; *(int*)(block + 4) = n; *(int*)(block + 8) = n; *(int*)(block + 12) = refs;
        memcpy(block + 16, s, n); block[16 + n] = 0;
        slot = (char**)malloc(4); *slot = (char*)(block + 16);
    }
    void* obj() { return slot; }
};
static HMODULE g_srv;
static void* Sym(const char* m) { return (void*)GetProcAddress(g_srv, m); }

// 解析地址 "I0.0"/"Q1.3" → (area, byte, bit)
static bool parse_addr(const char* a, int* area, int* byte, int* bit) {
    if (!a || !a[0]) return false;
    char ar = (char)toupper((unsigned char)a[0]);
    int j = 1;
    int b = 0;
    while (a[j] && a[j] != '.') { if (!isdigit((unsigned char)a[j])) return false; b = b * 10 + (a[j] - '0'); j++; }
    int bt = 0;
    if (a[j] == '.') { j++; while (a[j]) { if (!isdigit((unsigned char)a[j])) return false; bt = bt * 10 + (a[j] - '0'); j++; } }
    *area = (ar == 'Q') ? 2 : (ar == 'I') ? 1 : 0;
    *byte = b; *bit = bt;
    return (*area) != 0;
}

static void DoWork() {
    g_srv = GetModuleHandleA("storeretrieveverify.dll");
    void* gR = Sym("?g_Retrieve@@3VMWRetrieve@@A");
    void* gS = Sym("?g_Store@@3VMWStore@@A");
    Log("g_Retrieve=0x%p g_Store=0x%p", gR, gS);

    typedef int (__thiscall* CreateIO)(void*, unsigned char*);
    CreateIO cio = (CreateIO)Sym("?SYM_CreateIOSymbolTable@MWStore@@QAEJAAVMW_ID@@@Z");
    typedef int (__thiscall* SRows)(void*, const unsigned char*, unsigned short*);
    SRows srw = (SRows)Sym("?SYM_GetNumberRows@MWRetrieve@@QBEJABVMW_ID@@AAG@Z");
    typedef int (__thiscall* SSetName)(void*, const unsigned char*, unsigned short, void*);
    SSetName ssn = (SSetName)Sym("?SYM_SetName@MWStore@@QAEJABVMW_ID@@GABV?$CStringT@DV?$StrTraitMFC_DLL@DV?$ChTraitsCRT@D@ATL@@@@@ATL@@@Z");
    typedef int (__thiscall* Save)(void*);
    Save save = (Save)Sym("?PRJ_Save@MWRetrieve@@QBEJXZ");

    if (!cio || !srw || !ssn) { Log("API缺失"); Log("__DONE__"); return; }

    // 创建 I/O 表
    unsigned char id[16] = {0};
    int rc = cio(gS, id);
    unsigned short rows = 0; srw(gR, id, &rows);
    Log("CreateIO ret=%d rows=%u", rc, rows);
    int di_count = rows * 3 / 5;  // ST 系列 DI:DO = 3:2
    Log("推算 DI 数 = %d", di_count);

    // 测试几个地址
    struct { const char* addr; const char* name; } tests[] = {
        {"I0.0", "SYM_IN_00"}, {"I0.7", "SYM_IN_07"}, {"I1.0", "SYM_IN_10"},
        {"Q0.0", "SYM_OUT_00"}, {"Q0.7", "SYM_OUT_07"},
    };
    for (int i = 0; i < 5; i++) {
        int area = 0, byte = 0, bit = 0;
        if (!parse_addr(tests[i].addr, &area, &byte, &bit)) { Log("解析失败: %s", tests[i].addr); continue; }
        int row = (area == 1) ? (byte * 8 + bit) : (di_count + byte * 8 + bit);
        CStr nm(tests[i].name);
        int r = ssn(gS, id, (unsigned short)row, nm.obj());
        Log("SYMSET %s -> %s (row %d) ret=%d", tests[i].addr, tests[i].name, row, r);
    }

    if (save) { int rs = save(gR); Log("PRJ_Save ret=%d", rs); }
    Log("完成");
    Log("__DONE__");
}

static WNDPROC g_old = nullptr;
static HWND g_hwnd = nullptr;
static LRESULT CALLBACK NewProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_RUN) { DoWork(); return 0; }
    return CallWindowProcW(g_old, h, m, w, l);
}
static BOOL CALLBACK EnumProc(HWND h, LPARAM) {
    DWORD wpid = 0; GetWindowThreadProcessId(h, &wpid);
    if (wpid != GetCurrentProcessId()) return TRUE;
    wchar_t cls[64] = {0}; GetClassNameW(h, cls, 63);
    if (wcscmp(cls, L"SmartApp") == 0) { g_hwnd = h; return FALSE; }
    return TRUE;
}
static DWORD WINAPI Setup(LPVOID) {
    for (int i = 0; i < 60 && !g_hwnd; i++) { EnumWindows(EnumProc, 0); if (!g_hwnd) Sleep(500); }
    if (!g_hwnd) { Log("ERR: 找不到主窗口"); return 1; }
    Log("找到主窗口 hwnd=0x%p", (void*)g_hwnd);
    g_old = (WNDPROC)SetWindowLongPtrW(g_hwnd, GWLP_WNDPROC, (LONG_PTR)NewProc);
    SendMessageW(g_hwnd, WM_RUN, 0, 0);
    SetWindowLongPtrW(g_hwnd, GWLP_WNDPROC, (LONG_PTR)g_old);
    return 0;
}
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
    if (r == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(h); InitPaths(h); CreateThread(nullptr, 0, Setup, nullptr, 0, nullptr); }
    return TRUE;
}
