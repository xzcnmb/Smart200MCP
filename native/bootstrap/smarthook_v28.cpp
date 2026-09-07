// smarthook_v28.cpp —— STEP 7-Micro/WIN SMART V2.8.2 专用引擎注入 DLL。
// 移植自 smarthook.cpp（V3.2），符号名按 V2.8.2 的 storeretrieveverify.dll 调整。
// 实测打通（2026-08-29/30，V02.08.02.00）：
//   注入 ✅  FindPouByName ✅  PRJ_Export ✅  POU_IsValidNet ✅  POU_CompilePous ✅
//   PRJ_Save ✅  PRJ_Import ✅  SYMSET ✅（创建I/O表+地址算行号+SetName） __DONE__ ✅
// 未打通：SAVEAS（崩，改用 SAVE）、SYMDUMP（SYM_GetRow 卡死，读符号用离线解析替代）。
// 新增接线（2026-09，⚠ 未经真机验证，MCP 层 confirm 门把关）：
//   GETADDR / PLCSTATE / SETOPMODE / DOWNLOAD / UPLOAD / EVENTLOG
//   （PRJ_GetAccessPoint / COM_IsConnected / COM_GetOpMode / COM_SetOpMode /
//    PRJ_Download / PRJ_Upload / PRJ_GetPrjRemoteAddress / COM_GetEventLog）
//
// 与 V3.2 的符号差异（详见 docs/V28_PORT.md）：
//   PRJ_ExportPOU  -> PRJ_Export（无 bool）
//   PRJ_CompileAll -> POU_CompilePous(unsigned short&, unsigned short&, int)
//   PRJ_ImportPouFile -> PRJ_Import（V2.8 唯一文件级导入）
//   GLBVAR_*       -> SYM_*（SYMSET 用 SYM_CreateIOSymbolTable + SYM_SetName 实现）
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstdarg>
#include <cctype>

// 命令/结果文件放在【本 DLL 自己旁边】，路径运行时从模块句柄取。
static char g_result[MAX_PATH] = {0};
static char g_cmdfile[MAX_PATH] = {0};

static void InitPaths(HINSTANCE hSelf) {
    char dir[MAX_PATH] = {0};
    GetModuleFileNameA(hSelf, dir, MAX_PATH);
    char* slash = strrchr(dir, '\\');
    if (slash) *(slash + 1) = 0; else dir[0] = 0;
    sprintf_s(g_result, "%sinject_result.txt", dir);
    sprintf_s(g_cmdfile, "%sinject_cmd.txt", dir);
}

#define RESULT  g_result
#define CMDFILE g_cmdfile
#define WM_SMART_RUN (WM_APP + 0x1234)

static void Log(const char* fmt, ...) {
    char buf[1200]; va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    HANDLE h = CreateFileA(RESULT, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(h, buf, (DWORD)strlen(buf), &w, nullptr); WriteFile(h, "\r\n", 2, &w, nullptr); CloseHandle(h); }
}

// 命令文件里的块名/路径是 GBK 字节，日志统一转成 UTF-8，避免两种编码混着。
struct U8 {
    char b[1024];
    explicit U8(const char* gbk) {
        b[0] = 0;
        if (!gbk) return;
        wchar_t w[512];
        int n = MultiByteToWideChar(936, 0, gbk, -1, w, 512);
        if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w, -1, b, sizeof(b), nullptr, nullptr);
        else { strncpy_s(b, gbk, sizeof(b) - 1); }
    }
    const char* c() const { return b; }
};

// ATL CString 的字符串管理器指针。SAVEAS/符号写入会拷贝存储 CString，需要它。
static void* g_strMgr = nullptr;

struct CStr {
    uint8_t* block; char** slot;
    CStr(const char* s, int refs = -1) {
        int n = (int)strlen(s);
        block = (uint8_t*)malloc(16 + n + 1);
        *(void**)block = g_strMgr; *(int*)(block + 4) = n; *(int*)(block + 8) = n; *(int*)(block + 12) = refs;
        memcpy(block + 16, s, n); block[16 + n] = 0;
        slot = (char**)malloc(4); *slot = (char*)(block + 16);
    }
    void* obj() { return slot; }
    ~CStr() { free(block); free(slot); }
};

static void SafeStr(void* cstrObj, char* out, int outsz) {
    out[0] = 0;
    if (!cstrObj) return;
    const char* d = *(const char**)cstrObj;
    if (!d) return;
    int n = *(const int*)((const uint8_t*)d - 12);
    if (n < 0) n = 0;
    if (n > outsz - 1) n = outsz - 1;
    memcpy(out, d, n); out[n] = 0;
}

static HMODULE g_srv;
static void* Sym(const char* m) { return (void*)GetProcAddress(g_srv, m); }
static WNDPROC g_oldProc = nullptr;
static HWND g_hwnd = nullptr;

// 抠字符串管理器：V2.8 没有 V3 的 GLBVAR_GetDataSize(按值返回 CString)可借。
// 首选：从已加载的 MFC DLL(或主 exe)取 AfxGetStringManager。
// 兜底：g_Retrieve/g_Store 是全局门面对象，其成员里必有活 CString —— 按 4 字节
// 对齐扫描成员，验证"CStringData 头在 data-16: [manager][len][alloc][refs]"布局，
// 取出现次数最多的 manager(真实管理器被无数字符串共享)。
// CString 出参赋值会走 Clone 路径、必须要有有效管理器，没有它 GETADDR/EVENTLOG 必崩。
static bool ValidHeader(uint8_t* d) {
    if (!d) return false;
    // 头在 data-16，检查必须覆盖它 —— 只查 d 会在 d<0x10 时下溢踩空
    uint8_t* hdr = d - 16;
    if (IsBadReadPtr(hdr, 32)) return false;
    void* mgr = *(void**)(hdr + 0);
    int len = *(int*)(hdr + 4);
    int alloc = *(int*)(hdr + 8);
    int refs = *(int*)(hdr + 12);
    if (!mgr || IsBadReadPtr(mgr, 4)) return false;
    if (len < 0 || len > (1 << 20)) return false;
    if (alloc < len || alloc > (1 << 20) + 64) return false;
    if (!(refs == -1 || (refs >= 1 && refs < 0x40000000))) return false;
    if (IsBadReadPtr(d, (size_t)(alloc > 0 ? alloc : 1) + 1)) return false;
    return true;
}

static void GrabStrMgr(void* gR, void* gS) {
    if (g_strMgr) return;
    static const char* names[] = {
        "mfc140u.dll", "mfc120u.dll", "mfc110u.dll", "mfc100u.dll",
        "mfc90u.dll", "mfc80u.dll", "mfc71u.dll", "mfc70u.dll",
    };
    HMODULE mods[16] = { nullptr };  // nullptr = 主 exe(静态链 MFC)
    int n = 1;
    for (const char* nm : names) {
        HMODULE m = GetModuleHandleA(nm);
        if (m && n < 16) mods[n++] = m;
    }
    for (int i = 0; i < n; i++) {
        void* fn = GetProcAddress(mods[i],
            "?AfxGetStringManager@@YGPAVIAtlStringMgr@@XZ");
        if (!fn) continue;
        typedef void* (__cdecl *GetMgr)();
        void* mgr = ((GetMgr)fn)();
        if (mgr) {
            g_strMgr = mgr;
            Log("[主线程] 字符串管理器=%p (AfxGetStringManager, 模块 #%d)", mgr, i);
            return;
        }
    }
    // 兜底：扫全局门面对象里的活 CString，按命中次数选管理器。
    // 真实管理器被对象里的无数字符串共享，命中最多的就是它。
    void* cand[256]; int candN[256] = {0}; int nCand = 0;
    void* candObj[256]; size_t candOff[256];
    void* bases[2] = { gR, gS };
    for (int bi = 0; bi < 2; bi++) {
        uint8_t* b = (uint8_t*)bases[bi];
        for (size_t off = 0; off < 16384; off += 4) {
            uint8_t* d = *(uint8_t**)(b + off);
            if (!d || !ValidHeader(d)) continue;
            void* mgr = *(void**)(d - 16);
            int k = 0;
            for (; k < nCand; k++) if (cand[k] == mgr) { candN[k]++; break; }
            if (k == nCand && nCand < 256) {
                cand[nCand] = mgr; candN[nCand] = 1;
                candObj[nCand] = bases[bi]; candOff[nCand] = off;
                nCand++;
            }
        }
    }
    void* best = nullptr; int bestN = 0; void* bestObj = nullptr; size_t bestOff = 0;
    for (int k = 0; k < nCand; k++) {
        if (candN[k] > bestN) {
            best = cand[k]; bestN = candN[k]; bestObj = candObj[k]; bestOff = candOff[k];
        }
    }
    if (best && bestN >= 2) {
        g_strMgr = best;
        Log("[主线程] 字符串管理器=%p (扫自 %s+0x%zx, 共享计数=%d)",
            best, bestObj == gR ? "g_R" : "g_S", bestOff, bestN);
        return;
    }
    Log("[主线程] 警告: 未找到字符串管理器(候选 %d, 最高命中 %d) —— CString 出参命令不可用",
        nCand, bestN);
}

// 解析绝对地址 "I0.0"/"Q1.3" → (area, byte, bit)。area: 1=I 2=Q。返回是否合法。
static bool parse_addr(const char* a, int* area, int* byte, int* bit) {
    if (!a || !a[0]) return false;
    char ar = (char)toupper((unsigned char)a[0]);
    int j = 1, b = 0;
    while (a[j] && a[j] != '.') {
        if (!isdigit((unsigned char)a[j])) return false;
        b = b * 10 + (a[j] - '0'); j++;
    }
    int bt = 0;
    if (a[j] == '.') { j++; while (a[j]) { if (!isdigit((unsigned char)a[j])) return false; bt = bt * 10 + (a[j] - '0'); j++; } }
    *area = (ar == 'Q') ? 2 : (ar == 'I') ? 1 : 0;
    *byte = b; *bit = bt;
    return *area != 0;
}

// —— 在主线程执行的引擎工作 ——
static void DoWork() {
    g_srv = GetModuleHandleA("storeretrieveverify.dll");
    void* gR = Sym("?g_Retrieve@@3VMWRetrieve@@A");
    void* gS = Sym("?g_Store@@3VMWStore@@A");
    Log("[主线程] g_Retrieve=0x%p g_Store=0x%p", gR, gS);
    GrabStrMgr(gR, gS);

    // 常用符号
    typedef int (__thiscall *FindByName)(void*, void*, unsigned char*);
    FindByName find = (FindByName)Sym("?POU_FindPouByName@MWRetrieve@@QAEJABV?$CStringT@DV?$StrTraitMFC_DLL@DV?$ChTraitsCRT@D@ATL@@@@@ATL@@AAVMW_ID@@@Z");
    typedef int (__thiscall *ExportPou)(void*, const unsigned char*, void*);
    ExportPou epou = (ExportPou)Sym("?PRJ_Export@MWRetrieve@@QBEJABVMW_ID@@ABV?$CStringT@DV?$StrTraitMFC_DLL@DV?$ChTraitsCRT@D@ATL@@@@@ATL@@@Z");
    typedef int (__thiscall *Compile)(void*, unsigned short*, unsigned short*, int);
    Compile comp = (Compile)Sym("?POU_CompilePous@MWStore@@QAEJAAG0H@Z");
    typedef int (__thiscall *Save)(void*);
    Save save = (Save)Sym("?PRJ_Save@MWRetrieve@@QBEJXZ");
    typedef int (__thiscall *Import)(void*, void*, unsigned short*);
    Import imp = (Import)Sym("?PRJ_Import@MWStore@@QAEJABV?$CStringT@DV?$StrTraitMFC_DLL@DV?$ChTraitsCRT@D@ATL@@@@@ATL@@AAG@Z");
    typedef int (__thiscall *GetNetCnt)(void*, const unsigned char*, unsigned short*);
    GetNetCnt getCnt = (GetNetCnt)Sym("?POU_GetNetCnt@MWRetrieve@@QBEJABVMW_ID@@AAG@Z");
    typedef int (__thiscall *IsValidNet)(void*, const unsigned char*, unsigned short, int*, int);
    IsValidNet isVal = (IsValidNet)Sym("?POU_IsValidNet@MWRetrieve@@QBEJABVMW_ID@@GAAHW4LANGUAGE@@@Z");
    // 符号表（SYM_*，V2.8 的 I/O 表懒加载，需先 CreateIOSymbolTable 创建）
    typedef int (__thiscall *CreateIO)(void*, unsigned char*);
    CreateIO cio = (CreateIO)Sym("?SYM_CreateIOSymbolTable@MWStore@@QAEJAAVMW_ID@@@Z");
    typedef int (__thiscall *SRows)(void*, const unsigned char*, unsigned short*);
    SRows srw = (SRows)Sym("?SYM_GetNumberRows@MWRetrieve@@QBEJABVMW_ID@@AAG@Z");
    typedef int (__thiscall *SSetName)(void*, const unsigned char*, unsigned short, void*);
    SSetName ssn = (SSetName)Sym("?SYM_SetName@MWStore@@QAEJABVMW_ID@@GABV?$CStringT@DV?$StrTraitMFC_DLL@DV?$ChTraitsCRT@D@ATL@@@@@ATL@@@Z");

    // —— 在线控制 / 下载上传 / 诊断（V2.8 新接线，⚠ 未经真机验证）——
    typedef int (__thiscall *GetAP)(void*, void*);
    GetAP getap = (GetAP)Sym("?PRJ_GetAccessPoint@MWStore@@QBEJAAV?$CStringT@DV?$StrTraitMFC_DLL@DV?$ChTraitsCRT@D@ATL@@@@@ATL@@@Z");
    typedef int (__thiscall *IsConn)(void*, int*);
    IsConn isconn = (IsConn)Sym("?COM_IsConnected@MWRetrieve@@QAEJAAH@Z");
    typedef int (__thiscall *GetOpMode)(void*, unsigned short*);
    GetOpMode gopm = (GetOpMode)Sym("?COM_GetOpMode@MWRetrieve@@QBEJPAG@Z");
    typedef int (__thiscall *SetOpMode)(void*, unsigned short);
    SetOpMode sopm = (SetOpMode)Sym("?COM_SetOpMode@MWStore@@QAEJG@Z");
    typedef int (__thiscall *IsPwd)(void*, int*);
    IsPwd ispwd = (IsPwd)Sym("?PRJ_IsPLCPasswordProtected@MWRetrieve@@QBEJAAH@Z");
    typedef int (__thiscall *IsDlBeg)(void*, int*);
    IsDlBeg isdl = (IsDlBeg)Sym("?PRJ_IsDownloadBeginSupported@MWRetrieve@@QBEJAAH@Z");
    typedef int (__thiscall *IsUlBeg)(void*, int*);
    IsUlBeg isul = (IsUlBeg)Sym("?PRJ_IsUploadBeginSupported@MWRetrieve@@QBEJAAH@Z");
    typedef int (__thiscall *PreCheckDl)(void*, int);
    PreCheckDl prechk = (PreCheckDl)Sym("?PRJ_PreCheckDownload@MWStore@@QAEJH@Z");
    typedef int (__thiscall *DlFn)(void*, int, void*);
    DlFn dlfn = (DlFn)Sym("?PRJ_Download@MWStore@@QAEJW4BLOCK_TYPES@@PAUHWND__@@@Z");
    typedef int (__thiscall *UlFn)(void*, int);
    UlFn ulfn = (UlFn)Sym("?PRJ_Upload@MWRetrieve@@QAEJW4BLOCK_TYPES@@@Z");
    typedef int (__thiscall *GetRemote)(void*, void*);
    GetRemote getremote = (GetRemote)Sym("?PRJ_GetPrjRemoteAddress@MWRetrieve@@QBEJAAVMWNetworkInfo@@@Z");
    typedef int (__thiscall *GetEvLog)(void*, int, int, void*, void**, int*);
    GetEvLog getev = (GetEvLog)Sym("?COM_GetEventLog@MWRetrieve@@QAEJHHAAVMWNetworkInfo@@PAPAUsCOMMCOMPASS_EVENT_LOG@@AAH@Z");

    Log("find=%p export=%p compile=%p save=%p import=%p", find, epou, comp, save, imp);

    // 读命令文件：第1行 action(应为 "script")，之后每行一条子命令。
    FILE* cf = nullptr; fopen_s(&cf, CMDFILE, "rb");
    if (!cf) { Log("无命令文件"); Log("__DONE__"); return; }
    char line[700]; int lineno = 0;
    while (fgets(line, sizeof(line), cf)) {
        lineno++;
        line[strcspn(line, "\r\n")] = 0;
        if (lineno == 1) continue;      // 跳过 action 行
        if (!line[0]) continue;
        char* sp = strchr(line, ' ');
        char* arg = sp ? sp + 1 : (char*)"";
        if (sp) *sp = 0;

        if (strcmp(line, "EXPORT") == 0) {
            // "名字|路径" —— 按名查 MW_ID，导出为 AWL
            char* bar = strchr(arg, '|');
            if (!bar) { Log("script EXPORT: 缺|"); continue; }
            *bar = 0; char* nm = arg; char* op = bar + 1;
            unsigned char id[16] = {0};
            if (find) { CStr c(nm); find(gR, c.obj(), id); }
            char hx[40]; for (int k = 0; k < 16; k++) sprintf_s(hx + k * 2, 3, "%02x", id[k]);
            CStr p(op);
            int r = epou ? epou(gR, id, p.obj()) : -1;
            Log("script EXPORT '%s' id=%s -> %s ret=%d(0x%x)", U8(nm).c(), hx, U8(op).c(), r, r);
        }
        else if (strcmp(line, "COMPILE") == 0) {
            unsigned short a = 0xFFFF, b = 0xFFFF;
            int r = comp ? comp(gS, &a, &b, 0) : -1;
            Log("script COMPILE ret=%d(0x%x) out=%u,%u", r, r, a, b);
        }
        else if (strcmp(line, "VALIDATE") == 0) {
            // "块名|语言" —— 逐网络 POU_IsValidNet
            int lang = 0; char* lb = strchr(arg, '|');
            if (lb) { *lb = 0; lang = atoi(lb + 1); }
            if (!find || !getCnt || !isVal) { Log("script VALIDATE: API缺失"); continue; }
            unsigned char id[16] = {0};
            CStr nm(arg); int fr = find(gR, nm.obj(), id);
            bool zero = true; for (int k = 0; k < 16; k++) if (id[k]) { zero = false; break; }
            if (zero) { Log("script VALIDATE '%s' ERR=块未找到 find_ret=%d", U8(arg).c(), fr); continue; }
            unsigned short cnt = 0; int cr = getCnt(gR, id, &cnt);
            if (cr != 0) { Log("script VALIDATE '%s' ERR=取网络数失败 ret=%d", U8(arg).c(), cr); continue; }
            int bad = 0;
            for (unsigned short i = 0; i < cnt; i++) {
                int out = -999;
                int r = isVal(gR, id, i, &out, lang);
                if (r != 0) { Log("script VALIDATE '%s' net=%u ERR ret=%d", U8(arg).c(), (unsigned)(i + 1), r); bad++; }
                else if (out == 0) { Log("script VALIDATE '%s' net=%u INVALID", U8(arg).c(), (unsigned)(i + 1)); bad++; }
            }
            Log("script VALIDATE '%s' nets=%u invalid=%d lang=%d", U8(arg).c(), cnt, bad, lang);
        }
        else if (strcmp(line, "SAVE") == 0) {
            int r = save ? save(gR) : -1;
            Log("script SAVE ret=%d(0x%x)", r, r);
        }
        else if (strcmp(line, "IMPORTPOU") == 0 || strcmp(line, "IMPORT") == 0) {
            // V2.8 无 PRJ_ImportPouFile，唯一文件级导入是 PRJ_Import
            CStr p(arg);
            unsigned short w = 0xFFFF;
            int r = imp ? imp(gS, p.obj(), &w) : -1;
            Log("script %s '%s' ret=%d(0x%x) out=%u", line, U8(arg).c(), r, r, w);
        }
        else if (strcmp(line, "SYMSET") == 0) {
            // "地址|名字"：给绝对地址(I0.0/Q0.0/...)命名。
            // V2.8 I/O 表懒加载：先 CreateIOSymbolTable 创建（40行=DI+DO），
            // 行序 = I区(按位偏移 byte*8+bit) + Q区(DI数 + 位偏移)，DI数 = 总行数*3/5。
            if (!cio || !srw || !ssn) { Log("script SYMSET: API缺失"); continue; }
            static unsigned char io_id[16] = {0};
            static bool io_created = false;
            static int di_count = 0;
            if (!io_created) {
                int rc = cio(gS, io_id);
                unsigned short rows = 0; srw(gR, io_id, &rows);
                di_count = rows * 3 / 5;
                io_created = true;
                char hx[40]; for (int k = 0; k < 16; k++) sprintf_s(hx + k * 2, 3, "%02x", io_id[k]);
                Log("script SYMSET: 创建I/O表 ret=%d rows=%u DI数=%d id=%s", rc, rows, di_count, hx);
            }
            char* bar = strchr(arg, '|');
            if (!bar) { Log("script SYMSET: 缺|"); continue; }
            *bar = 0; char* addr = arg; char* nm = bar + 1;
            int area = 0, byte = 0, bit = 0;
            if (!parse_addr(addr, &area, &byte, &bit)) { Log("script SYMSET: 地址解析失败 %s", addr); continue; }
            int row = (area == 1) ? (byte * 8 + bit) : (di_count + byte * 8 + bit);
            CStr cn(nm);
            int r = ssn(gS, io_id, (unsigned short)row, cn.obj());
            char hx[40]; for (int k = 0; k < 16; k++) sprintf_s(hx + k * 2, 3, "%02x", io_id[k]);
            Log("script SYMSET '%s' -> '%s' 表=%s 行=%d SetName=%d", U8(addr).c(), U8(nm).c(), hx, row, r);
        }
        else if (strcmp(line, "GETADDR") == 0) {
            // 读工程里配置的 PLC 连接点（下载前向用户复述目标，防下错 CPU）
            static CStr blank("", 0x40000000);
            void* slot = blank.obj();
            char out[512];
            int r = getap ? getap(gS, slot) : -1;
            SafeStr(slot, out, sizeof(out));
            Log("script GETADDR ret=%d(0x%x) accesspoint='%s'", r, r, U8(out).c());
        }
        else if (strcmp(line, "PLCSTATE") == 0) {
            int conn = -1, pwd = -1; unsigned short mode = 0xFFFF;
            int r1 = isconn ? isconn(gR, &conn) : -1;
            int r2 = gopm ? gopm(gR, &mode) : -1;
            int r3 = ispwd ? ispwd(gR, &pwd) : -1;
            Log("script PLCSTATE connected=%d opmode=%u pwd_protected=%d rets=%d/%d/%d",
                conn, (unsigned)mode, pwd, r1, r2, r3);
        }
        else if (strcmp(line, "SETOPMODE") == 0) {
            // 枚举未经真机核实：惯例 1=STOP 2=RUN（MCP 层强制 confirm）
            int m = atoi(arg);
            if (m != 1 && m != 2) { Log("script SETOPMODE: 参数必须是 1(STOP) 或 2(RUN)"); }
            else {
                int r = sopm ? sopm(gS, (unsigned short)m) : -1;
                unsigned short now = 0xFFFF; int rr = gopm ? gopm(gR, &now) : -1;
                Log("script SETOPMODE %d ret=%d(0x%x) now=%u", m, r, r, (unsigned)now);
            }
        }
        else if (strcmp(line, "DOWNLOAD") == 0) {
            // BLOCK_TYPES 枚举未知，0=全部(猜测)；真机首验时用参数 0/1/2 探测。
            int bt = (arg && *arg) ? atoi(arg) : 0;
            int conn = -1; isconn(gR, &conn);
            if (conn != 1) {
                Log("script DOWNLOAD SKIP=未连接PLC connected=%d", conn);
            } else {
                int sup = -1, rsup = isdl ? isdl(gR, &sup) : -1;
                Log("script DOWNLOAD IsDownloadBeginSupported ret=%d out=%d", rsup, sup);
                if (!isdl || rsup != 0 || sup != 1) { Log("script DOWNLOAD SKIP=能力探测不过"); }
                else {
                    int pc = prechk ? prechk(gS, 0) : -999;
                    Log("script DOWNLOAD PreCheck ret=%d(0x%x)", pc, pc);
                    if (pc != 0) { Log("script DOWNLOAD SKIP=PreCheck失败"); }
                    else {
                        int r = dlfn ? dlfn(gS, bt, g_hwnd) : -1;
                        Log("script DOWNLOAD block_types=%d ret=%d(0x%x)", bt, r, r);
                    }
                }
            }
        }
        else if (strcmp(line, "UPLOAD") == 0) {
            int bt = (arg && *arg) ? atoi(arg) : 0;
            int conn = -1; isconn(gR, &conn);
            if (conn != 1) {
                Log("script UPLOAD SKIP=未连接PLC connected=%d", conn);
            } else {
                int sup = -1, rsup = isul ? isul(gR, &sup) : -1;
                if (!isul || rsup != 0 || sup != 1) {
                    Log("script UPLOAD SKIP=能力探测不过 ret=%d out=%d", rsup, sup);
                } else {
                    int r = ulfn ? ulfn(gR, bt) : -1;
                    Log("script UPLOAD block_types=%d ret=%d(0x%x)", bt, r, r);
                }
            }
        }
        else if (strcmp(line, "EVENTLOG") == 0) {
            // MWNetworkInfo 结构未逆向：先用 PRJ_GetPrjRemoteAddress 让软件把
            // 工程里的连接参数填好，再原样传回 COM_GetEventLog；每 4 字节预填
            // CString filler，防结构里 CString 成员赋值时踩空。条目结构未逆向，
            // 只回读条数，内容等真机校准后再解析（见 docs/V28_PORT.md）。
            static CStr blank("", 0x40000000);
            void* filler = *(void**)blank.obj();
            char* ni = (char*)malloc(4096);
            for (int i = 0; i < 4096 / 4; i++) ((void**)ni)[i] = filler;
            int r0 = getremote ? getremote(gR, ni) : -1;
            void* entries = nullptr; int count = -1;
            int r1 = getev ? getev(gR, 0, 0, ni, &entries, &count) : -1;
            Log("script EVENTLOG GetRemoteAddr=%d GetEventLog=%d(0x%x) count=%d entries=0x%p",
                r0, r1, r1, count, entries);
            free(ni);
        }
        else {
            Log("script: 未支持命令 %s", line);
        }
    }
    fclose(cf);

    Log("[主线程] 完成");
    Log("__DONE__");
}

static LRESULT CALLBACK NewProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_SMART_RUN) { DoWork(); return 0; }
    return CallWindowProcW(g_oldProc, h, msg, wp, lp);
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
    if (!g_hwnd) { Log("ERR: 找不到本进程的 SmartApp 主窗口"); return 1; }
    Log("找到主窗口 hwnd=0x%p，子类化并投递 WM_SMART_RUN", (void*)g_hwnd);
    g_oldProc = (WNDPROC)SetWindowLongPtrW(g_hwnd, GWLP_WNDPROC, (LONG_PTR)NewProc);
    SendMessageW(g_hwnd, WM_SMART_RUN, 0, 0);
    SetWindowLongPtrW(g_hwnd, GWLP_WNDPROC, (LONG_PTR)g_oldProc);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        InitPaths(h);
        CreateThread(nullptr, 0, Setup, nullptr, 0, nullptr);
    }
    return TRUE;
}
