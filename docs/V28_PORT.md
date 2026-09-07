# V2.8.2 移植逆向记录（符号映射）

目标：把 Smart200 MCP 的引擎注入层从 V3.2 移植到 STEP 7-Micro/WIN SMART V2.8.2。
逆向对象：`C:\Program Files (x86)\Siemens\STEP 7-MicroWIN SMART\`（V02.08.02.00）。

## 环境事实

| 项 | V3.2（原） | V2.8.2（本次） |
|---|---|---|
| 可执行文件 | `MWSmartV3.exe` | `MWSmart.exe` |
| 引擎 DLL | `storeretrieveverify.dll` | `storeretrieveverify.dll`（同名！） |
| 窗口类名 | `SmartApp` | `SmartApp`（exe 字符串命中，待运行时确认） |
| 位宽 | x86 | x86 |
| 空白模板 | `template.smartV3` | `template.smart`（⚠ 魔数 `DEM\0`+zlib@0x44，非 `SH3\0`） |
| 工程格式 | `.smartV3`(加密)/`.smart`(SH3\0+zlib@0x70) | `.smart`（真实工程格式待样本确认） |

## 符号映射总表

**✅ 同名可复用**（V3 → V2.8 完全一致）：

| 用途 | 符号 |
|---|---|
| 数据管理器全局 | `?g_Retrieve@@3VMWRetrieve@@A`、`?g_Store@@3VMWStore@@A` |
| 保存/另存 | `?PRJ_Save@MWRetrieve@@QBEJXZ`、`?PRJ_SaveAs@MWRetrieve@@QBEJABV?$CStringT@...@Z` |
| 通用导入 | `?PRJ_Import@MWStore@@QAEJABV?$CStringT@...AAG@Z` |
| 权威验证 | `?POU_IsValidNet@MWRetrieve@@QBEJABVMW_ID@@GAAHW4LANGUAGE@@@Z` |
| 网络数 | `?POU_GetNetCnt@MWRetrieve@@QBEJABVMW_ID@@AAG@Z` |
| 按名查块 | `?POU_FindPouByName@MWRetrieve@@QAEJABV?$CStringT@...AAVMW_ID@@@Z` |
| 枚举块 | `?POU_GetCount@MWRetrieve@@QBEJABW4MW_IDType@@AAG@Z`、`?POU_GetId@...`、`?POU_GetName@...` |
| 当前工程 | `?PRJ_GetCurrentProject@MWRetrieve@@QBEJAAG@Z`、`?PRJ_SetCurrentProject@MWStore@@QAEJABG@Z` |
| 语言 | `?PRJ_GetLang@MWRetrieve@@QBEJAAW4LANGUAGE@@@Z`、`?PRJ_SetLang@MWStore@@QAEJW4LANGUAGE@@@Z` |
| 梯形图尺寸 | `?LAD_GetNetworkDimensions@MWRetrieve@@QAEJVMW_ID@@GPAE11@Z` |

**🔄 改名/换签名**（V3 → V2.8）：

| 用途 | V3.2 符号 | V2.8.2 符号 |
|---|---|---|
| 导出 POU(AWL) | `PRJ_ExportPOU(MW_ID, CString, bool)` | `?PRJ_Export@MWRetrieve@@QBEJABVMW_ID@@ABV?$CStringT@...@Z`（无 bool） |
| 导出 XML | `PRJ_ExportXML` | **不存在**（V2.8 无 XML 导出） |
| 编译全部 | `PRJ_CompileAll` | **无此名**；候选 `?POU_CompilePous@MWStore@@QAEJAAG0H@Z` / `POU_CompilePou` / `Program_Before/AfterCompile` |
| 导入 AWL POU | `PRJ_ImportPouFile(CString, vector, bool, vector)` | **无文件级**；只有 `PRJ_Import(CString, ushort&)` + 块级 `PRJ_ImportPouBlock*` |
| 符号表(GVT) API | `GLBVAR_*`（行结构 `VARIABLE_ELEMENT`，行号 `int`） | **`SYM_*`**（行结构 `SYM_ELEMENT`，行号 `unsigned short`） |

## V2.8 符号表 API（SYM_*，取代 GLBVAR_*）

| 用途 | 符号 |
|---|---|
| 行数/取行 | `?SYM_GetNumberRows@MWRetrieve@@QBEJABVMW_ID@@AAG@Z`、`?SYM_GetRow@MWRetrieve@@QBEJABVMW_ID@@GAAUSYM_ELEMENT@@@Z` |
| 设名/值/注释 | `?SYM_SetName@MWStore@@QAEJABVMW_ID@@GABV?$CStringT@...@Z`、`?SYM_SetValue@...`、`?SYM_SetComment@...` |
| 设类型/整行 | `?SYM_SetDataType@MWStore@@QAEJABVMW_ID@@GABV?$CStringT@...@Z`、`?SYM_SetRow@MWStore@@QAEJABVMW_ID@@ABGABUSYM_ELEMENT@@@Z` |
| 插行/插符号 | `?SYM_InsertRow@MWStore@@QAEJABVMW_ID@@GG@Z`、`?SYM_InsertSymbol@MWStore@@QAEJABVMW_ID@@GABV?$CStringT@...11H@Z` |
| 按名查/取 | `?SYM_FindSymbol@MWStore@@QAEJABV?$CStringT@...AAVMW_ID@@AAG@Z`、`?SYM_GetSymbol@MWRetrieve@@QAEJABV?$CStringT@...AAUSYM_ELEMENT@@@Z` |
| 建 I/O 表/未定义表 | `?SYM_CreateIOSymbolTable@MWStore@@QAEJAAVMW_ID@@@Z`、`?SYM_CreateUndefinedSymbolTable@...`、`?SYM_CreateS7200SymbolTable@...` |
| 载入/保存表 | `?SYM_LoadSymbolTable@MWRetrieve@@QAEJABVMW_ID@@@Z`、`?SYM_SaveSymbolTable@MWStore@@QAEJABVMW_ID@@@Z` |
| 地址按名取 | `?SYM_GetAddressFromName@MWRetrieve@@QBEJABV?$CStringT@...AAUADDRESS_STRUCT@@@Z` |
| 校验 | `?SYM_ValidAddress@MWRetrieve@@QAEJV?$CStringT@...@Z`、`?SYM_ValidateSymName@...`、`?SYM_ValidateSymValue@...` |
| 表枚举 | `?SYM_GetCount@MWRetrieve@@QBEJABW4MW_IDType@@AAG@Z`、`?SYM_GetId@...`、`?SYM_GetName@...`、`?SYM_GetOffset@...` |

## 字符串管理器抠取（V3 用 GLBVAR_GetDataSize，V2.8 无）

V3 通过调用返回 CString 的函数读 header 首字段得字符串管理器。
V2.8 **无 MWRetrieve/MWStore 按值返回 CString 的函数**（按值返回的都是 DataLogDefinition/IODevice/TransferArea 等对象方法，拿不到实例）。

**改用 out 参数抠**：`?PRJ_GetName@MWRetrieve@@QBEJAAV?$CStringT@...@Z` 是 CString& out 参数，
传一个 refs=0x40000000 的 filler，调 `PRJ_GetName(gR, out)`，引擎赋值后从 out 数据头 -16 处读 manager。

## 其它发现

- **下载/上传存在**：`?PRJ_Download@MWStore@@QAEJW4BLOCK_TYPES@@PAUHWND__@@@Z`、`?PRJ_Upload@MWRetrieve@@QAEJW4BLOCK_TYPES@@@Z`（V3 也未接线，V2.8 同样待真机验证）。
- `template.smart` 是 `DEM\0`(v1.0 演示模板)+zlib@0x44，与作者文档的 `SH3\0`+zlib@0x70 不同 → 真实 V2.8 工程的离线格式待样本验证。
- 行号类型：V2.8 符号表行号是 `G`(unsigned short)，V3 是 `H`(int)。

## 实测结果（2026-08-29，本机 V02.08.02.00）

对真实工程 `PLC.smart`（天车/运动控制，主程序名为「主程序」）注入实测，全部打通：

| 操作 | V2.8 符号 | 实测 |
|---|---|---|
| 注入 | SmartApp 窗口子类化 | ✅ 稳定不崩 |
| 查块 | POU_FindPouByName | ✅ ret=0，找到「主程序」 |
| 导出 | PRJ_Export | ✅ ret=0，9288 字节 AWL（含全部块） |
| 编译 | POU_CompilePous(gS,&a,&b,0) | ✅ ret=0，out=0,553（0 错误） |
| 验证 | POU_IsValidNet | ✅ 4 网络全有效 |
| 保存 | PRJ_Save | ✅ ret=0 |
| 导入 | PRJ_Import(path,&w) | ✅ ret=0（V2.8 唯一文件级导入，能吃 .awl） |
| 写符号名 | SYM_SetName | ✅ ret=0，**已离线读回验证真写入**（122→124 符号） |
| 数行数 | SYM_GetNumberRows | ✅ ret=0 |
| 读行内容 | SYM_GetRow / SYM_GetName / SYM_LoadSymbolTable | ❌ **卡死**（独立线程也卡，非消息泵死锁；读路径懒加载未触发） |
| 另存为 | PRJ_SaveAs | ❌ 崩（内部拷贝存储路径，需字符串管理器） |

**关键结论：核心部署工作流（导入→编译→验证→导出→保存）在 V2.8 全部打通，
用 PRJ_Save 代替 PRJ_SaveAs 即可，不依赖字符串管理器。**

### 符号表位置（V2.8 与 V3 不同）

扫 MW_ID（id[4..5]=n、id[8]=variant、id[15]=0x80）实测：

| 表 | MW_ID | 行数 |
|---|---|---|
| 表A | n=0x0bb8, variant=0 | 39 |
| 表B | n=0x0bb9, variant=0 | 9 |
| 表C | n=0x0bb9, variant=1 | 10 |

V3 的表在 0x0d80-0x0dd0，V2.8 在 0x0bb8-0x0bb9。

⚠️ 实测 CPU 为 ST20（12DI+8DO+2AI+1AO≈23 点），而表A有 39 行 → **表A是系统变量表**（`SYM_LoadSystemTable` 返回其 id=0x0bb8 佐证）。

**突破（2026-08-30）**：V2.8 的 I/O 变量表是**懒加载**的，需 `SYM_CreateIOSymbolTable` 显式创建：
- 创建返回 id=`0x0bb9` variant=1，行数 = CPU 的 DI+DO（ST40=40 行）
- **行序 = I区（按位偏移 byte*8+bit）+ Q区（DI数 + 位偏移）**，DI数 = 总行数 × 3/5（ST 系列 DI:DO=3:2）
- 地址在 .smart 里二进制存储：名字后区号在 +4 字节（I=0x01/Q=0x02），位偏移在 +8 字节
- **SYM_SetName 按行号改名可用**（已验证离线读回），**V2.8 不需要 GVTCOMPILE**（符号表自动生效）

`SYM_GetRow`/`SYM_LoadSymbolTable` 仍卡死（读行内容无解），但 SYMSET（写符号）已可用"创建 I/O 表 + 按地址算行号 + SetName"绕开。

### 其他实测事实

- 块名是 GBK 中文（「主程序」），不是 "MAIN"。
- 真实 V2.8 工程 `PLC.smart` 魔数 `SH3\0` + zlib@0x70，与作者文档一致 → 离线解析层零改动。
- 安装目录里的 `template.smart` 是 `DEM\0`(v1.0 演示模板)，是特例不是真实格式。
- 软件用 mfc140.dll（VS2015），CString 布局与 V3 同代。
- **V2.8 导出格式：指令在行首【无 Tab 缩进】；V3 是 Tab 缩进**。作者 `_ops` 正则靠 `\t` 前缀认指令，
  已适配为"助记符后跟空白/行尾 + 关键字排除"，两种缩进都兼容。

## 端到端验证（2026-08-30，Python MCP server 实测）

Python 3.11.9 装好后，MCP server 各工具在真实 `PLC.smart` 上实测：

| 工具 | 结果 |
|---|---|
| smart_doctor | ✅ ok=True，正确路由 smarthook_v28.dll + inject_native.exe |
| smart_analyze | ✅ 项目名 PLC、122 符号、65 种功能框 |
| smart_export_blocks | ✅ 导出「主程序」9288 字节 AWL |
| smart_validate_project | ✅ 主程序 4 网络 0 无效 |
| **smart_deploy（五关）** | ✅ **全部 PASS**（导入→编译→验证→往返→落盘） |

**结论：V2.8.2 的核心 MCP 功能（引擎注入部署 + 五关验证 + 离线解析）已端到端打通。**

## 待办

- [x] 写 V2.8 版 smarthook（smarthook_v28.cpp）—— 核心命令已实现并实测
- [x] paths.py / engine.py / build.py / server.py 加 V2.8 路由
- [x] Python 环境（重装 3.11.9）+ 依赖（mcp/pywinauto/python-snap7）
- [x] 往返核对正则适配 V2.8 无 Tab 缩进导出格式
- [x] UI 层适配：smart_ui_project_tree 引擎补 POU、compile_project 按钮定位、_ob1_name 探测
- [x] SYMSET 命令接入 smarthook_v28（创建 I/O 表 + 地址算行号 + SetName）；smart_deploy 带符号五关 PASS、smart_set_symbols all_ok
- [ ] SYMDUMP（读符号表内容）：SYM_GetRow 卡死，读行内容无解（离线解析可替代读符号，见 smart_symbols）
- [ ] 在线通讯 snap7 真机验证（本机无 CPU）
