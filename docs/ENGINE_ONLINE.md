# 引擎路线 PLC 在线操作（V2.8 注入 DLL 新命令）

> 2026-09 新增接线。⚠ **全部未经真机验证** —— 这是接好线、可冒烟、但必须在真机首验
> 后才能宣称"能用"的一批功能。MCP 层对改状态的操作都有 confirm 门。

## 1. 新增 DLL 命令（smarthook_v28.cpp）

| 命令 | 引擎符号 | 作用 | 是否改状态 |
|---|---|---|---|
| `GETADDR` | `PRJ_GetAccessPoint(CString& out)` | 读工程里配置的 PLC 连接点（下载前复述目标） | 只读 |
| `PLCSTATE` | `COM_IsConnected` + `COM_GetOpMode` + `PRJ_IsPLCPasswordProtected` | 连接状态 / 运行模式 / 密码保护 | 只读 |
| `SETOPMODE n` | `COM_SetOpMode(ushort)` | RUN/STOP（n: 1=STOP, 2=RUN，枚举值**待真机核实**） | ✅ confirm |
| `DOWNLOAD [n]` | `PRJ_IsDownloadBeginSupported` → `PRJ_PreCheckDownload` → `PRJ_Download(BLOCK_TYPES, HWND)` | 下载工程程序到 PLC | ✅ confirm |
| `UPLOAD [n]` | `PRJ_IsUploadBeginSupported` → `PRJ_Upload(BLOCK_TYPES)` | 从 PLC 上传程序 | 只读（进副本） |
| `EVENTLOG` | `PRJ_GetPrjRemoteAddress` + `COM_GetEventLog` | 事件日志条数（条目结构未逆向，只回读 count） | 只读 |

调用约定全部 `__thiscall`，与已实测命令一致（见 V28_PORT.md）。CString 出参用
`refs=0x40000000` filler + SafeStr 有界读；MWNetworkInfo 结构未逆向，用
`PRJ_GetPrjRemoteAddress` 让软件自填 + 每 4 字节预填 filler 防 CString 成员赋值踩空。

## 2. 安全设计（无真机也不踩坑）

- `DOWNLOAD`/`UPLOAD` 在 **未连接时直接 SKIP**，不调下载函数 —— 冒烟测试不会误触发。
- `DOWNLOAD` 全链：连接检查 → 能力探测（IsDownloadBeginSupported）→
  PreCheckDownload → 才真正 Download；任何一步不过都停下来并写明原因。
- **上传走副本**：`smart_plc_upload` / `smart_plc_compare` 把工程拷到临时目录再
  UPLOAD+SAVE，原工程文件绝不动。
- BLOCK_TYPES 枚举未知，默认 0（猜测=全部块），真机首验用 0/1/2 探测。
- DOWNLOAD/EVENTLOG 可能超过 180s 脚本超时 —— 大工程用环境变量
  `SMART200_SCRIPT_TIMEOUT` 放宽。

## 3. MCP 工具（0.6.0 新增 7 个）

| 工具 | 路线 | 说明 |
|---|---|---|
| `smart_engine_status` | 引擎 | 连接状态/RUN-STOP/密码保护 + 工程配置的连接点。只读 |
| `smart_engine_run` / `smart_engine_stop` | 引擎 | RUN/STOP，confirm=True |
| `smart_plc_download` | 引擎 | **下载到 PLC**，confirm=True；返回含目标连接点、前后状态 |
| `smart_plc_upload` | 引擎 | 上传 CPU 程序（副本+导出），返回各块文本 |
| `smart_plc_compare` | 引擎 | **在线/离线差异报告**：上传后与本地工程逐块比对指令流/网络数 |
| `smart_event_log` | 引擎 | 事件日志条数（内容待真机校准） |

与 snap7 路线的分工：snap7（`smart_plc_read/monitor/run/stop/time/diag`）独立直连
CPU，不依赖软件在线；引擎路线（本批）走软件自己的通信栈，连接参数取自工程配置，
能做 snap7 做不到的**块传输（下载/上传）**。

## 4. 真机首验清单（按顺序执行）

1. `smart_doctor` 确认环境；接好 CPU 并在 MicroWIN「设备」里配好 IP（通信已连通）。
2. `smart_engine_status` —— 确认 connected=1、opmode 与 CPU 实际状态一致
   （**这一步同时校准 opmode 枚举：1/2 是否真的是 STOP/RUN**）。
3. `smart_plc_download(confirm=True)` 前先核对返回里的 accesspoint 就是目标 CPU；
   第一次用一个小工程试。
4. `smart_plc_upload` —— 上传后与 `smart_export_all` 的本地导出对照。
5. `smart_plc_compare` —— 找一份"现场改过"的 CPU 验证差异报告。
6. `smart_event_log` —— 记录 GetEventLog 的 ret；若 count>0，用 dumpbin/OD 把
   `sCOMMCOMPASS_EVENT_LOG` 条目结构逆向出来再解析内容。
7. 观察 DOWNLOAD 全程耗时，决定要不要调 `SMART200_SCRIPT_TIMEOUT`。

**任何一步不符合预期都如实回报**（连接不上、ret≠0、opmode 对不上），
先校准枚举和调用参数，不要把"ret=0"当成全部含义 —— 这是本项目一贯的红线。

## 5. 已知未接线（下一批候选，见 B 报告）

- `COM_SaveFaultInformation`：按值传 CString，调用约定需先实证，暂缓。
- `XREF_*` 21 个：软件原生交叉引用（结构黑盒）。
- `COM_GetDeviceInformation`：EX_PLCInformationData 结构未逆向。
- 事件日志条目解析：依赖第 6 步的条目结构逆向。
- SAVEAS：仍缺字符串管理器（STRMGR 命令），V2.8 落盘继续用 SAVE。
