# Smart200 MCP（V2.8.2 移植版）交付清单

本仓库已从作者 V3.2 移植到 **STEP 7-Micro/WIN SMART V2.8.2**，核心功能全部打通并实测。
整个仓库可**整体复制到任意位置**（注入 DLL 运行时自寻路径，无写死绝对路径）。

---

## 一、交付文件清单

### 核心二进制（编译产物，直接可用，勿改）
| 文件 | 说明 |
|---|---|
| `native/bootstrap/smarthook_v28.dll` | V2.8 引擎注入 DLL（核心，脚本模式：EXPORT/COMPILE/VALIDATE/SAVE/IMPORTPOU/SYMSET） |
| `native/bootstrap/inject_native.exe` | 原生 x86 注入器（零 .NET 依赖，替代原 net8.0 注入器） |

### 源码（重新编译用）
| 文件 | 说明 |
|---|---|
| `native/bootstrap/smarthook_v28.cpp` | V2.8 注入 DLL 源码 |
| `native/bootstrap/inject_native.cpp` | 原生注入器源码 |
| `native/bootstrap/build.py` | 一键编译脚本（自动找 VS Build Tools，含 v28 编译） |

### MCP Server 本体（Python）
| 文件 | 说明 |
|---|---|
| `run.py` | 启动入口（stdio） |
| `smart200_mcp/` 整个目录 | 25 个 MCP 工具 + 底层引擎/离线/UI/在线层 |

**本仓库相对原作者改动/新增的 Python 文件**：
- `smart200_mcp/paths.py` — V2.8 路由（探测 MWSmart.exe、选 smarthook_v28.dll/inject_native.exe）
- `smart200_mcp/engine.py` — 按版本路由 DLL 和注入器
- `smart200_mcp/autoflow.py` — V2.8 用 SAVE 替代 SAVEAS、`_ops` 正则兼容无 Tab 缩进、`_ob1_name` 自动探测主程序块名、`set_symbols` 适配
- `smart200_mcp/server.py` — `smart_ui_project_tree` 用引擎补 POU、`smart_doctor` 路径路由
- `smart200_mcp/ui.py` — 读项目树提取工程路径、`compile_project` 按钮深层定位
- `native/bootstrap/build.py` — 追加编译 v28 DLL + 原生注入器

### 文档
| 文件 | 说明 |
|---|---|
| `docs/V28_PORT.md` | 完整符号映射（V3→V2.8）、实测记录、突破过程 |
| `docs/v28_storeretrieveverify_exports.txt` | V2.8 全部 3565 个导出符号 dump |

---

## 二、部署步骤

### 1. 环境要求
- Windows（需装有 STEP 7-Micro/WIN SMART V2.8，本机在 `C:\Program Files (x86)\Siemens\STEP 7-MicroWIN SMART\`）
- Python 3.10+（本机 3.11.9）
- VS Build Tools（仅重新编译 DLL 时需要，已编译好的 dll/exe 不需要）

### 2. 装依赖
```bash
pip install -r requirements.txt
# = mcp>=2.0.0  python-snap7>=3.1.0  pywinauto>=0.6.9
```

### 3.（可选）重新编译注入 DLL
```bash
python native/bootstrap/build.py
# 自动找 VS Build Tools；找不到会提示设 VCVARS 环境变量
```

### 4. 挂到 MCP 客户端

**Claude Desktop**（`claude_desktop_config.json`）：
```json
{
  "mcpServers": {
    "smart200": {
      "command": "python",
      "args": ["<仓库路径>/run.py"]
    }
  }
}
```

**命令行（Claude Code）**：
```bash
claude mcp add smart200 -s user -- python <仓库路径>/run.py
```

**通用 MCP 客户端**：配置 stdio server，command=`python`，args=`[<仓库路径>/run.py]`。

> 注意：若 `python` 不在 PATH，换成完整路径（本机为 `E:\my_project\AI\jobs\Python311\python.exe`）。

### 5. 挂好后先跑自检
MCP 客户端里先调用 `smart_doctor`，它会一次说清缺什么。

---

## 三、已验证能力（全部实测）

| 能力 | 工具 | 状态 |
|---|---|---|
| 环境自检 | smart_doctor | ✅ |
| 部署 AWL + 五关验证 | **smart_deploy**（含符号） | ✅ 五关全 PASS |
| 导入块 | smart_import_blocks | ✅ |
| 导出块 / 全部 | smart_export_blocks / smart_export_all | ✅ |
| 编译+导出 | smart_compile_and_export | ✅ |
| 权威验证 | smart_validate_project | ✅ |
| 离线预检 / AWL 解析 | smart_check_stl / smart_awl_analyze | ✅ |
| 离线工程解析 | smart_probe/list_projects/analyze/symbols/function_blocks/compare | ✅ |
| 打开工程给人看 | smart_open_project | ✅ |
| 实时读项目树（CPU+POU） | smart_ui_project_tree | ✅ |
| 点编译 | smart_ui_compile | ✅ |
| 脚本工作流 | smart_run_workflow | ✅ |
| **符号写入** | smart_set_symbols / smart_deploy(symbols=) | ✅ |
| 在线读写 PLC | smart_plc_info/read/write | ⚠️ 需真机 |

---

## 四、已知限制（诚实标注）

1. **smart_export_all / smart_overview 的符号表读取**：`symbols.json` / `io_symbols` 缺失——V2.8 的 `SYM_GetRow` 卡死（读行内容），读符号请用 `smart_symbols`（离线解析，正常）。
2. **smart_ui_output**：V2.8 输出窗口是自定义绘制控件，UIA 读不到编译结果文本；编译结果请用 `smart_compile_and_export` 走引擎日志。
3. **在线通讯 snap7**：代码就绪但未经真机验证（本机无 CPU）。
4. **V2.8 无 XML 导出**：软件本身不支持，非移植问题。
5. **下载到 PLC**：`PRJ_Download` 符号已定位但未接线（作者 V3 也未打通），需真机配合。

---

## 五、关键路径（默认自动探测，无需改）

| 环境变量 | 作用 |
|---|---|
| `SMART200_EXE` | MWSmart.exe 完整路径（自动探测失败时用） |
| `SMART200_TEMPLATE` | 空白模板路径 |
| `SMART200_SCRIPT_TIMEOUT` | 单次注入等待上限（默认 180 秒） |

也可写进仓库根 `.smart200_local.json`（见作者原 README）。

---

## 六、0.6.0 增量（2026-09，版本 0.6.0 / 42 个工具）

在 V2.8 移植版基础上新增四批能力，全部如实标注验证状态：

| 能力 | 工具 | 状态 |
|---|---|---|
| 在线读写扩展（snap7） | smart_plc_run/stop/time/diag/blocks + cpu_info 增强（真实状态 SZL 0x0424） | ⚠️ 协议层实现，未真机验证 |
| 点位/监控/比对 | smart_plc_points / smart_plc_monitor / smart_plc_compare_pointmap | ⚠️ 未真机验证 |
| 交叉引用 / 程序段监控 | smart_xref（纯 Python）/ smart_monitor_program（STL 求值器） | ✅ 求值器离线单测；在线读数待真机 |
| **引擎在线（注入 DLL 新命令）** | smart_plc_download（下载到 PLC）/ smart_plc_upload / smart_plc_compare（在线离线比对）/ smart_engine_run/stop / smart_engine_status / smart_event_log | ⚠️ 已接线+冒烟（未连接时正确 SKIP），**未经真机验证** |

关键实现：

- 注入 DLL（`smarthook_v28.cpp`）新增 6 命令：GETADDR / PLCSTATE / SETOPMODE /
  DOWNLOAD / UPLOAD / EVENTLOG，对应 PRJ_GetAccessPoint / COM_IsConnected /
  COM_GetOpMode / COM_SetOpMode / PRJ_Download / PRJ_Upload / COM_GetEventLog。
- **字符串管理器突破**：V2.8 无 GLBVAR_GetDataSize 可借，改为扫描全局门面对象里的
  活 CString（共享计数验真），解锁 CString 出参 API。
- 编译工具链：需 VS Build Tools 2022 的「使用 C++ 的桌面开发」工作负载
  （`python native/bootstrap/build.py` 自动探测）。
- 安全设计：DOWNLOAD/UPLOAD 未连接时 SKIP；上传走副本不碰原工程；改状态一律
  confirm 门；下载前回显工程配置的目标连接点防下错机。
- 真机首验清单见 `docs/ENGINE_ONLINE.md`；脱机直连协议逆向见 `docs/COMML7_DIRECT.md`。
- 打包：`pyproject.toml` + `python -m build --wheel`，产物 `dist/smart200_mcp-0.6.0-py3-none-any.whl`
  （自带注入 DLL/注入器，pip 安装即可用，入口 `smart200-mcp`）。
