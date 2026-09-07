# Smart200 MCP

用 MCP 驱动 **S7-200 SMART**（STEP 7-Micro/WIN SMART）做工程分析、程序部署、
在线监控与诊断 —— 对标本机 TIA Portal MCP，但架构完全不同：MicroWIN SMART 没有
Openness 等价物（无 COM、无命令行、内置 JSON-RPC 只管 PROFINET），所以做成
**五层混合架构**，各层可靠度不同，工具描述里都如实标注。

| 层 | 能力 | 状态 |
|---|---|---|
| **引擎调用（DLL 注入）** | 导出/导入/编译/权威验证/保存、**下载到 PLC / 上传 PLC 程序 / RUN-STOP / 事件日志** | ✅ 注入链路已实测；在线类 ⚠️ 已接线冒烟过、**未经真机验证** |
| AWL 解析 | 程序块文本解析、交叉引用、程序验证（网络/指令/地址读写） | ✅ 实测 |
| 离线工程解析 | V2 `.smart` 解包、符号、POU 名、功能框统计、工程对比 | ✅ 11/11 真实工程验证 |
| 在线通讯（snap7） | 读写 V/M/I/Q、**全部点位/实时监控/点位图比对**、CPU 状态/RUN-STOP/时钟/诊断探测 | ⚠️ 协议层按规范实现，**未经真机验证** |
| UI 自动化 | 读项目树（CPU 型号 + POU 列表）、点编译 | ✅ 实测（引擎路线打通后已非主力） |

> V3 `.smartV3` 离线解析：❌ 数据段加密 —— 但**引擎注入可处理 V3 工程**。
> 版本 **0.6.0**，共 **42 个 MCP 工具**。

## 安装（两种方式任选）

### 方式 A：pip 安装打包好的 wheel（推荐）

```bash
pip install --no-deps dist/smart200_mcp-0.6.0-py3-none-any.whl
# 依赖单独装：
pip install "mcp>=2.0.0" "python-snap7>=3.1.0" "pywinauto>=0.6.9"
```

安装后生成控制台入口 `smart200-mcp`，MCP 配置里 command 直接指它：

```json
{
  "mcpServers": {
    "smart200": {
      "type": "stdio",
      "command": "<Python 安装目录>/Scripts/smart200-mcp.exe",
      "timeoutMs": 120000
    }
  }
}
```

wheel 自带注入 DLL / 注入器（`smart200_mcp/native/`），拷到哪台 Windows 都能跑。

### 方式 B：源码运行

```bash
# 1. 依赖
pip install -r requirements.txt

# 2. （可选）重新编译注入 DLL —— 自动找 VS Build Tools，找不到会告诉你缺什么
python native/bootstrap/build.py

# 3. 挂上 MCP（command 指向 run.py）
claude mcp add smart200 -s user -- python <仓库路径>/run.py
```

挂好之后**先跑 `smart_doctor`**，它会一次说清缺什么、怎么补。

**路径不用改。** 仓库放哪个盘都行（注入 DLL 运行时自寻路径），MicroWIN 安装位置自动探测。
探测不到时按 `smart_doctor` 的提示设环境变量：

| 环境变量 | 作用 |
|---|---|
| `SMART200_EXE` | MicroWIN 可执行文件完整路径（MWSmart.exe / MWSmartV3.exe） |
| `SMART200_TEMPLATE` | 空白模板工程路径 |
| `SMART200_SCRIPT_TIMEOUT` | 单次注入等待上限，默认 180 秒；大工程编译/下载慢可调大 |

## 42 个工具速查

**先跑这个**：`smart_doctor`（环境自检）

| 分组 | 工具 |
|---|---|
| **部署（引擎注入）** | `smart_deploy`（⭐ 一步到位：设符号→导入→编译→五关验证→落盘）`smart_import_blocks` `smart_compile_and_export` `smart_validate_project` `smart_run_workflow` `smart_set_symbols` `smart_open_project` |
| **导出/查看** | `smart_export_all`（全块+符号表自包含导出）`smart_export_blocks` `smart_overview`（谁调用谁一屏看清）`smart_awl_analyze` `smart_check_stl`（离线秒级预检）`smart_xref`（交叉引用） |
| **离线解析** | `smart_probe` `smart_list_projects` `smart_analyze` `smart_symbols` `smart_function_blocks` `smart_compare` |
| **在线（snap7，直连 CPU）** | `smart_plc_info` `smart_plc_read` `smart_plc_write` `smart_plc_points`（全部 I/Q/M 点位）`smart_plc_monitor`（实时轮询）`smart_plc_compare_pointmap`（点位图比对）`smart_plc_run` `smart_plc_stop` `smart_plc_time`（读/设/同步时钟）`smart_plc_diag`（SZL 诊断探测）`smart_plc_blocks` |
| **在线（引擎路线，走软件通信栈）** | `smart_engine_status`（连接/运行模式/目标连接点）`smart_engine_run` `smart_engine_stop` `smart_plc_download`（**下载到 PLC**）`smart_plc_upload`（**上传 PLC 程序**）`smart_plc_compare`（**在线/离线差异报告**）`smart_event_log` |
| **程序监控** | `smart_monitor_program`（程序段监控：逐网络导通状态/线圈/操作数实时值） |
| **界面** | `smart_ui_project_tree` `smart_ui_output` `smart_ui_compile` |

## 90% 的活只用一个工具

```python
smart_deploy(
    awl_files=["motor.awl"],
    symbols={"电机启动": "I0.0", "电机运行": "Q0.0"},   # 可选：给 I/O 命名
    open_after=True,                                    # 顺手打开给人看
)
```

它一次注入里把**设符号 → 导程序 → 编译 → 五关验证 → 保存**全干完。
别拆成 `smart_set_symbols` + `smart_deploy` + `smart_open_project` 三次调用 ——
每次调用都要重启一个 MicroWIN 实例（约 16 秒等工程载入），拆开就是三倍时间。

## 典型场景

```python
# 拿到一个别人的工程，先看结构
smart_overview(project_path=".../xxx.smart")

# 写完 AWL，先离线预检（秒级）
smart_check_stl(awl_path="motor.awl")

# 部署 + 五关验证（权威判据问软件本人）
smart_deploy(awl_files=["motor.awl"], symbols={...})

# 全工程交叉引用：每个地址被谁读写、调用图
smart_xref(project_path=".../xxx.smart")

# 现场监控：程序段状态（需真机 + 工程路径）
smart_monitor_program(ip="192.168.2.1", project_path=".../xxx.smart")

# 下载到 PLC / 与现场比对（需真机，confirm 门把关）
smart_plc_download(project_path=".../xxx.smart", confirm=True)
smart_plc_compare(project_path=".../xxx.smart")
```

## 五关验证（`smart_deploy`）

**血泪教训：软件的 `COMPILE ret=0` 不能当通过判据。** 无效程序段会被标红并
**排除在编译之外**，其余照常编译 → 返回成功，据此报"已验证"会骗人（真踩过）。

| 关 | 干什么 | 性质 |
|---|---|---|
| 1 静态预检 | `stlcheck.py`：一个 Network 只能有一条 rung | 离线秒级，**启发式** |
| 2 导入+编译 | 抓语法与交叉引用错误（`CALL`/`ATCH` 指向不存在的块） | 必要不充分 |
| 3 **引擎真值** | `POU_IsValidNet` 逐网络问软件本人 | **权威判据** |
| 4 往返导出 | 逐块**逐条**核对指令流 + 网络数，抓静默丢弃 | 抓"说成功其实没做" |
| 5 落盘校验 | 比对工程文件指纹，证明真的写进磁盘了 | 前四关都在同一个内存实例里问软件自己 |

第 3 关才是权威：第 1 关是我写的规则、可能有盲区，第 3 关是软件自己的答案。
两者在已知样本上完全一致（坏样本精确命中 9/9、好样本零误报），不一致时以第 3 关为准。

### 用 AWL 干活必须知道的几条（都是实测踩出来的）

- **主程序的关键字是 `ORGANIZATION_BLOCK`，不是 `PROGRAM_BLOCK`**。写错了
  `IMPORTPOU` 照样返回 `ret=0`，但**什么都没导进去**（第 4 关才抓得到）。
- **导入 OB1 会替换整个程序集** —— 先导入的子程序会被抹掉。所以主程序必须排最前
  （`smart_deploy` 会自动重排并在报告里说明）。
- 其余按依赖排：被 `CALL` 的子程序、被 `ATCH` 的中断程序要在引用它们的块之前。
- **一个 .awl 含多个 BLOCK 时导入只吃到一个** → 拆成多个文件。
- **未定义的符号名会让整个网络变成无效程序段**（不是编译报错），第 3 关能抓到。
- **S7-200 SMART 没有 `NETR`/`NETW`**（那是 S7-200 的 PPI 指令）。以太网 S7 通信用
  `GET VB780` / `PUT VB800`。写错的助记符不报错，而是被当成未定义符号 → 整段无效。
  `smart_check_stl` 里有实测出来的黑名单，离线就能挡住。
- **AWL 直接用 UTF-8 写就行**：编码与行尾会自动规范成软件要的 ANSI+CRLF。
  遇到 GBK 表示不了的字符会报出**行号+具体字符**，不会静默替换成 `?`。
- **V2.8 落盘用 SAVE（SAVEAS 会崩）、V3 用 SAVEAS** —— 引擎内部已按版本自动处理，别手动干预。
- **从工程导出的 AWL 用的是符号名不是绝对地址**（软件会把符号表里有名字的地址替换掉），
  所以导出件**依赖那份符号表**。`smart_export_all` 会一并导出 `symbols.json`，
  拿整个目录就能原样重建工程。

## 符号表

给 I/O 地址命名后，AWL 里就能直接写符号名，可读性和现场维护性好得多：

```python
smart_deploy(["motor.awl"], symbols={"电机启动": "I0.0", "电机停止": "I0.1", "电机运行": "Q0.0"})
```

```stl
Network 1
	LD     电机启动
	O      电机运行
	AN     电机停止
	=      电机运行
```

要点（踩了很多弯路才搞清）：绝对地址符号走「I/O 变量」表（改那一行的名字，不是新建行）；
「变量表 1」是 V 区变量表、地址由编译器自动分配，想绑死绝对地址就别用它；
符号表必须落盘保存（V2.8 SAVE / V3 SAVEAS，引擎已自动处理）。

## 示例工程（`examples/`）

- `demo_station/`：从空白模板从零生成、五关验证过的完整工程 —— 双工位自动上料·加工·出料站，
  **18 块 / 231 网络 / 635 条指令 / 158 种指令助记符**，SCR 顺序控制、定时器/计数器、
  模拟量、PID、高速计数、脉冲输出、字符串、通信全都有。`src/*.awl` 是 UTF-8 源码直接改。
- `cylinder_control_template/`：两气缸控制模板（OB1 调 SBR0），带 I/O 分配表。
- `instruction_probe/`：问软件"这条指令你到底认不认"的可复跑探针。
  实测 22 条的结论是只有 `NETR`/`NETW` 不支持 —— 别凭印象回避指令。

## 安全红线（照搬 TIA MCP 的教训）

1. **注入只允许打到本模块自己启动的实例**（`engine._OWN_PIDS` 白名单，机器强制）
2. UI 层**只接管已打开的实例**，绝不替你打开/新建工程去顶掉正在编辑的内容
3. 绝不按进程名批量杀 `MWSmart.exe`
4. 写 PLC、下载、启停、点编译等会改变状态的操作，一律要求显式 `confirm=True`
5. 找不到控件/解不开文件就抛异常，**绝不静默返回空**——那会把失败伪装成成功
6. **改已存在的工程前自动备份** `<工程>.bak`
7. **进程退出时收掉自己起的实例**（`atexit`），只收自己起的
8. **注入串行化**：命令/结果文件全局只有一份，并发会串台
9. **上传 PLC 程序走副本**，绝不覆盖原工程文件

## 测试

```bash
python tests/test_stlcheck.py     # 网络结构 / SMART 不支持的助记符
python tests/test_enginelog.py    # 引擎日志判据
python tests/test_persist.py      # 落盘校验 + 第4关往返判据
python tests/test_encoding.py     # AWL 编码与行尾规范化
python tests/test_report.py       # deploy 报告裁剪
python tests/test_export.py       # 拆块 / 符号表读取 / 调用关系解析
python tests/test_online_xref.py  # CPU状态解析 / V2.8无缩进AWL / 交叉引用 / 格式解码
python tests/test_monitor.py      # 程序段监控 STL 求值器
python tests/test_plceng.py       # 引擎在线命令日志判读
python tests/test_all.py          # 容器/解析层，部分小节需真实工程样本（缺了打印 SKIP）
```

离线部分 clone 下来就能跑。每套都含**反向哨兵**（哨兵若 PASS 就说明测试本身坏了），
关键修复还做过故障注入验证 —— 把修复改回去，确认测试真的会 FAIL，再还原并核对文件 MD5。

**教训：判据自己有洞时，它会一路 PASS，看起来一切正常。**
唯一的发现办法是把判据抽成独立函数、给它本身写单测。

## 已知边界（诚实标注）

- **在线层（snap7 与引擎在线命令）均未经过真机验证**：开发时手边无 CPU。接真机请先
  用 `smart_plc_info` / `smart_engine_status` 试探；引擎在线命令的真机首验清单见
  `docs/ENGINE_ONLINE.md`（含 opmode 枚举校准、下载首试步骤）。
- **下载到 PLC 已接线但未真机验证**：`PRJ_Download` 全链（连接检查→能力探测→预检→下载）
  已接好、冒烟测试通过（未连接时正确 SKIP），但没在真 CPU 上跑过。
- **`smart_event_log` 只回读条数**：事件条目结构未逆向，内容解析待真机校准。
- **force 强制不支持**：S7-200 SMART 固件不实现（协议层无对应物），不要对标博图的强制表。
- **`smart_export_all` 的符号表读取**：V2.8 的 `SYM_GetRow` 卡死，读符号用
  `smart_symbols`（离线解析）替代。
- **`smart_ui_output`**：V2.8 输出窗口是自绘控件，UIA 读不到；编译结果请走
  `smart_compile_and_export` 的引擎日志。
- 不还原逐网络 LAD 图（定长记录字段布局未逆向完，强行输出等于编造）；语言切换
  （`PRJ_SetLang` 报成功没生效）；离线拿不到当前 CPU 型号（改由 UI 层读）。
- 编程语言只有 LAD / FBD / STL，**没有 SCL** —— 要写 SCL 得上 S7-1200/1500 + 博途。

## 文档索引

| 文档 | 内容 |
|---|---|
| `docs/V28_PORT.md` | V3→V2.8 符号映射、实测记录、突破过程 |
| `docs/v28_storeretrieveverify_exports.txt` | V2.8 全部 3565 个导出符号 dump |
| `docs/ENGINE_ONLINE.md` | 引擎在线命令（下载/上传/启停/事件日志）接线说明 + 真机首验清单 |
| `docs/COMML7_DIRECT.md` | commL7 通信栈逆向：脱机直连 CPU 的协议结论与验证对照表 |
| `DELIVERY.md` | V2.8 移植版交付清单 |

## 致谢

基于 [bulaofen0036-coder/Smart200-MicroWIN-MCP](https://github.com/bulaofen0036-coder/Smart200-MicroWIN-MCP)
移植到 STEP 7-Micro/WIN SMART **V2.8** 并扩展（在线监控、交叉引用、程序段监控、
引擎在线下载/上传/启停、脱机直连协议逆向）。
