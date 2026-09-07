"""Smart200 MCP Server —— S7-200 SMART (STEP 7-Micro/WIN SMART V3) 自动化。

三层能力，各自的可靠度不同，工具描述里都如实标注：
  离线工程解析  V2 .smart 完全可用；V3 .smartV3 加密，不支持
  在线通讯      snap7，代码完备但【未经真机验证】
  UI 自动化     读项目树已实测；编译未实测
"""

import glob
import os
import shutil
import tempfile

from mcp.server import MCPServer

from . import container, online, project, ui, awl, engine, paths, stlcheck, autoflow, pointmap, xref, monitor, plceng

mcp = MCPServer("smart200", version="0.6.0")


@mcp.tool()
def smart_doctor() -> dict:
    """环境自检：一次说清缺什么、怎么补。装好之后先跑这个。

    检查引擎 DLL、注入器、MicroWIN 安装位置、空白模板是否都就位。
    """
    missing = paths.check()
    return {
        "ok": not missing,
        "仓库根": paths.ROOT,
        "引擎DLL": paths.engine_dll(),
        "注入器": paths.injector(),
        "V2.8": paths.is_v28(),
        "MicroWIN": (paths.mwsmart() if not missing else "未找到"),
        "空白模板": paths.blank_template() or "未找到（新建工程会失败，可传 project_path 绕开）",
        "脚本超时秒": engine.SCRIPT_TIMEOUT,
        "问题": missing,
    }


# ---------- 离线工程解析 ----------

@mcp.tool()
def smart_probe(path: str) -> dict:
    """探查一个 .smart/.smartV3 工程能否离线解析，不解包。

    V2(.smart) 可解析；V3(.smartV3) 数据段加密，只能走 UI 自动化。
    """
    return container.probe(path)


@mcp.tool()
def smart_list_projects(directory: str, recursive: bool = True) -> dict:
    """扫描目录下的 S7-200 SMART 工程，并标出每个能否离线解析。"""
    pat = "**/*.smart*" if recursive else "*.smart*"
    files = [p for p in glob.glob(os.path.join(directory, pat), recursive=recursive)
             if p.lower().endswith((".smart", ".smartv3"))]
    return {"directory": directory, "count": len(files),
            "projects": [container.probe(p) for p in sorted(files)]}


@mcp.tool()
def smart_analyze(path: str) -> dict:
    """解析 V2 工程并汇总：项目名、版本、用户符号数、POU 名、功能框使用统计。

    注意：不还原逐网络 LAD/STL 逻辑（容器网络记录结构尚未逆向完成）；
    CPU 型号离线不可靠，需用 smart_ui_project_tree 读。
    """
    return project.summary(container.load(path))


@mcp.tool()
def smart_symbols(path: str) -> dict:
    """列出工程里用户定义的符号名（已剔除西门子系统 SM 符号表）。"""
    proj = container.load(path)
    syms = project.symbols(proj)
    return {"path": path, "count": len(syms), "symbols": syms}


@mcp.tool()
def smart_function_blocks(path: str) -> dict:
    """功能框（MOV_DW / MUL_DI / ...）使用直方图，用于快速判断程序在干什么。"""
    proj = container.load(path)
    fb = project.function_blocks(proj)
    return {"path": path, "kinds": len(fb),
            "total": sum(n for _, n in fb),
            "histogram": [{"name": k, "count": v} for k, v in fb]}


@mcp.tool()
def smart_compare(path_a: str, path_b: str) -> dict:
    """对比两个 V2 工程的符号与功能框差异 —— 同系列天车程序找改动点很有用。"""
    a, b = container.load(path_a), container.load(path_b)
    sa, sb = set(project.symbols(a)), set(project.symbols(b))
    fa, fb_ = dict(project.function_blocks(a)), dict(project.function_blocks(b))
    changed = {k: [fa.get(k, 0), fb_.get(k, 0)]
               for k in set(fa) | set(fb_) if fa.get(k, 0) != fb_.get(k, 0)}
    return {
        "a": project.info(a), "b": project.info(b),
        "symbols_only_in_a": sorted(sa - sb),
        "symbols_only_in_b": sorted(sb - sa),
        "function_block_count_diff": changed,
    }


# ---------- 在线通讯（snap7）----------

@mcp.tool()
def smart_plc_info(ip: str) -> dict:
    """读 CPU 型号/序列号/运行状态。⚠ 本层未经真机验证，接真机请先用此工具试探。"""
    with online.Plc(ip) as plc:
        return plc.cpu_info()


@mcp.tool()
def smart_plc_read(ip: str, addresses: list[str], fmt: str = "auto") -> dict:
    """读一批地址，如 ["VW100","V10.3","QB0"]。V 区映射为 DB1。⚠ 未经真机验证。

    fmt 给这批地址统一解码格式：auto（按宽度给无符号整数/位给 bool）/
    int（有符号16位）/ dint（有符号32位）/ real（IEEE754 浮点）/ string（Pascal 字符串）。
    位地址（如 V10.3）恒返回 bool，忽略 fmt。
    """
    with online.Plc(ip) as plc:
        return {"ip": ip, "values": plc.read_many(addresses, fmt or "auto")}


@mcp.tool()
def smart_plc_write(ip: str, address: str, value: int, confirm: bool = False) -> dict:
    """向 PLC 写值。

    ⚠ 写运行中的 PLC 是不可逆的现场操作，必须 confirm=True。本层未经真机验证。
    """
    if not confirm:
        return {"refused": True,
                "reason": "写 PLC 是不可逆现场操作，需显式 confirm=True；且本层尚未真机验证"}
    with online.Plc(ip) as plc:
        return plc.write(address, value)


# ---------- 在线监控 / 点位读取 / 点位图比对（snap7，同一套 S7 协议）----------

def _safe_read_points(ip, points, m_bytes=0):
    """按点位图逐地址读实时值；单个地址解析失败不拖垮整批。返回 (values, errors)。"""
    values, errors = {}, []
    with online.Plc(ip) as plc:
        for p in points:
            addr = p["address"]
            try:
                values[addr] = plc.read(addr, p.get("type") or "auto")
            except online.OnlineError as e:
                errors.append({"address": addr, "error": str(e)})
    return values, errors


@mcp.tool()
def smart_plc_points(ip: str, di_count: int = 0, do_count: int = 0,
                     include_m: bool = False, m_bytes: int = 0) -> dict:
    """批量读 PLC 当前 I/Q（可选 M）全部点位，返回点位表。⚠ 未经真机验证。

    直接对 PLC 读点位，不依赖工程文件 —— 适合"我有一份点位图，要核对现场 PLC
    实际点位"的场景。di_count/do_count 缺省时按 CPU 型号自动定（读整字节无损，
    会连同未用到的位一起返回，宁可多读不漏）。include_m=True 时额外读 m_bytes 个 M 字节。

    返回 points = [{"address":"I0.0","value":true}, ...]，含 inputs/outputs 计数。
    """
    with online.Plc(ip) as plc:
        info = plc.cpu_info()
        module = info.get("module_type") or ""
        pts = online.read_points(plc, di_count=di_count, do_count=do_count,
                                 include_m=include_m, m_bytes=m_bytes,
                                 module_type=module)
    inputs = [p for p in pts if p[0].startswith("I")]
    outputs = [p for p in pts if p[0].startswith("Q")]
    mem = [p for p in pts if p[0].startswith("M")]
    return {
        "ip": ip,
        "module_type": module,
        "count": len(pts),
        "input_count": len(inputs),
        "output_count": len(outputs),
        "memory_count": len(mem),
        "points": [{"address": a, "value": v} for a, v in pts],
    }


@mcp.tool()
def smart_plc_monitor(ip: str, addresses: list[str], interval: float = 0.5,
                      duration: float = 0.0, max_samples: int = 0,
                      fmt: str = "auto") -> dict:
    """实时轮询监控一批地址，返回时间序列（对标 STEP 7 状态图表）。⚠ 未经真机验证。

    每隔 interval 秒读一次 addresses，直到 duration 秒或 max_samples 个采样
    （两者都设取先到的；都不设默认采 5 个）。返回每个采样的值与相对上一采样的
    变化点，外加 latest（最新值）与 changed_overall（全程变过的地址）。

    用途：看某个 I 点被触发、某个 V 字在程序里累加、某个 Q 点输出翻转的过程。
    addresses 如 ["I0.0","Q0.0","VW100"]。fmt 给这批地址统一解码格式（同 smart_plc_read）。
    """
    result = online.monitor(ip, addresses, interval=interval, duration=duration,
                            max_samples=max_samples, fmt=fmt or "auto")
    return result


@mcp.tool()
def smart_plc_compare_pointmap(ip: str, pointmap_path: str) -> dict:
    """用点位图核对 PLC 当前点位：读点位图 → 读 PLC 实时值 → 逐点比对。⚠ 未经真机验证。

    点位图支持 JSON / CSV / TXT / XLSX（格式见 pointmap.parse_pointmap）：
      每行至少一列【地址】（I0.0 / Q0.0 / VB0 / VW100 / M0.0 …），可选
      【名称】【类型(BOOL/INT/REAL/… )】【期望值】。
    有期望值时逐点判一致/不一致；没有期望值就只回填实时值（等于给点位图补上现场状态）。

    返回 points（地址/名称/类型/期望/实际/是否一致）+ matched/mismatched/no_expected/missing
    计数，以及 mismatches 明细。单个地址解析失败会记在 errors 里，不拖垮整批。
    """
    points = pointmap.parse_pointmap(path=pointmap_path)
    if not points:
        return {"ip": ip, "pointmap": pointmap_path, "error": "点位图里没解析到任何有效点位"}
    values, errors = _safe_read_points(ip, points)
    result = pointmap.compare(values, points)
    result["ip"] = ip
    result["pointmap"] = pointmap_path
    if errors:
        result["errors"] = errors
    return result


# ---------- 在线通讯（snap7）扩展：运行控制 / 时钟 / 诊断 / 块 ----------

@mcp.tool()
def smart_plc_run(ip: str, confirm: bool = False) -> dict:
    """让 CPU 进入 RUN（热启动）。⚠ 改变现场设备运行状态，必须 confirm=True。未经真机验证。

    执行前后各读一次 CPU 状态（SZL 0x0424）回显。
    """
    if not confirm:
        return {"refused": True,
                "reason": "启停运行中的 PLC 是现场操作，需显式 confirm=True；且本层尚未真机验证"}
    with online.Plc(ip) as plc:
        return plc.plc_run()


@mcp.tool()
def smart_plc_stop(ip: str, confirm: bool = False) -> dict:
    """让 CPU STOP。⚠ 停止运行中的 PLC 是现场操作，必须 confirm=True。未经真机验证。

    执行前后各读一次 CPU 状态（SZL 0x0424）回显。
    """
    if not confirm:
        return {"refused": True,
                "reason": "启停运行中的 PLC 是现场操作，需显式 confirm=True；且本层尚未真机验证"}
    with online.Plc(ip) as plc:
        return plc.plc_stop()


@mcp.tool()
def smart_plc_time(ip: str, action: str = "read", value: str = "",
                   confirm: bool = False) -> dict:
    """读/设 CPU 时钟。action: read=读当前时间；set=设成 value（格式 "YYYY-MM-DD HH:MM:SS"）；
    sync=同步成这台电脑的时间。写操作(set/sync)需 confirm=True。⚠ 未经真机验证。"""
    import datetime
    with online.Plc(ip) as plc:
        if action == "read":
            return {"ip": ip, "datetime": plc.get_datetime().isoformat(sep=" ")}
        if not confirm:
            return {"refused": True, "reason": "改 CPU 时钟需显式 confirm=True"}
        if action == "sync":
            return plc.sync_datetime()
        if action == "set":
            dt = datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
            return plc.set_datetime(dt)
        raise online.OnlineError(f"未知 action {action!r}（read/set/sync）")


@mcp.tool()
def smart_plc_diag(ip: str) -> dict:
    """实验性诊断探测：逐个试读候选 SZL（诊断缓冲/强制表/CP 信息/CPU 状态），
    如实记录哪些读得通、原始内容长什么样。只读。

    S7-200 SMART 没有公开的 SZL 支持清单 —— 这是真机首次接入时的摸底工具，
    探通的再考虑转正式诊断工具。
    """
    with online.Plc(ip) as plc:
        return {"ip": ip, "probes": plc.diag_probe()}


@mcp.tool()
def smart_plc_blocks(ip: str) -> dict:
    """CPU 里的块计数（OB/FB/FC/DB/SDB/SFB/SFC）。只读。

    ⚠ S7-200 SMART 的块到 S7 块类型的映射未经真机验证，先如实给原始计数，
    真机核对后再解读（可用 smart_plc_diag 摸底）。
    """
    with online.Plc(ip) as plc:
        return {"ip": ip, "blocks": plc.list_blocks()}


@mcp.tool()
def smart_xref(project_path: str) -> dict:
    """全工程交叉引用（对标博图 cross-reference）。只读，不改工程。

    产出：每个绝对地址被哪些块/网络/指令读写（读写方向按指令族启发式判定）、
    每个块用了哪些地址和符号名、CALL/ATCH 调用图。
    数据来源：引擎 EXPORT OB1（带出全部块）→ 离线解析。
    """
    return xref.for_project(project_path)


@mcp.tool()
def smart_monitor_program(ip: str, project_path: str, block_name: str = "") -> dict:
    """程序段监控（对标 MicroWIN「程序监控」/ 博图 monitor block）。只读，不改 PLC 不改工程。

    原理与软件一致：CPU 不上报"哪个网络导通"，监控 = 读操作数实时值 + 本地逐网络求值。
    流程：引擎导出程序 → snap7 读实时值 → 每个网络给出 rung 导通状态、线圈状态、
    操作数实时值、定时器/计数器状态。

    block_name 留空 = 全部块；给了就只看那个块（块名或块号，如 "CYL_CTRL" 或 "SBR0"）。
    ⚠ 在线层未经真机验证；SCR/JMP/FOR 等控制流网络标 approximate（不仿真跳转）；
    有符号名的地址靠符号表映射，映射不了的网络 rung 为 null。
    """
    return monitor.monitor_project(ip, project_path, block_name)


# ---------- 引擎路线 PLC 在线操作（下载/上传/启停/事件日志）----------
# 走注入 DLL 的 GETADDR/PLCSTATE/SETOPMODE/DOWNLOAD/UPLOAD/EVENTLOG 命令，
# 由软件自己的通信栈干活，连接参数取自工程配置。⚠ 全部未经真机验证。

@mcp.tool()
def smart_engine_status(project_path: str) -> dict:
    """读 PLC 在线状态（引擎路线）：是否已连接、运行模式(RUN/STOP)、密码保护，
    以及工程里配置的 PLC 连接点（IP/站号）。只读。⚠ 未经真机验证。

    与 snap7 路线的 smart_plc_info 互补：这条走软件自己的通信栈，
    连接参数就是工程里配的，不用另传 IP。
    """
    plceng.require_v28()
    return plceng.status(project_path)


@mcp.tool()
def smart_engine_run(project_path: str, confirm: bool = False) -> dict:
    """让 PLC 进入 RUN（引擎路线，COM_SetOpMode）。⚠ 现场操作，必须 confirm=True。未经真机验证。

    与 snap7 路线的 smart_plc_run 区别：走软件通信栈、目标 PLC 取自工程配置。
    """
    plceng.require_v28()
    if not confirm:
        return {"refused": True,
                "reason": "启停运行中的 PLC 是现场操作，需显式 confirm=True；且本层尚未真机验证"}
    return plceng.set_opmode(project_path, "run")


@mcp.tool()
def smart_engine_stop(project_path: str, confirm: bool = False) -> dict:
    """让 PLC STOP（引擎路线，COM_SetOpMode）。⚠ 现场操作，必须 confirm=True。未经真机验证。"""
    plceng.require_v28()
    if not confirm:
        return {"refused": True,
                "reason": "启停运行中的 PLC 是现场操作，需显式 confirm=True；且本层尚未真机验证"}
    return plceng.set_opmode(project_path, "stop")


@mcp.tool()
def smart_plc_download(project_path: str, block_types: int = 0,
                       confirm: bool = False) -> dict:
    """【下载到 PLC】把工程程序下载到 CPU（引擎路线 PRJ_Download）。⚠ 必须 confirm=True。未经真机验证。

    流程：读工程配置的 PLC 连接点 → 读连接/运行状态 → 下载 → 回读状态。
    下载前请核对返回里的 accesspoint 就是目标 CPU —— 下错机是不可逆的。
    BLOCK_TYPES 枚举未知，0=全部块（猜测值），真机首验时用 0/1/2 探测。
    """
    plceng.require_v28()
    if not confirm:
        return {"refused": True,
                "reason": "下载会覆盖 PLC 里的程序，是不可逆现场操作，需显式 confirm=True；且本层尚未真机验证"}
    return plceng.download(project_path, block_types=block_types)


@mcp.tool()
def smart_plc_upload(project_path: str, block_types: int = 0) -> dict:
    """【从 PLC 上传程序】读回 CPU 里的程序（引擎路线 PRJ_Upload）。只读，不改 PLC 不改原工程。

    上传到临时副本再导出成 AWL，返回各块的文本；原工程文件不动。
    ⚠ 未经真机验证。想一键比对 PLC 与本地工程的差异，用 smart_plc_compare。
    """
    plceng.require_v28()
    up = plceng.upload(project_path, block_types=block_types)
    return {
        "project": project_path,
        "online": {"connected": up["state"]["connected"], "upload": up["upload"]},
        "blocks": [{"name": b["name"], "id": b["id"], "kind": b["kind"],
                    "networks": b["networks"]} for b in up["blocks"]],
    }


@mcp.tool()
def smart_plc_compare(project_path: str) -> dict:
    """【在线/离线差异报告】上传 CPU 程序与本地工程逐块比对指令流和网络数。

    结论回答"现场 PLC 里的程序跟我手上这份差多少"。上传经副本，原工程不动。
    ⚠ 未经真机验证；比对依据是指令流文本，压缩/等效改写不算差异。
    """
    plceng.require_v28()
    return plceng.compare_plc(project_path)


@mcp.tool()
def smart_event_log(project_path: str) -> dict:
    """读 PLC 事件日志（引擎路线 COM_GetEventLog）。只读。⚠ 未经真机验证。

    ⚠ 事件条目结构尚未逆向，当前只回读条数；内容解析待真机校准。
    """
    plceng.require_v28()
    return plceng.event_log(project_path)


# ---------- UI 自动化 ----------

@mcp.tool()
def smart_ui_project_tree() -> dict:
    """读取【已打开的】MicroWIN 里的工程：文件名、CPU 型号、POU 列表。

    只接管已打开的实例读 CPU 与窗口标题；V2.8 项目树里「程序块」折叠、UIA 读不到
    POU 子项，所以 POU 列表另起独立引擎实例 EXPORT 补全（不碰你正在编辑的窗口）。
    """
    result = ui.read_project_tree()
    d = result.get("project_dir")
    pf = result.get("project_file")
    proj = os.path.join(d, pf) if (d and pf) else None
    if proj and os.path.exists(proj):
        try:
            tmpdir = tempfile.mkdtemp(prefix="smart200_pou_")
            dump = os.path.join(tmpdir, "all.awl")
            try:
                pid = engine.launch_instance(proj)
                try:
                    engine.run_script(pid, ["EXPORT %s|%s" % (autoflow._ob1_name(proj), dump)])
                finally:
                    engine.kill_instance(pid)
                if os.path.exists(dump) and os.path.getsize(dump) > 0:
                    blocks = autoflow.split_blocks(autoflow._read(dump))
                    result["pous"] = [{"name": b["name"], "id": b["id"], "kind": b["kind"]}
                                      for b in blocks]
                    result["pou_count"] = len(result["pous"])
            finally:
                shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception as e:
            result["pou_error"] = str(e)
    result.pop("project_dir", None)
    return result


@mcp.tool()
def smart_ui_output() -> dict:
    """回读 MicroWIN 输出窗口（编译结果 / 错误列表）。只读。"""
    return ui.read_output_window()


@mcp.tool()
def smart_ui_compile(confirm: bool = False) -> dict:
    """点击 Ribbon【编译】。⚠ 会操作你正在用的界面，需 confirm=True；且尚未实测。"""
    return ui.compile_project(confirm=confirm)


# ---------- 引擎调用（注入路线，全自动，无 UI）----------

@mcp.tool()
def smart_awl_analyze(awl_path: str) -> dict:
    """解析并分析一个 AWL/STL 程序块文件（软件导出或引擎导出的 .awl）。

    返回块名/ID、网络数、指令统计、读写地址、网络注释 —— 用于程序验证与审查。
    """
    block = awl.parse_file(awl_path)
    return awl.analyze(block)


@mcp.tool()
def smart_export_blocks(project_path: str, blocks: dict) -> dict:
    """【全自动】从 V3 工程导出若干程序块为 AWL 文本。

    blocks = {"块名": "输出路径", ...}，块名如 "初始化"、"地址判定"。
    自动启动独立实例、注入引擎、按名查块、导出、关实例 —— 全程无 UI，不碰你正编辑的工程。
    返回每个输出路径是否成功。V3 加密工程也适用（引擎在软件内部执行）。
    """
    result, log = engine.export_blocks(project_path, blocks)
    return {"exported": result, "all_ok": all(result.values())}


@mcp.tool()
def smart_compile_and_export(project_path: str, blocks: dict) -> dict:
    """【全自动】编译工程并导出若干块（一次注入完成）。

    用于"改完验证"：编译看是否通过，同时导出块文本供检查。
    返回编译是否成功 + 每块导出是否成功。
    """
    compiled, exported, log = engine.compile_and_export(project_path, blocks)
    return {"compiled": compiled, "exported": exported}


@mcp.tool()
def smart_check_stl(awl_path: str) -> dict:
    """【离线秒级预检】静态检查 AWL 的网络结构，抓"无效程序段"。

    不启动软件，写完 AWL 先过这一关，省得白跑一趟部署。
    规则：一个 Network 只能有一条独立逻辑行(rung)。已双向验证（坏样本 9/9、好样本零误报）。

    注意这是【启发式规则】，权威判据是 smart_validate_project（问软件本人）。
    另：软件的编译 ret=0 **不代表没有无效程序段** —— 无效网络被排除在编译之外。
    """
    return stlcheck.check_file(awl_path)


@mcp.tool()
def smart_validate_project(project_path: str, block_names: list[str]) -> dict:
    """【权威判据】问软件本人：这些块里有没有"无效程序段"（打开工程会标红的那种）。

    走引擎 POU_IsValidNet 逐网络判定，是软件自己的答案，不是静态猜测。
    已用真实案例验证：已知坏样本精确报出 9 个无效网络、已知好样本 0 误报。
    只读 —— 不导入、不编译、不保存。返回每个块的网络总数与无效网络号。
    """
    return autoflow.validate_project(project_path, block_names)


def _slim_report(report):
    """把 deploy 的完整报告压成好读的摘要。

    原则：**成功时精简，失败时该给的诊断一条不少。**
    18 个块的完整报告有几百行 JSON（每块的验证明细 + 往返明细 + 整段引擎日志），
    全过时这些没人看；一旦不过，又必须给足信息才能排错。
    警告类字段（重排、编码转换、落盘异常）无论成败都保留 —— 那是"虽然过了但你该知道"。

    库函数 autoflow.deploy 始终返回完整报告，裁剪只发生在 MCP 工具这一层。
    """
    d = report.get("detail") or {}
    keys = ("stage1_structure", "stage2_compile", "stage3_engine_validate",
            "stage4_roundtrip", "stage5_persisted", "passed", "project")
    out = {k: report[k] for k in keys if k in report}

    ev = d.get("engine_validate") or {}
    rt = d.get("roundtrip") or {}
    if ev or rt:
        out["summary"] = {
            "blocks": len(ev) or len(rt),
            "networks": sum((v.get("nets") or 0) for v in ev.values()),
            "instructions": sum((v.get("instructions_src") or 0) for v in rt.values()),
        }

    # 无论成败都值得说的
    for k in ("reordered", "encoding_normalized", "persist_warn"):
        if d.get(k):
            out[k] = d[k]
    p = d.get("persisted") or {}
    if p.get("fingerprint_after"):
        out["persisted_bytes"] = p.get("bytes")

    if report.get("passed"):
        return out

    # ---- 没过：把排错要用的全给出来 ----
    det = {}
    for k in ("fatal", "structure", "hint", "persist_hint", "symbol_hint",
              "imports", "blocks", "log"):
        if d.get(k):
            det[k] = d[k]
    bad = {k: v for k, v in ev.items() if v.get("invalid") or v.get("error")}
    if bad:
        det["blocks_with_invalid_networks"] = bad
    bad_rt = {k: v for k, v in rt.items() if v.get("error") or v.get("missing_kinds")}
    if bad_rt:
        det["blocks_failing_roundtrip"] = bad_rt
    bad_sym = {k: v for k, v in (d.get("symbols") or {}).items() if not v.get("ok")}
    if bad_sym:
        det["symbols_not_set"] = bad_sym
    if det:
        out["detail"] = det
    return out


@mcp.tool()
def smart_deploy(awl_files: list[str], project_path: str = "",
                 symbols: dict = None, verify_block: str = "",
                 open_after: bool = False, verbose: bool = False) -> dict:
    """【全自动·推荐入口】把 AWL 块部署进工程并做五关验证，一步到位。

    五关（任何一关不过都会如实报 FAIL，不吹成功）：
      1 静态预检   离线秒级，先挡明显问题
      2 导入+编译  抓语法/交叉引用错误（CALL/ATCH 指向不存在的块）
      3 引擎真值   问软件本人 POU_IsValidNet 有无无效程序段 ← 权威判据
      4 往返导出   逐块核对指令与网络数，抓被软件静默丢弃的内容
      5 落盘校验   比对工程文件指纹，证明【真的写进磁盘】了 ← 前四关都在同一个
                   内存实例里问软件自己，软件说"存好了"不等于文件变了

    awl_files 顺序：主程序(ORGANIZATION_BLOCK/OB1)会自动排到最前（导入 OB1 会替换
    整个程序集）；其余按依赖排，被 CALL 的子程序、被 ATCH 的中断程序排在引用者之前。
    symbols = {"符号名": "绝对地址"}，如 {"电机启动": "I0.0", "电机运行": "Q0.0"}。
    设了就能在 AWL 里直接写符号名（`LD 电机启动`），可读性和客户现场维护性都好得多。
    project_path 留空则用【软件自带的空白模板】新建（不含任何已有工程内容）。
    open_after=True 会把工程留开给人看。

    AWL 文件可以直接用 UTF-8 写 —— 编码与行尾会自动规范成软件要的 ANSI+CRLF
    （引擎的 IMPORTPOU 只吃 ANSI，直接喂 UTF-8 会 ret=0 但块名导成乱码）。
    遇到 GBK 表示不了的字符会报出行号+具体字符，不会静默替换。

    默认返回【摘要】：五关结果 + 块数/网络数/指令数，外加"虽然过了但你该知道"的
    警告（块被重排、文件被转码、旁边冒出 .smart 等）。
    没过时会自动附上排错要用的明细（哪些块有无效网络、哪些块往返对不上、
    哪些符号没设上、引擎日志）。要看全量报告传 verbose=True。
    """
    report = autoflow.deploy(awl_files,
                             project_path=project_path or None,
                             symbols=symbols or None,
                             verify_block=verify_block or None,
                             open_after=open_after)
    return report if verbose else _slim_report(report)


@mcp.tool()
def smart_overview(project_path: str) -> dict:
    """读工程结构概览：有哪些块、各干什么、谁调用谁、用了哪些 I/O。只读。

    拿到一个别人的工程时先跑这个，比一个块一个块点开看快得多。
    每个块给出：名字/ID/类型、网络数、指令数、TITLE、块注释、
    它 CALL 了哪些子程序、ATCH 了哪些中断（含事件号）。

    另外两个字段值得先看：
      never_called            —— 没被任何块 CALL/ATCH 到的块（死代码）
      referenced_but_missing  —— 引用了但工程里不存在的块。这种不会报编译错，
                                 而是让整个网络变成【无效程序段】，很隐蔽。
    """
    return autoflow.project_overview(project_path)


@mcp.tool()
def smart_export_all(project_path: str, out_dir: str,
                     encoding: str = "utf-8") -> dict:
    """把工程里【所有】程序块各导出成一个 .awl 文件 —— 不用先知道块名。

    拿到一个别人的工程想看内容、或者想把程序纳入 git 版本管理时用这个：
    一次调用就把 OB1/SBR/INT 全部落到 out_dir，每块一个文件，文件名就是块名。
    只读，不改工程。

    encoding: 默认 "utf-8"（人读 / 进 git 友好）；传 "ansi" 得到软件原生的
    ANSI+CRLF。两种都能被 smart_deploy 直接吃回去（它会自动规范化）。

    返回每个块的名字、类型、网络数和落地路径。
    """
    return autoflow.export_all_blocks(project_path, out_dir, encoding=encoding)


@mcp.tool()
def smart_set_symbols(project_path: str, symbols: dict) -> dict:
    """给 I/O 地址命名（写符号表），之后程序里就能用符号名代替 I0.0 这种绝对地址。

    symbols = {"符号名": "绝对地址"}，如 {"电机启动": "I0.0", "急停": "I0.7"}。
    做法：I/O 变量表里每个 I/O 点本来就有一行、地址是现成的，这里改的是那一行的名字。
    ⚠ 只支持 CPU 上实际存在的 I/Q 点；地址找不到对应行会如实报 ok=False，不会假装成功。
    ⚠ 会修改并另存工程（符号表必须靠 SAVEAS 落盘，普通保存存不下来）。
    ⚠ 只适合【还没有程序】的工程。对已有程序的工程事后改符号表，会打断程序与
      符号表的绑定：符号条条 ok、GVTCOMPILE 也 ret=0，但随后 COMPILE 报
      -1610612428（各块 POU_IsValidNet 却全是 invalid=0 —— 程序没坏，绑定坏了）。
      本工具改完会补一次 COMPILE 验证，不过就【自动回滚】，不把坏工程留给你。
      要给带程序的工程加符号，请走 smart_deploy(awl_files=[...], symbols={...})，
      它的顺序是 SYMSET → GVTCOMPILE → IMPORTPOU → COMPILE → SAVEAS。
    """
    return autoflow.set_symbols(project_path, symbols)


@mcp.tool()
def smart_open_project(project_path: str) -> dict:
    """打开工程窗口给人看（从磁盘加载，项目树才会正确显示新导入的块）。

    注意：通过引擎 API 导入的块，对【已经开着的】窗口不会实时刷新项目树，
    必须重新打开工程才看得到 —— 所以给人看之前用这个工具重开。
    """
    pid = autoflow.open_project(project_path)
    return {"pid": pid, "project": project_path, "note": "已打开并置于前台"}


@mcp.tool()
def smart_import_blocks(project_path: str, awl_files: list[str], save: bool = True) -> dict:
    """【全自动】把 AWL 程序块导入工程并编译验证（一次注入）。

    awl_files 是 .awl 文件路径列表（可由你生成或修改）。已闭环验证：导入的改动真实落进工程。
    ⚠ 会修改工程；project_path 请用副本或新工程，别直接改客户原始工程。
    返回每个文件是否导入成功 + 编译是否通过。
    """
    imported, compiled, log = engine.import_and_compile(project_path, awl_files, save=save)
    return {"imported": imported, "compiled": compiled, "all_ok": all(imported.values()) and compiled}


@mcp.tool()
def smart_run_workflow(project_path: str, commands: list[str]) -> dict:
    """【全自动】在工程上执行一整条引擎脚本（一次注入，主线程顺序执行）。

    commands 每条是一个子命令（按顺序在主线程执行）：
      "EXPORT 块名|输出路径"   导出 POU 为 AWL
      "XML 块名|输出路径"      导出 POU 为 XML
      "IMPORTPOU AWL文件路径"  导入 AWL 程序块（改动真实落进工程，已闭环验证）
                               编码/行尾自动规范成软件要的 ANSI+CRLF，
                               所以 AWL 可以直接用 UTF-8 写
      "IMPORT 文件路径"        通用导入
      "COMPILE"                编译整个工程
      "VALIDATE 块名|0"        问引擎该块有无无效程序段（权威判据）
      "SAVE"                   ⚠ 别用：对 .smartV3 工程它会把内容【静默写进同名的
                               .smart(V2)】、原 .smartV3 字节不变，而且照样 ret=0。
                               实测过"四关全绿但工程是空的"。落盘一律用 SAVEAS。
      "SAVEAS 完整路径"        另存工程 —— 这才是唯一可靠的落盘方式，
                               临时文件也要保持同样扩展名（SAVEAS 按扩展名认格式）
    返回执行日志里各步的返回码摘要。这是最灵活的入口，可把"导入→编译→导出确认"串成一条。
    ⚠ 含导入/保存时会修改工程，请用副本或新工程。
    """
    # IMPORTPOU 的文件先过一遍编码规范化：引擎按 ANSI 读文件，
    # 直接喂 UTF-8 会 ret=0 但块名导成乱码，随后按中文块名找就是"块未找到"。
    # deploy 早就这么做了，这里补齐 —— 否则同一个坑换个入口又能踩一次。
    tmpdir = tempfile.mkdtemp(prefix="smart200_wf_")
    normalized = []
    try:
        cooked = []
        for i, c in enumerate(commands):
            if c.upper().startswith("IMPORTPOU ") and os.path.exists(c[10:].strip()):
                src = c[10:].strip()
                dst = autoflow._engine_ready_awl(src, tmpdir, i)
                if dst != src:
                    normalized.append(os.path.basename(src))
                cooked.append("IMPORTPOU " + dst)
            else:
                cooked.append(c)

        pid = engine.launch_instance(project_path)
        try:
            log = engine.run_script(pid, cooked)
        finally:
            engine.kill_instance(pid)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    steps = [ln for ln in log.splitlines() if "script " in ln or "ret=" in ln]
    out = {"steps": steps, "ok": "__DONE__" in log}
    if normalized:
        out["encoding_normalized"] = normalized
    return out


def main():
    mcp.run()


if __name__ == "__main__":
    main()
