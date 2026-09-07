# -*- coding: utf-8 -*-
"""引擎路线的 PLC 在线操作：下载 / 上传 / RUN-STOP / 状态 / 事件日志 / 在线离线比对。

走注入 DLL 的新命令（GETADDR / PLCSTATE / SETOPMODE / DOWNLOAD / UPLOAD /
EVENTLOG），由软件自己的 COMMCOMPASS 通信栈干活，与 snap7 路线互补：

  · 连接参数（IP/站号）来自【工程里配置的】access point，不用另传 IP；
  · 下载/上传是块传输，snap7 路线做不到；
  · 事件日志是软件侧诊断，snap7 没有。

⚠ 全部未经真机验证。改状态的操作（下载/RUN/STOP）由 MCP 层 confirm 门把关。
红线不变：只对 engine.launch_instance() 起的独立实例注入；上传走副本，
绝不碰原工程文件。
"""

import os
import re
import shutil
import tempfile

from . import autoflow, engine, enginelog, paths

# ---------------- 日志判读（纯函数，可单测） ----------------

_GETADDR = re.compile(r"GETADDR ret=(-?\d+)\(0x[0-9a-fA-F]+\) accesspoint='([^']*)'")
_STATE = re.compile(
    r"PLCSTATE connected=(-?\d+) opmode=(\d+) pwd_protected=(-?\d+) rets=(-?\d+)/(-?\d+)/(-?\d+)")
_SETOPMODE = re.compile(r"SETOPMODE (\d+) ret=(-?\d+)\(0x[0-9a-fA-F]+\) now=(\d+)")
_DL_SKIP = re.compile(r"DOWNLOAD SKIP=([^\r\n]*)")
_DL_RET = re.compile(r"DOWNLOAD block_types=(\d+) ret=(-?\d+)\(0x[0-9a-fA-F]+\)")
_UL_SKIP = re.compile(r"UPLOAD SKIP=([^\r\n]*)")
_UL_RET = re.compile(r"UPLOAD block_types=(\d+) ret=(-?\d+)\(0x[0-9a-fA-F]+\)")
_EVLOG = re.compile(
    r"EVENTLOG GetRemoteAddr=(-?\d+) GetEventLog=(-?\d+)\(0x[0-9a-fA-F]+\) count=(-?\d+)")


def parse_state(log):
    """PLCSTATE 行 → {connected, opmode, pwd_protected, rets}。判读失败抛 FlowError。"""
    m = _STATE.search(log)
    if not m:
        raise autoflow.FlowError("PLCSTATE 无有效日志行，可能是不支持的命令：\n" + log[-600:])
    return {"connected": int(m.group(1)) == 1,
            "opmode": int(m.group(2)),
            "opmode_text": {1: "STOP", 2: "RUN", 0xFFFF: "未知"}.get(int(m.group(2)), str(int(m.group(2)))),
            "pwd_protected": int(m.group(3)) == 1,
            "rets": [int(m.group(i)) for i in (4, 5, 6)]}


def parse_getaddr(log):
    m = _GETADDR.search(log)
    if not m:
        raise autoflow.FlowError("GETADDR 无有效日志行：\n" + log[-600:])
    return {"ret": int(m.group(1)), "accesspoint": m.group(2)}


def parse_setopmode(log):
    m = _SETOPMODE.search(log)
    if not m:
        raise autoflow.FlowError("SETOPMODE 无有效日志行：\n" + log[-600:])
    return {"mode": int(m.group(1)), "ret": int(m.group(2)),
            "now": int(m.group(3)),
            "now_text": {1: "STOP", 2: "RUN"}.get(int(m.group(3)), str(int(m.group(3))))}


def parse_download(log):
    """DOWNLOAD 的结果：成功/跳过/失败 + 原因。"""
    if _DL_RET.search(log):
        m = _DL_RET.search(log)
        return {"attempted": True, "block_types": int(m.group(1)), "ret": int(m.group(2))}
    m = _DL_SKIP.search(log)
    if m:
        return {"attempted": False, "skip": m.group(1)}
    raise autoflow.FlowError("DOWNLOAD 无有效日志行：\n" + log[-600:])


def parse_upload(log):
    if _UL_RET.search(log):
        m = _UL_RET.search(log)
        return {"attempted": True, "block_types": int(m.group(1)), "ret": int(m.group(2))}
    m = _UL_SKIP.search(log)
    if m:
        return {"attempted": False, "skip": m.group(1)}
    raise autoflow.FlowError("UPLOAD 无有效日志行：\n" + log[-600:])


def parse_eventlog(log):
    m = _EVLOG.search(log)
    if not m:
        raise autoflow.FlowError("EVENTLOG 无有效日志行：\n" + log[-600:])
    return {"remote_addr_ret": int(m.group(1)), "ret": int(m.group(2)),
            "count": int(m.group(3))}


# ---------------- 引擎执行 ----------------

def _run(project_path, commands):
    pid = engine.launch_instance(project_path)
    try:
        return engine.run_script(pid, commands)
    finally:
        engine.kill_instance(pid)


def _export_all_text(project_path):
    """EXPORT OB1（带出全部块）→ 已解码文本。只读。"""
    tmpdir = tempfile.mkdtemp(prefix="smart200_pe_")
    dump = os.path.join(tmpdir, "all.awl")
    try:
        log = _run(project_path, ["EXPORT %s|%s" % (autoflow._ob1_name(project_path), dump)])
        if not enginelog.done(log):
            raise autoflow.FlowError("引擎脚本没跑完：\n" + log[-600:])
        if not os.path.exists(dump) or os.path.getsize(dump) == 0:
            raise autoflow.FlowError("导出为空。日志：" + "; ".join(enginelog.ret_lines(log)))
        return autoflow._read(dump)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def status(project_path):
    """PLC 连接状态/运行模式/密码保护 + 工程配置的 access point。只读。"""
    log = _run(project_path, ["GETADDR", "PLCSTATE"])
    out = {"state": parse_state(log), "accesspoint": parse_getaddr(log)}
    out["state"]["log"] = [ln for ln in log.splitlines() if "PLCSTATE" in ln or "GETADDR" in ln]
    return out


def set_opmode(project_path, mode):
    """RUN/STOP（引擎路线）。mode: 'run' | 'stop'。返回执行后状态。"""
    n = 2 if mode == "run" else 1
    log = _run(project_path, ["SETOPMODE %d" % n, "PLCSTATE"])
    return {"requested": mode, "setopmode": parse_setopmode(log),
            "after": parse_state(log)}


def download(project_path, block_types=0):
    """下载工程程序到 PLC：先读目标/连接状态，再 DOWNLOAD，最后回读状态。

    ⚠ 会把程序写入 PLC —— MCP 层必须 confirm。日志里的 access point
    就是目标 CPU，下错机的责任在调用方确认。
    """
    cmds = ["GETADDR", "PLCSTATE", "DOWNLOAD %d" % block_types, "PLCSTATE"]
    log = _run(project_path, cmds)
    return {
        "accesspoint": parse_getaddr(log),
        "before": parse_state(log),
        "download": parse_download(log),
        "after": parse_state(log),
    }


def upload(project_path, block_types=0):
    """从 PLC 上传程序到【副本】并导出成 AWL 文本。原工程文件不动。

    返回 {state, upload, saved, blocks_text, blocks}。
    """
    ext = os.path.splitext(project_path)[1] or ".smart"
    tmpdir = tempfile.mkdtemp(prefix="smart200_up_")
    copy = os.path.join(tmpdir, "copy" + ext)
    shutil.copy(project_path, copy)
    try:
        log = _run(copy, ["PLCSTATE", "UPLOAD %d" % block_types, "SAVE"])
        if not enginelog.done(log):
            raise autoflow.FlowError("引擎脚本没跑完：\n" + log[-600:])
        state = parse_state(log)
        up = parse_upload(log)
        text = _export_all_text(copy)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return {"state": state, "upload": up, "blocks_text": text,
            "blocks": autoflow.split_blocks(text)}


def compare_plc(project_path):
    """在线/离线比对：上传 CPU 程序 → 与本地工程逐块比对指令流与网络数。

    返回逐块结论 + 只在一边的块 + 总体结论。上传经副本，原工程不动。
    """
    orig = _export_all_text(project_path)
    up = upload(project_path)

    local = {b["name"]: b for b in autoflow.split_blocks(orig)}
    plc = {b["name"]: b for b in up["blocks"]}
    names = sorted(set(local) | set(plc))
    rows, mismatched = [], []
    for n in names:
        l, p = local.get(n), plc.get(n)
        if l is None:
            rows.append({"name": n, "in_both": False, "side": "only_plc"})
            continue
        if p is None:
            rows.append({"name": n, "in_both": False, "side": "only_local"})
            continue
        ok, detail = autoflow.compare_roundtrip(l["text"], p["text"])
        rows.append({"name": n, "id": l["id"], "in_both": True, "match": ok,
                     "src_nets": detail.get("networks_src"),
                     "plc_nets": detail.get("networks_back"),
                     "src_instr": detail.get("instructions_src"),
                     "plc_instr": detail.get("instructions_back"),
                     "error": detail.get("error", "")})
        if not ok:
            mismatched.append(n)
    conclusion = ("全部块一致" if not mismatched
                  and all(r["in_both"] for r in rows) else
                  "%d 个块不一致" % len(mismatched) if mismatched else
                  "存在只在一边的块")
    return {
        "project": project_path,
        "online": {"connected": up["state"]["connected"],
                   "upload": up["upload"]},
        "blocks": rows,
        "mismatched": mismatched,
        "conclusion": conclusion,
    }


def event_log(project_path):
    """PLC 事件日志（COM_GetEventLog）。⚠ 条目结构未逆向，只回读条数。"""
    log = _run(project_path, ["EVENTLOG"])
    return parse_eventlog(log)


def require_v28():
    if not paths.is_v28():
        raise autoflow.FlowError(
            "引擎路线在线命令（下载/上传/启停/事件日志）只在 V2.8 接好线，"
            "当前环境未探测到 V2.8（MWSmart.exe）。")
