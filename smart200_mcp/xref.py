# -*- coding: utf-8 -*-
"""全工程交叉引用（纯 Python，对标博图 cross-reference）。

S7-200 SMART 在协议层和 .smart 容器里都不存交叉引用数据，唯一可靠来源
是软件导出的 AWL 文本（引擎 EXPORT OB1 会带出全部块，见 autoflow）。
本模块解析这些文本，产出三层引用表：

  · 地址 → 引用它的块/网络/指令（读写方向按指令族启发式判定）
  · 块   → 它引用的地址与符号名
  · CALL / ATCH 调用图（复用 autoflow 的解析）

已知边界（如实标注，不装权威）：
  · 读写方向是启发式：认不出的指令族一律按"读"记，宁可保守不误标写；
  · 软件导出时会把有符号名的地址替换成符号（README 已知行为），这些
    引用记在块的 symbols 里，不参与地址表 —— 地址表覆盖的是绝对地址引用。
"""

import os
import re
import shutil
import tempfile
from collections import defaultdict

from . import awl, engine, enginelog

# 把操作数里的绝对地址抠出来：VW100 / V10.3 / M0.0 / SM0.1 / AIW16 / AQW32 /
# T37 / C3 / HC0 / AC0 / IW64 / QD0 / LB10 / SMB34 / VB0 ...
_ADDR = re.compile(
    r"\b(?:[VMIQS][BWD]?\d+(?:\.\d)?|SM[BWD]?\d+(?:\.\d)?|"
    r"AIW\d+|AQW\d+|[TC]\d+|HC\d+|AC[0-3]|L[BWD]?\d+(?:\.\d)?)\b")

# 指令族 → 操作数访问方向。没列出的族一律按 R（读）记，保守不误标。
# 约定：last_w=最后一个操作数是写目标其余读；all_w=全部写；first_w=第一个写；
#       last_rw=最后一个读改写；none=操作数不是地址（标号/块名类）。
_WRITE_RULES = {
    "=": "all_w", "=I": "all_w", "S": "all_w", "R": "all_w",
    "SI": "all_w", "RI": "all_w",
    "MOVB": "last_w", "MOVW": "last_w", "MOVD": "last_w", "MOVR": "last_w",
    "BMB": "last_w", "BMW": "last_w", "BMD": "last_w",
    "FILL": "last_w", "SWAP": "last_w",
    "TON": "first_w", "TONR": "first_w", "TOF": "first_w",
    "CTU": "first_w", "CTD": "first_w", "CTUD": "first_w",
    "INC": "all_w", "DEC": "all_w",
    "GET": "last_w", "PUT": "first_w",
    "HTA": "last_w", "ATH": "last_w", "ITA": "last_w", "DTA": "last_w",
    "RTA": "last_w", "BTI": "last_w", "ITB": "last_w", "ITD": "last_w",
    "DTB": "last_w", "DTR": "last_w", "ROUND": "last_w", "TRUNC": "last_w",
    "SIN": "last_w", "COS": "last_w", "TAN": "last_w", "SQRT": "last_w",
    "LN": "last_w", "EXP": "last_w",
    "ANDB": "last_w", "ORB": "last_w", "XORB": "last_w", "INVB": "last_w",
    "ANDW": "last_w", "ORW": "last_w", "XORW": "last_w", "INVW": "last_w",
    "ANDD": "last_w", "ORD": "last_w", "XORD": "last_w", "INVD": "last_w",
    "+I": "last_rw", "+D": "last_rw", "+R": "last_rw",
    "-I": "last_rw", "-D": "last_rw", "-R": "last_rw",
    "*I": "last_rw", "*D": "last_rw", "*R": "last_rw",
    "/I": "last_rw", "/D": "last_rw", "/R": "last_rw",
    "SLB": "last_rw", "SRB": "last_rw", "RLB": "last_rw", "RRB": "last_rw",
    "SLW": "last_rw", "SRW": "last_rw", "RLW": "last_rw", "RRW": "last_rw",
    "SLD": "last_rw", "SRD": "last_rw", "RLD": "last_rw", "RRD": "last_rw",
    "PID": "last_w",
    "ATT": "first_w",  # ATT 表,值 —— 表是写入目标
    "LSCR": "none", "SCRT": "none", "SCRE": "none",
    "CRET": "none", "CRETI": "none",
}

# 这些指令的操作数是块名/标号/常量，不当地址
_NAME_OPS = {"CALL", "ATCH", "DTCH", "JMP", "LBL", "SCRT", "LSCR",
             "SCRE", "FOR", "NEXT", "CRET", "CRETI"}

_AREA_RE = re.compile(r"^([VMIQSL]|SM|AIW|AQW|[TC]|HC|AC)")


def _access(op, idx, n_opnds):
    rule = _WRITE_RULES.get(op)
    if rule is None:
        return "R"
    if rule == "none":
        return None
    if rule == "all_w":
        return "W"
    if rule == "last_w":
        return "W" if idx == n_opnds - 1 else "R"
    if rule == "first_w":
        return "W" if idx == 0 else "R"
    if rule == "last_rw":
        return "RW" if idx == n_opnds - 1 else "R"
    return "R"


def block_refs(block):
    """单个块（awl.parse 的结果）的地址引用清单。纯函数可单测。"""
    refs = []
    for net in block["networks"]:
        for i, ins in enumerate(net["instructions"]):
            op = ins["op"].upper()
            if op in _NAME_OPS:
                continue
            opnds = ins["operands"]
            n = len(opnds)
            for j, operand in enumerate(opnds):
                for m in _ADDR.finditer(operand):
                    acc = _access(op, j, n)
                    if acc is None:
                        continue
                    refs.append({"address": m.group(0).upper(), "op": op,
                                 "access": acc, "network": net["n"],
                                 "instr": i + 1})
    return refs


def build(blocks_text):
    """从一份含全部块的 AWL 文本构造交叉引用。纯函数，可单测。

    blocks_text: 已解码的 AWL 文本（引擎 EXPORT OB1 的产出）。
    """
    from . import autoflow

    parts = autoflow.split_blocks(blocks_text)
    blocks, addr_map, calls = [], defaultdict(list), []
    for p in parts:
        b = awl.parse(p["text"])
        refs = block_refs(b)
        m = re.search(r"^TITLE=(.*)$", p["text"], re.M)
        title = m.group(1).strip() if m else ""
        syms = autoflow.symbol_refs(p["text"])
        blocks.append({
            "name": b["name"], "id": b["id"], "kind": b["kind"],
            "title": title,
            "networks": len(b["networks"]),
            "instructions": sum(len(n["instructions"]) for n in b["networks"]),
            "refs": refs,
            "symbols": syms,
        })
        for r in refs:
            addr_map[r["address"]].append({"block": b["name"], **r})
        c, a = autoflow._block_refs(p["text"])
        calls.append({"block": b["name"], "calls": c, "attaches": a})

    addresses = []
    for addr in sorted(addr_map):
        refs = addr_map[addr]
        am = _AREA_RE.match(addr)
        addresses.append({
            "address": addr,
            "area": am.group(1) if am else "?",
            "total": len(refs),
            "writers": [r for r in refs if r["access"] in ("W", "RW")],
            "readers": [r for r in refs if r["access"] in ("R", "RW")],
            "refs": refs,
        })
    return {
        "blocks": blocks,
        "addresses": addresses,
        "calls": calls,
        "summary": {
            "blocks": len(blocks),
            "addresses": len(addresses),
            "references": sum(len(a["refs"]) for a in addresses),
            "note": "读写方向按指令族启发式判定，认不出的指令族按读记；"
                    "有符号名的地址以符号引用形式记在块的 symbols 里",
        },
    }


def for_project(project_path):
    """对真实工程建交叉引用：引擎 EXPORT OB1（带出全部块）→ 离线解析。只读。

    走引擎注入，不编译不保存不改工程。
    """
    from . import autoflow

    project_path = os.path.abspath(project_path)
    if not os.path.exists(project_path):
        raise autoflow.FlowError("工程不存在：" + project_path)
    tmpdir = tempfile.mkdtemp(prefix="smart200_xr_")
    dump = os.path.join(tmpdir, "all.awl")
    try:
        pid = engine.launch_instance(project_path)
        try:
            log = engine.run_script(
                pid, ["EXPORT %s|%s" % (autoflow._ob1_name(project_path), dump)])
        finally:
            engine.kill_instance(pid)
        if not enginelog.done(log):
            raise autoflow.FlowError("引擎脚本没跑完 —— 软件可能中途崩了或超时")
        if not os.path.exists(dump) or os.path.getsize(dump) == 0:
            raise autoflow.FlowError("导出为空。日志：" + "; ".join(enginelog.ret_lines(log)))
        text = autoflow._read(dump)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    out = build(text)
    out["project"] = project_path
    return out
