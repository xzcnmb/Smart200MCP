# -*- coding: utf-8 -*-
"""程序段监控（对标 MicroWIN「程序监控」/ 博图 monitor block）。

原理与软件一致：CPU 并不直接上报"哪个网络导通"——MicroWIN 的程序监控
是【读操作数实时值 + 在 PC 侧逐网络求值】。本模块照做：

  1. 引擎注入 EXPORT OB1 拿到全部块的 AWL 程序文本；
  2. snap7 批量读程序里用到的操作数实时值；
  3. 用一个小的 STL 求值器逐网络算出：rung 导通状态、线圈状态、
     各操作数的实时值、定时器/计数器状态。

已知边界（如实标注，不装权威）：
  · 在线层未经真机验证（连接/读值都可能要按真机行为修正）；
  · 软件导出会把有符号名的地址替换成符号（README 已知行为）——符号
    操作数需要符号表映射。一次注入里顺带 SYMDUMP，能映射的 I/O 符号
    自动还原，映射不了的标"未解析符号"、该网络结果按 None 处理；
  · SCR/JMP/FOR 等控制流不仿真（CPU 里的跳转状态协议层拿不到），
    含这些指令的网络标 approximate=True；
  · 定时器/计数器走 S7 协议 TM/CT 区读取，位约定（bit12=触点位、
    低 12 位 BCD=当前值）未经真机验证，首验时用 smart_plc_diag 校核。
"""

import re

from . import awl, engine, enginelog

# 绝对地址形态（与 xref 保持一致，符号/常量之外的都是地址）
_ADDR = re.compile(
    r"\b(?:[VMIQS][BWD]?\d+(?:\.\d)?|SM[BWD]?\d+(?:\.\d)?|"
    r"AIW\d+|AQW\d+|[TC]\d+|HC\d+|AC[0-3]|L[BWD]?\d+(?:\.\d)?)\b")

# 比较指令：S7-200 STL 是前缀形式 —— LDW=/AW=/OW=（字）、LDD=/AD=/OD=（双字）、
# LDR=/AR=/OR=（实数）、LDB=/AB=/OB=（字节），后缀 = / <> / < / <= / > / >=。
# 前缀决定栈动作：L=压新值，A=与栈顶相与，O=与栈顶相或。
# （裸 "=I" 是立即输出线圈，不是比较 —— 见线圈分支。）
_CMP_PFX = re.compile(r"^(LDW|AW|OW|LDD|AD|OD|LDR|AR|OR|LDB|AB|OB)(=|<>|<=|>=|<|>)$")

# 这些操作数是块名/标号/常量，不是地址
_NAME_OPS = {"CALL", "ATCH", "DTCH", "JMP", "LBL", "SCRT", "LSCR",
             "SCRE", "FOR", "NEXT", "CRET", "CRETI", "RET", "RETI"}

# 控制流指令：本模块不仿真跳转，含它们的网络标"近似"
_CTRL_OPS = {"JMP", "LBL", "SCRT", "LSCR", "SCRE", "CRET", "CRETI",
             "FOR", "NEXT", "RET", "RETI", "CALL", "ATCH", "DTCH"}

_TIMER_OPS = {"TON", "TONR", "TOF"}
_COUNTER_OPS = {"CTU", "CTD", "CTUD"}


def _bcd12(word):
    """12 位 BCD → int。"""
    return ((word >> 8) & 0xF) * 100 + ((word >> 4) & 0xF) * 10 + (word & 0xF)


def _cmp(op, a, b):
    if op.startswith("<>"):
        return a != b
    if op.startswith(">="):
        return a >= b
    if op.startswith("<="):
        return a <= b
    if op.startswith(">"):
        return a > b
    if op.startswith("<"):
        return a < b
    return a == b


class NetEval:
    """单网络的 STL 求值器。逻辑栈语义按 S7-200 STL。

    mem: {地址: 值}，位地址为 bool、字/双字为 int。
    symbol_map: {符号名: 地址}，能映射的符号在求值前替换成地址。
    """

    def __init__(self, mem, symbol_map=None):
        self.mem = mem
        self.symbol_map = symbol_map or {}
        self.stack = []

    # ---- 操作数取值 ----
    def resolve(self, token):
        """token → (值, 说明)。返回 (None, reason) 表示取不到，不抛。"""
        t = token.strip()
        if not t:
            return None, "空操作数"
        key = t.upper()
        if key in self.mem:
            return self.mem[key], "ok"
        if _ADDR.match(t.upper()):
            return None, "未读到实时值"
        if self.symbol_map and t in self.symbol_map:
            key2 = self.symbol_map[t].upper()
            if key2 in self.mem:
                return self.mem[key2], "ok"
            return None, "符号 %s(%s)未读到实时值" % (t, self.symbol_map[t])
        if re.match(r"^[+-]?\d+(\.\d+)?$", t) or re.match(r"^16#[0-9A-Fa-f]+$", t):
            return None, "常量"
        return None, "未解析符号 " + t

    def val(self, token):
        return self.resolve(token)[0]

    # ---- 指令执行 ----
    def step(self, ins, out):
        op = ins["op"].upper()
        opnds = ins["operands"]
        stack = self.stack

        if op in ("LD", "LDN"):
            v, why = self.resolve(opnds[0]) if opnds else (None, "缺操作数")
            stack.append((v if op == "LD" else not v) if isinstance(v, bool) else None)
            self._note_val(out, opnds, v, why)
        elif op in ("A", "AN", "O", "ON"):
            v, why = self.resolve(opnds[0]) if opnds else (None, "缺操作数")
            self._note_val(out, opnds, v, why)
            if not stack:
                stack.append(None)
                return
            if not isinstance(v, bool):
                stack[-1] = None
                return
            if op == "A":
                stack[-1] = stack[-1] and v
            elif op == "AN":
                stack[-1] = stack[-1] and not v
            elif op == "O":
                stack[-1] = stack[-1] or v
            else:
                stack[-1] = stack[-1] or not v
        elif op in ("=", "=I"):
            addr = opnds[0] if opnds else ""
            key = self._map(addr)
            state = stack[-1] if stack else None
            out["coils"].append({"address": key or addr, "on": state})
            if key and isinstance(state, bool):
                self.mem[key] = state
        elif op in ("S", "R", "SI", "RI"):
            addr = opnds[0] if opnds else ""
            key = self._map(addr)
            cond = stack[-1] if stack else None
            out["actions"].append({"op": op, "address": key or addr,
                                   "condition": cond})
            if key and isinstance(cond, bool) and cond:
                self.mem[key] = op in ("S", "SI")
        elif op == "NOT":
            if stack and isinstance(stack[-1], bool):
                stack[-1] = not stack[-1]
        elif op == "ALD":
            if len(stack) >= 2:
                b, a = stack.pop(), stack.pop()
                stack.append((a and b) if isinstance(a, bool) and isinstance(b, bool) else None)
        elif op == "OLD":
            if len(stack) >= 2:
                b, a = stack.pop(), stack.pop()
                stack.append((a or b) if isinstance(a, bool) and isinstance(b, bool) else None)
        elif op == "LPS":
            if stack:
                stack.append(stack[-1])
        elif op == "LRD":
            if len(stack) >= 2:
                stack.append(stack[-2])
        elif op == "LPP":
            if stack:
                stack.pop()
        elif op in _TIMER_OPS and opnds:
            self._note_timer(out, op, opnds[0], why="")
            self._note_val(out, opnds[:1], None, "定时器")
        elif op in _COUNTER_OPS and opnds:
            self._note_counter(out, op, opnds[0], why="")
            self._note_val(out, opnds[:1], None, "计数器")
        elif op == "AENO":
            pass  # ENO 不仿真，保持栈不变
        elif op in _NAME_OPS or op in _CTRL_OPS:
            out["approx"] = True
            out["warnings"].append("%s（网络 %s 指令 %s）：控制流/调用不仿真"
                                   % (op, out["network"], out["instr"]))
        else:
            m = _CMP_PFX.match(op)
            if m and len(opnds) >= 2:
                mode = m.group(1)[0]   # L / A / O
                suffix = m.group(2)
                a, whya = self.resolve(opnds[0])
                b, whyb = self.resolve(opnds[1])
                self._note_val(out, opnds, [a, b], whya + " / " + whyb)
                cond = _cmp(suffix, a, b) if a is not None and b is not None else None
                if mode == "L":
                    stack.append(cond)
                elif stack:
                    top = stack[-1]
                    if isinstance(cond, bool) and isinstance(top, bool):
                        stack[-1] = (top or cond) if mode == "O" else (top and cond)
                    else:
                        stack[-1] = None
            else:
                # 传送/运算等：不碰逻辑栈，只把操作数实时值记下来给人看
                vals = [self.resolve(o)[0] for o in opnds]
                self._note_val(out, opnds, vals, "ok")

    def _map(self, token):
        """符号 → 绝对地址（能映射的话）；返回 None 表示映射不了。"""
        if not token:
            return None
        if _ADDR.match(token.upper()):
            return token.upper()
        mapped = self.symbol_map.get(token.strip())
        return mapped.upper() if mapped else None

    def _note_val(self, out, opnds, vals, why):
        for i, o in enumerate(opnds):
            key = self._map(o)
            if not key:
                continue
            v = vals[i] if isinstance(vals, list) else vals
            out["values"].append({"address": key, "value": v,
                                  "readable": v is not None,
                                  "note": why if i == 0 else ""})

    def _note_timer(self, out, op, tok, why=""):
        t = tok.strip().upper()
        bit = self.mem.get(t)
        cur = self.mem.get(t + "#VAL")
        out["timers"].append({"timer": t, "op": op,
                              "done_bit": bit, "current": cur})

    def _note_counter(self, out, op, tok, why=""):
        c = tok.strip().upper()
        bit = self.mem.get(c)
        cur = self.mem.get(c + "#VAL")
        out["counters"].append({"counter": c, "op": op,
                                "done_bit": bit, "current": cur})


def evaluate_network(network, mem, symbol_map=None, net_no=None, instr_no=1):
    """对一个网络求值。返回状态 dict。纯函数，可离线单测（喂假 mem）。"""
    ev = NetEval(mem, symbol_map)
    out = {"network": net_no if net_no is not None else network["n"],
           "comment": network.get("comment"),
           "coils": [], "actions": [], "values": [], "timers": [],
           "counters": [], "approx": False, "warnings": []}
    for i, ins in enumerate(network["instructions"]):
        out["instr"] = i + instr_no
        ev.step(ins, out)
    out["rung"] = ev.stack[-1] if ev.stack else None
    out.pop("instr", None)
    # values 去重（同地址取最后一次读到的）
    seen = {}
    for v in out["values"]:
        seen[v["address"]] = v
    out["values"] = list(seen.values())
    return out


def read_memory(ip, addresses):
    """批量读 PLC 实时值 → {地址: 值}。位地址→bool，字/双字→int，
    定时器/计数器→触点位 + 当前值(T37 与 T37#VAL)。

    读不到的地址不进字典（求值层把缺失标为"未读到"）。
    """
    import snap7
    from .online import Plc, parse_address

    mem = {}
    tcs = sorted({a for a in addresses if re.match(r"^[TC]\d+$", a)},
                 key=lambda x: int(x[1:]))
    with Plc(ip) as plc:
        for a in addresses:
            if re.match(r"^[TC]\d+$", a):
                continue  # 单独走 TM/CT 区
            try:
                area, byte, bit, size = parse_address(a)
                raw = plc._area_read(area, byte, size)
                mem[a.upper()] = (bool(raw[0] >> bit & 1) if bit is not None
                                  else int.from_bytes(raw, "big"))
            except Exception:
                continue
        for a in tcs:
            num = int(a[1:])
            area = snap7.type.Area.TM if a[0].upper() == "T" else snap7.type.Area.CT
            try:
                raw = plc._c.read_area(area, 0, num * 2, 2)
                w = int.from_bytes(raw, "big")
                mem[a] = bool(w & 0x1000)
                mem[a + "#VAL"] = _bcd12(w)
            except Exception:
                continue
    return mem


def gather_addresses(blocks):
    """从解析好的块结构里收集全部绝对地址引用（T/C 也要）。"""
    out = set()
    for b in blocks:
        for net in b["networks"]:
            for ins in net["instructions"]:
                if ins["op"].upper() in _NAME_OPS:
                    continue
                for o in ins["operands"]:
                    for m in _ADDR.finditer(o):
                        out.add(m.group(0).upper())
    return out


def monitor_project(ip, project_path, block_name="", blocks_text=None):
    """程序段监控主流程：导出程序 → 读实时值 → 逐网络求值。

    block_name 留空 = 全部块；给了就只看那个块。
    """
    import os as _os
    import shutil
    import tempfile

    from . import autoflow

    project_path = _os.path.abspath(project_path)
    if not _os.path.exists(project_path):
        raise autoflow.FlowError("工程不存在：" + project_path)

    tmpdir = tempfile.mkdtemp(prefix="smart200_mon_")
    dump = _os.path.join(tmpdir, "all.awl")
    try:
        pid = engine.launch_instance(project_path)
        try:
            log = engine.run_script(
                pid, ["EXPORT %s|%s" % (autoflow._ob1_name(project_path), dump),
                      "SYMDUMP ALL"])
        finally:
            engine.kill_instance(pid)
        if not enginelog.done(log):
            raise autoflow.FlowError("引擎脚本没跑完 —— 软件可能中途崩了或超时")
        if not _os.path.exists(dump) or _os.path.getsize(dump) == 0:
            raise autoflow.FlowError("导出为空。日志：" + "; ".join(enginelog.ret_lines(log)))
        text = autoflow._read(dump)
        sym_rows = enginelog.symbol_dump(log)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    parts = autoflow.split_blocks(text)
    if block_name:
        parts = [p for p in parts if p["name"] == block_name or p["id"] == block_name]
        if not parts:
            raise autoflow.FlowError("块未找到：" + block_name)

    symbol_map = {r["name"]: r["address"] for r in sym_rows if r.get("address")}
    parsed = []
    for p in parts:
        b = awl.parse(p["text"])
        parsed.append({"name": b["name"], "id": b["id"], "kind": b["kind"],
                       "block": b})

    addrs = gather_addresses([p["block"] for p in parsed])
    mem = read_memory(ip, addrs)

    blocks_out = []
    for p in parsed:
        nets = []
        for net in p["block"]["networks"]:
            nets.append(evaluate_network(net, mem, symbol_map))
        blocks_out.append({"name": p["name"], "id": p["id"], "kind": p["kind"],
                           "networks": nets,
                           "networks_total": len(nets),
                           "nets_energized": sum(1 for n in nets if n["rung"] is True),
                           "nets_approx": sum(1 for n in nets if n["approx"]),
                           "nets_unresolved": sum(1 for n in nets if n["rung"] is None)})
    return {
        "ip": ip, "project": project_path,
        "addresses_read": len(mem),
        "unresolved_symbols": sorted({w.split(" ")[-1] for b in blocks_out
                                      for n in b["networks"] for w in n["warnings"]
                                      if w.startswith("未解析")}) or [],
        "blocks": blocks_out,
    }
