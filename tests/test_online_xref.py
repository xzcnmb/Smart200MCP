# -*- coding: utf-8 -*-
"""0.5.0 新增能力的离线单测：CPU 状态解析 / V2.8 无缩进 AWL 解析 / 交叉引用 / 格式解码。

全部纯函数，不需要装 MicroWIN、不需要真机。反向哨兵保证"测试本身没坏"。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from smart200_mcp import awl, online, xref   # noqa: E402

fails = []


def check(name, cond, extra=""):
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else "  " + str(extra)))
    if not cond:
        fails.append(name)


print("=== CPU 状态解析（SZL 0x0424，纯函数）===")
check("0x08 判 RUN", online.cpu_state_from_szl(bytes([0, 0, 0, 0, 0, 0, 0, 0x08])) == "RUN")
check("0x04 判 STOP", online.cpu_state_from_szl(bytes([0, 0, 0, 0, 0, 0, 0, 0x04])) == "STOP")
check("老 CPU 0x03 判 STOP", online.cpu_state_from_szl(bytes([0, 0, 0, 0, 0, 0, 0, 0x03])) == "STOP")
check("数据太短判 STOP（不崩）", online.cpu_state_from_szl(bytes([0, 1])) == "STOP")
# 反向哨兵：0x08 出现在错误偏移上绝不能判 RUN
check("哨兵：0x08 错位不误判 RUN",
      online.cpu_state_from_szl(bytes([0x08, 0, 0, 0, 0, 0, 0, 0])) == "STOP")

print("=== V2.8 引擎导出（无缩进指令）能被 awl.parse 解析 ===")
text = "\n".join([
    "SUBROUTINE_BLOCK SUB1:SBR0",
    "TITLE=",
    "BEGIN",
    "Network 1",
    "LD     I0.0",
    "=      Q0.0",
    "+I     VW0, AC0",
    "CALL   SUB2",
    "END_SUBROUTINE_BLOCK",
])
b = awl.parse(text)
ops = [i["op"] for i in b["networks"][0]["instructions"]]
check("无缩进指令全部解析（含 = 与 +I）", ops == ["LD", "=", "+I", "CALL"], ops)
check("= 线圈的操作数不丢", b["networks"][0]["instructions"][1]["operands"] == ["Q0.0"])

print("=== 交叉引用（xref.build 纯函数）===")
all_text = "\n".join([
    "ORGANIZATION_BLOCK MAIN:OB1",
    "TITLE=test",
    "BEGIN",
    "Network 1",
    "LD     I0.0",
    "O      Q0.0",
    "AN     I0.1",
    "=      Q0.0",
    "CALL   SUB1",
    "END_ORGANIZATION_BLOCK",
    "SUBROUTINE_BLOCK SUB1:SBR0",
    "TITLE=",
    "BEGIN",
    "Network 1",
    "LD     M0.0",
    "MOVW   VW100, VW200",
    "TON    T37, 100",
    "+I     VW0, AC0",
    "END_SUBROUTINE_BLOCK",
])
x = xref.build(all_text)
addrs = {a["address"] for a in x["addresses"]}
want = {"I0.0", "Q0.0", "I0.1", "M0.0", "VW100", "VW200", "T37", "VW0", "AC0"}
check("地址表收集全 9 个地址", addrs == want, sorted(addrs ^ want))
check("引用总数 10 条（常量 100 不算地址）",
      x["summary"]["references"] == 10, x["summary"]["references"])
q = next(a for a in x["addresses"] if a["address"] == "Q0.0")
check("Q0.0 读+写各一", len(q["readers"]) == 1 and len(q["writers"]) == 1,
      (len(q["readers"]), len(q["writers"])))
ac = next(a for a in x["addresses"] if a["address"] == "AC0")
check("AC0 判为读写 RW", ac["writers"][0]["access"] == "RW", ac["writers"])
vw200 = next(a for a in x["addresses"] if a["address"] == "VW200")
check("MOVW 目标 VW200 判为写", vw200["writers"][0]["access"] == "W")
check("MOVW 源 VW100 判为读",
      next(a for a in x["addresses"] if a["address"] == "VW100")["readers"][0]["access"] == "R")
calls = {c["block"]: c["calls"] for c in x["calls"]}
check("CALL 调用图正确", calls.get("MAIN") == ["SUB1"], calls)
check("块数汇总", x["summary"]["blocks"] == 2, x["summary"]["blocks"])
# 反向哨兵：把 _ADDR 弄丢一条地址引用就该报 9 个地址 / 9 条引用
check("哨兵：地址表不为空", len(addrs) == 9 and x["summary"]["references"] == 10)

print("=== 格式解码（decode 纯函数）===")
check("INT 解码", online.decode(b"\x00\x64", 2, "int") == 100)
check("REAL 解码", online.decode(b"\x3f\x00\x00\x00", 4, "real") == 0.5)
check("Pascal 字符串解码", online.decode(bytes([3]) + b"ABC", 4, "string") == "ABC")
check("bool 位解码", online.decode(b"\x01", 1, "bool") is True)

print("")
print("全部通过" if not fails else str(len(fails)) + " 项失败: " + str(fails))
sys.exit(1 if fails else 0)
