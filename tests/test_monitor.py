# -*- coding: utf-8 -*-
"""程序段监控求值器的离线单测（STL 求值不需要真机，喂假内存表即可）。

覆盖位逻辑全集、栈操作、比较、S/R、定时器记录、符号映射、控制流近似标注。
反向哨兵：ALD/OLD 语义写反任何一个，哨兵用例都会失败。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from smart200_mcp import awl, monitor   # noqa: E402

fails = []


def check(name, cond, extra=""):
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else "  " + str(extra)))
    if not cond:
        fails.append(name)


def net(*lines):
    """把指令行拼成一个 Network 的 AWL 文本并 parse 出来。"""
    text = "\n".join(["SUBROUTINE_BLOCK S:SBR0", "TITLE=", "BEGIN",
                      "Network 1"] + list(lines) + ["END_SUBROUTINE_BLOCK"])
    return awl.parse(text)["networks"][0]


def ev(n, mem, symbol_map=None):
    return monitor.evaluate_network(n, mem, symbol_map)


print("=== 基础位逻辑 ===")
n = net("LD     I0.0", "=      Q0.0")
r = ev(n, {"I0.0": True})
check("LD 导通 → rung True 线圈通", r["rung"] is True and r["coils"][0]["on"] is True, r)
r = ev(n, {"I0.0": False})
check("LD 断开 → rung False 线圈断", r["rung"] is False and r["coils"][0]["on"] is False, r)

n = net("LD     I0.0", "A      I0.1", "AN     I0.2", "=      Q0.0")
r = ev(n, {"I0.0": True, "I0.1": True, "I0.2": False})
check("A/AN 串联求值", r["rung"] is True, r)
r = ev(n, {"I0.0": True, "I0.1": False, "I0.2": False})
check("串联中一个断开 → 全断", r["rung"] is False, r)

n = net("LD     I0.0", "O      I0.1", "=      Q0.0")
r = ev(n, {"I0.0": False, "I0.1": True})
check("O 并联求值", r["rung"] is True, r)

n = net("LDN    I0.0", "ON     I0.1", "=      Q0.0")
r = ev(n, {"I0.0": False, "I0.1": False})
check("LDN/ON 取反求值", r["rung"] is True, r)

print("=== 栈操作 ALD / OLD / LPS ===")
n = net("LD     I0.0", "LD     I0.1", "ALD", "=      Q0.0")
r = ev(n, {"I0.0": True, "I0.1": True})
check("ALD=与", r["rung"] is True, r)
# 反向哨兵：ALD 与 OLD 写反，这里必然变 True
r = ev(n, {"I0.0": True, "I0.1": False})
check("哨兵：ALD 只要一个假就是假", r["rung"] is False, r)

n = net("LD     I0.0", "LD     I0.1", "OLD", "=      Q0.0")
r = ev(n, {"I0.0": False, "I0.1": False})
check("OLD=或", r["rung"] is False, r)
r = ev(n, {"I0.0": False, "I0.1": True})
check("哨兵：OLD 只要一个真就是真", r["rung"] is True, r)

n = net("LD     I0.0", "LPS", "A      I0.1", "=      Q0.0",
        "LPP", "A      I0.2", "=      Q0.1")
r = ev(n, {"I0.0": True, "I0.1": True, "I0.2": False})
check("LPS/LPP 双线圈", r["coils"][0]["on"] is True and r["coils"][1]["on"] is False,
      r["coils"])

print("=== 比较与运算 ===")
n = net("LD     I0.0", "AW>=   VW100, VW200", "=      Q0.0")
r = ev(n, {"I0.0": True, "VW100": 50, "VW200": 30})
check("比较指令参与逻辑", r["rung"] is True, r)
r = ev(n, {"I0.0": True, "VW100": 10, "VW200": 30})
check("比较不成立 → rung False", r["rung"] is False, r)
r = ev(n, {"I0.0": True})
check("值缺失 → rung None（不装权威）", r["rung"] is None, r)

# 前缀比较的三种栈动作（L=压新值 / A=与 / O=或）——写错任何一个哨兵都会红
n = net("LD     I0.0", "LDW=   VW100, VW200", "=      Q0.0")
r = ev(n, {"I0.0": True, "VW100": 30, "VW200": 30})
check("LDW= 压新值参与逻辑", r["rung"] is True, r)
n = net("LD     I0.0", "OW>    VW100, VW200", "=      Q0.0")
r = ev(n, {"I0.0": False, "VW100": 50, "VW200": 30})
check("哨兵：OW> 是或不是与", r["rung"] is True, r)
n = net("LD     I0.0", "AD<=   VD100, VD200", "=      Q0.0")
r = ev(n, {"I0.0": True, "VD100": 30, "VD200": 300})
check("AD<= 双字比较", r["rung"] is True, r)

print("=== S/R 与定时器 ===")
n = net("LD     I0.0", "S      M0.0, 1")
r = ev(n, {"I0.0": True})
check("S 动作带条件", r["actions"][0] == {"op": "S", "address": "M0.0", "condition": True},
      r["actions"])

n = net("LD     I0.0", "TON    T37, 100")
r = ev(n, {"I0.0": True, "T37": True, "T37#VAL": 42})
check("定时器状态记录", r["timers"][0]["done_bit"] is True
      and r["timers"][0]["current"] == 42, r["timers"])

print("=== 符号映射与控制流标注 ===")
n = net("LD     电机启动", "=      电机运行")
r = ev(n, {}, {"电机启动": "I0.0", "电机运行": "Q0.0"})
check("符号经 symbol_map 解析失败不装权威", r["rung"] is None, r)
r = ev(n, {"I0.0": True}, {"电机启动": "I0.0", "电机运行": "Q0.0"})
check("符号经 symbol_map 正确求值", r["rung"] is True
      and r["coils"][0]["address"] == "Q0.0", r)

n = net("LD     I0.0", "JMP    1", "=      Q0.0")
r = ev(n, {"I0.0": True})
check("控制流指令标 approximate", r["approx"] is True and r["warnings"], r)

print("=== 地址收集 ===")
fake = {"networks": [net("LD     I0.0", "MOVW   VW100, VW200", "TON    T37, 100")]}
check("gather_addresses 收集 4 个地址",
      monitor.gather_addresses([fake]) == {"I0.0", "VW100", "VW200", "T37"},
      sorted(monitor.gather_addresses([fake])))

print("")
print("全部通过" if not fails else str(len(fails)) + " 项失败: " + str(fails))
sys.exit(1 if fails else 0)
