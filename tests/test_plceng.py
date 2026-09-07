# -*- coding: utf-8 -*-
"""plceng 日志判读的离线单测（纯函数，用夹具日志字符串，不需要 DLL/真机）。

判据和 DLL 命令的日志格式是一一对应的 —— 哪边改了另一边没跟上，
这些用例会立刻红。含反向哨兵：判读函数对"半个日志"必须抛错，不装成功。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from smart200_mcp import plceng   # noqa: E402

fails = []


def check(name, cond, extra=""):
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else "  " + str(extra)))
    if not cond:
        fails.append(name)


print("=== PLCSTATE 判读 ===")
log = ("[主线程] 完成\n"
       "script PLCSTATE connected=1 opmode=2 pwd_protected=0 rets=0/0/0\n"
       "__DONE__\n")
s = plceng.parse_state(log)
check("连接/RUN/无密码", s["connected"] is True and s["opmode"] == 2
      and s["opmode_text"] == "RUN" and s["pwd_protected"] is False, s)
log2 = "script PLCSTATE connected=0 opmode=65535 pwd_protected=-1 rets=0/7/0"
s2 = plceng.parse_state(log2)
check("未连接/模式未知", s2["connected"] is False and s2["opmode_text"] == "未知", s2)
try:
    plceng.parse_state("script COMPILE ret=0")
    check("哨兵：缺 PLCSTATE 行必须抛错", False)
except Exception:
    check("哨兵：缺 PLCSTATE 行必须抛错", True)

print("=== GETADDR 判读 ===")
g = plceng.parse_getaddr("script GETADDR ret=0(0x0) accesspoint='以太网:192.168.2.1'")
check("连接点解析", g["ret"] == 0 and g["accesspoint"] == "以太网:192.168.2.1", g)

print("=== SETOPMODE 判读 ===")
m = plceng.parse_setopmode("script SETOPMODE 1 ret=0(0x0) now=1")
check("STOP 成功且回读 STOP", m["ret"] == 0 and m["now_text"] == "STOP", m)

print("=== DOWNLOAD 判读 ===")
d = plceng.parse_download("script DOWNLOAD block_types=0 ret=0(0x0)")
check("下载已尝试 ret=0", d["attempted"] is True and d["ret"] == 0, d)
d2 = plceng.parse_download("script DOWNLOAD SKIP=未连接PLC connected=0")
check("未连接 → SKIP 且给原因", d2["attempted"] is False and "未连接" in d2["skip"], d2)
try:
    plceng.parse_download("script COMPILE ret=0")
    check("哨兵：缺 DOWNLOAD 行必须抛错", False)
except Exception:
    check("哨兵：缺 DOWNLOAD 行必须抛错", True)

print("=== UPLOAD 判读 ===")
u = plceng.parse_upload("script UPLOAD block_types=0 ret=0(0x0)")
check("上传已尝试 ret=0", u["attempted"] is True and u["ret"] == 0, u)
u2 = plceng.parse_upload("script UPLOAD SKIP=能力探测不过 ret=7 out=0")
check("能力探测不过 → SKIP 带原因", u2["attempted"] is False and "能力探测" in u2["skip"], u2)

print("=== EVENTLOG 判读 ===")
e = plceng.parse_eventlog("script EVENTLOG GetRemoteAddr=0 GetEventLog=0(0x0) count=12 entries=0x0ABCDEF0")
check("事件日志条数", e["ret"] == 0 and e["count"] == 12 and e["remote_addr_ret"] == 0, e)

print("")
print("全部通过" if not fails else str(len(fails)) + " 项失败: " + str(fails))
sys.exit(1 if fails else 0)
