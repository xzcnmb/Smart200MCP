# -*- coding: utf-8 -*-
"""路径解析：仓库自身位置 + MicroWIN 安装位置，全部自动探测。

为什么单独一层：以前这些是写死的绝对路径（E:\\Smart200_Mcp、D:\\smart200），
别人 clone 到别的盘就跑不起来。现在的优先级是

    环境变量  >  .smart200_local.json  >  自动探测  >  报错说清楚缺什么

仓库内的东西（注入器、DLL）一律相对本文件定位，仓库可以随便搬。
"""

import glob
import os

from . import localcfg

# 仓库根 = 本文件的上两层（源码开发布局）
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 包目录本身（smart200_mcp/）
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))


def _native_dir():
    """native 二进制资源目录。

    pip 安装成 wheel 后，注入 DLL / 注入器随包分发在 smart200_mcp/native/；
    源码仓库开发时它们在 仓库根/native/。两处都探测，优先随包的（这样 clone 到
    别的盘、或 pip install 到别的机器都能找到注入器）。
    """
    bundled = os.path.join(_PKG_DIR, "native")
    if os.path.isdir(bundled):
        return bundled
    return os.path.join(ROOT, "native")


NATIVE = _native_dir()
BOOTSTRAP = os.path.join(NATIVE, "bootstrap")
# V3.2 引擎 DLL（原版）与 V2.8.2 引擎 DLL（本仓库移植版，见 docs/V28_PORT.md）
DLL_V3 = os.path.join(BOOTSTRAP, "smarthook_WORKING.dll")
DLL_V28 = os.path.join(BOOTSTRAP, "smarthook_v28.dll")
DLL = DLL_V3  # 默认，mwsmart() 探到 V2.8 时切到 DLL_V28
CMD_FILE = os.path.join(BOOTSTRAP, "inject_cmd.txt")
RESULT_FILE = os.path.join(BOOTSTRAP, "inject_result.txt")
# 原版注入器是 net8.0 框架依赖（需 .NET 8 运行时）；另备原生注入器（零依赖，x86）
INJECTOR = os.path.join(NATIVE, "injector", "bin", "Release",
                        "net8.0", "win-x86", "injector.exe")
INJECTOR_NATIVE = os.path.join(BOOTSTRAP, "inject_native.exe")


class PathError(Exception):
    pass


def _from_env_or_cfg(env_name, cfg_key):
    v = os.environ.get(env_name)
    if v and os.path.exists(v):
        return v
    v = localcfg.get(cfg_key)
    if v and os.path.exists(v):
        return v
    return None


def _scan_install():
    """找 MicroWIN SMART 的安装目录。V3 用 MWSmartV3.exe，V2.8 用 MWSmart.exe。"""
    bases = []
    for env_key in ("ProgramFiles(x86)", "ProgramFiles"):
        v = os.environ.get(env_key)
        if v and v not in bases:
            bases.append(v)
    # 硬编码兜底：MCP stdio 客户端只透传白名单环境变量，ProgramFiles 可能不在其中，
    # 直接枚举标准 Program Files 位置，避免明明装了软件却报"找不到"。
    for fallback in (r"C:\Program Files (x86)", r"C:\Program Files"):
        if fallback not in bases and os.path.isdir(fallback):
            bases.append(fallback)
    pats = []
    for base in bases:
        pats.append(os.path.join(base, "Siemens", "*", "MWSmart*.exe"))
        pats.append(os.path.join(base, "*Micro*WIN*", "MWSmart*.exe"))
    for drive in ("C:", "D:", "E:", "F:"):
        pats.append(os.path.join(drive + os.sep, "smart200", "MWSmart*.exe"))
        pats.append(os.path.join(drive + os.sep, "*Micro*WIN*", "MWSmart*.exe"))
        pats.append(os.path.join(drive + os.sep, "Siemens", "*", "MWSmart*.exe"))
    for p in pats:
        hits = sorted(glob.glob(p))
        if hits:
            # 优先 V2.8 的 MWSmart.exe（本机现状），其次 MWSmartV3.exe
            for h in hits:
                if os.path.basename(h).lower() == "mwsmart.exe":
                    return h
            return hits[0]
    return None


def is_v28():
    """探测到的软件是不是 V2.8（可执行名 MWSmart.exe 而非 MWSmartV3.exe）。"""
    try:
        return os.path.basename(mwsmart()).lower() == "mwsmart.exe"
    except PathError:
        return False


def engine_dll():
    """按探测到的软件版本返回对应的注入 DLL。V2.8 用 smarthook_v28.dll。"""
    if is_v28() and os.path.exists(DLL_V28):
        return DLL_V28
    return DLL_V3


def injector():
    """注入器：优先原生 x86 注入器（零 .NET 依赖），否则退回 net8.0 注入器。"""
    if os.path.exists(INJECTOR_NATIVE):
        return INJECTOR_NATIVE
    return INJECTOR


def mwsmart():
    """MicroWIN SMART 可执行文件完整路径（MWSmart.exe 或 MWSmartV3.exe）。"""
    v = _from_env_or_cfg("SMART200_EXE", "mwsmart_exe")
    if v:
        return v
    v = _scan_install()
    if v:
        return v
    raise PathError(
        "找不到 MicroWIN SMART 可执行文件（MWSmart.exe / MWSmartV3.exe）。请任选一种方式指明：\n"
        "  1) 设环境变量 SMART200_EXE=<完整路径>\n"
        "  2) 在仓库根的 .smart200_local.json 里加 \"mwsmart_exe\": \"<完整路径>\"\n"
        "（已自动找过 Program Files 下的 Siemens/MicroWIN 目录，和各盘根的 smart200\\）")


def blank_template():
    """软件自带的空白模板工程（建新工程用）。找不到返回 None，调用方自己决定怎么办。"""
    v = _from_env_or_cfg("SMART200_TEMPLATE", "blank_template")
    if v:
        return v
    try:
        d = os.path.dirname(mwsmart())
    except PathError:
        return None
    for name in ("template.smartV3", "template.smart"):
        cand = os.path.join(d, name)
        if os.path.exists(cand):
            return cand
    return None


def check(require_injector=True):
    """开工前自检：缺什么一次说清，别等注入到一半才炸。"""
    missing = []
    dll = engine_dll()
    if not os.path.exists(dll):
        missing.append("引擎 DLL 不存在：%s\n     → 跑 python native/bootstrap/build.py 编译" % dll)
    inj = injector()
    if require_injector and not os.path.exists(inj):
        missing.append("注入器不存在：%s\n     → 跑 python native/bootstrap/build.py 编译原生注入器" % inj)
    try:
        mwsmart()
    except PathError as e:
        missing.append(str(e))
    return missing
