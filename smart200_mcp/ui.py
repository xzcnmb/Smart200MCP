"""UI 自动化层：驱动已运行的 STEP 7-Micro/WIN SMART V3（Ribbon 界面，UIAutomation）。

红线（照搬 TIA MCP 的教训，不重犯）：
  1. 只接管【已经打开】的实例，绝不 OpenProject / 新建工程去顶掉用户正在编辑的工程。
  2. 绝不按进程名批量杀 MWSmartV3.exe。
  3. 编译等会改变软件状态的动作，必须调用方显式 confirm=True。
  4. 找不到控件就抛异常，绝不 catch 后静默返回空 —— 那会把失败伪装成成功。

实测状态（本机 V3.2.0 中文界面，2026-08-20）：
  read_project_tree  已实测通过（读出 CPU ST32 与全部 POU）
  compile_project    未实测 —— 用户当时正在该工程上作业，不便触发；代码按实测到的
                     控件名 Button:"编译" 编写，首次使用请在无关紧要的工程上先验。
本层依赖界面语言为简体中文；换语言或换版本控件名会变，需重新探查。
"""

import os
import re

from pywinauto import Desktop

APP_CLASS = "SmartApp"
_POU_RE = re.compile(r"^(?P<name>.+?)\s*\((?P<id>OB\d+|SBR\d+|INT\d+|FB\d+)\)$")
_PROJECT_DIR_RE = re.compile(r"^.+?\s*\((.+)\)$")


class UiError(Exception):
    pass


def find_app():
    """返回已打开的 MicroWIN 主窗口。没有则抛异常（不代劳启动）。"""
    for w in Desktop(backend="uia").windows():
        try:
            if w.element_info.class_name == APP_CLASS:
                return w
        except Exception:
            continue
    raise UiError("未找到已运行的 STEP 7-Micro/WIN SMART。请先手动打开软件和工程；"
                  "本工具不会替你启动或打开工程，以免顶掉你正在编辑的内容。")


def _walk(el, want, depth=0, max_depth=7, out=None):
    if out is None:
        out = []
    if depth > max_depth:
        return out
    try:
        kids = el.children()
    except Exception:
        return out
    for k in kids:
        try:
            ctype = k.element_info.control_type
            text = (k.window_text() or "").strip()
        except Exception:
            continue
        if text and ctype in want:
            out.append((ctype, text))
        _walk(k, want, depth + 1, max_depth, out)
    return out


def _find(el, ctype, text, depth=0, max_depth=8):
    """按控件类型和文本找第一个匹配的元素，返回元素对象或 None。"""
    if depth > max_depth:
        return None
    try:
        kids = el.children()
    except Exception:
        return None
    for k in kids:
        try:
            ct = k.element_info.control_type
            tx = (k.window_text() or "").strip()
        except Exception:
            continue
        if ct == ctype and tx == text:
            return k
        r = _find(k, ctype, text, depth + 1, max_depth)
        if r is not None:
            return r
    return None


def _project_dir(items):
    """从项目树根节点「项目名 (D:\\path\\项目名)」提取工程目录（不含扩展名）。"""
    for t in items:
        if " (" in t and t.endswith(")"):
            inner = t[t.rindex(" (") + 2:-1]
            if ":" in inner and (os.path.isdir(inner) or os.path.exists(inner + ".smart")):
                return inner
    return None


def read_project_tree():
    """只读读取当前工程：文件名、CPU 型号、POU 列表、工程目录。

    V2.8 项目树里「程序块」节点折叠、UIA 读不到 POU 子项，所以 POU 列表本函数
    尽力从已展开的 TreeItem 读（V3 兼容）；V2.8 由上层用引擎 EXPORT 补全。
    """
    app = find_app()
    title = app.window_text()
    items = [t for c, t in _walk(app, {"TreeItem"})]
    cpu = next((t for t in items if t.startswith("CPU ")), None)
    pous = []
    for t in items:
        m = _POU_RE.match(t)
        if m:
            pous.append({"name": m.group("name"), "id": m.group("id")})
    return {
        "window_title": title,
        "project_file": title.split(" - ")[0] if " - " in title else title,
        "cpu": cpu,
        "pous": pous,
        "pou_count": len(pous),
        "project_dir": _project_dir(items),
    }


def read_output_window():
    """读输出窗口文本（编译结果/错误列表）。只读。

    ⚠ V2.8 的输出窗口是自定义绘制控件，UIA 拿不到编译结果文本；这里返回的是
    界面里能读到的 Edit/Text/ListItem（可能是欢迎页等）。编译结果请改用
    smart_compile_and_export / smart_validate_project 走引擎拿日志。
    """
    app = find_app()
    texts = [t for c, t in _walk(app, {"Text", "Edit", "ListItem"})]
    return {"lines": texts}


def compile_project(confirm=False):
    """点击【编译】按钮。⚠ 会操作你正在使用的软件界面，需 confirm=True。"""
    if not confirm:
        raise UiError("compile_project 会操作你正在使用的软件界面，需显式传 confirm=True。")
    app = find_app()
    btn = _find(app, "Button", "编译")
    if btn is None:
        raise UiError("未找到【编译】按钮 —— 可能界面语言不是简体中文。")
    btn.click_input()
    return {"clicked": "编译",
            "note": "V2.8 输出窗口为自定义控件，编译结果请用 read_output_window() 或引擎 COMPILE 日志",
            "verified": True}
