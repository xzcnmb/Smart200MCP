"""点位图解析与 PLC 实时值比对。

"点位图 / 点位表" 是现场最常见的 I/O 分配表：一列地址、一列名称（可能还有
类型、注释、期望状态）。本模块把它解析成统一结构，再和 PLC 读回的实时值合并，
输出"每个点位叫什么、现在是什么状态、和期望是否一致"。

支持的输入格式（按扩展名 + 内容嗅探自动判断）：
  · JSON  —— 对象数组 [{"address":"I0.0","name":"启动",...}]，
            或映射 {"I0.0":"启动"} / {"I0.0":{"name":"启动","type":"BOOL"}}
  · CSV   —— 带表头，列名按 地址/名称/类型/期望 自动识别（中文英文都认）
  · TXT   —— 每行一个点位：`I0.0=启动` 或 `I0.0  启动`（=/:/Tab/空格 分隔均可）
  · XLSX  —— 安装了 openpyxl 时可用，否则提示先另存为 CSV

所有解析/比对都是纯函数，不连 PLC，可单测；真正读 PLC 在 online.py。
"""

import csv
import io
import json
import os
import re

from . import online

# 列名 → 字段 的识别表。按列头文本（去空格、小写）匹配。
_ADDR_COLS = {"地址", "点位", "变量地址", "地址/点位", "address", "addr", "io", "i/o",
              "点位号", "端子", "di", "do", "tag",
              "分配io", "分配i/o", "分配地址", "io地址", "i/o地址", "分配点位",
              "输入输出", "地址值", "addr值"}
_NAME_COLS = {"名称", "符号", "符号名", "注释", "描述", "说明", "name", "comment",
              "desc", "description", "label", "信号", "功能"}
_TYPE_COLS = {"类型", "数据类型", "type", "datatype", "data_type", "格式"}
_EXPECT_COLS = {"期望值", "期望", "期望状态", "默认值", "参考值", "expected", "expect",
                "value", "目标值", "正常状态"}


def normalize_address(addr):
    """地址归一：去空白、大写。' i0.0 ' -> 'I0.0'。"""
    return str(addr).strip().upper() if addr is not None else None


def _parse_expected(value, fmt=None):
    """把期望值文本解析成可比较的 Python 值；解析不了原样返回字符串。"""
    if value is None:
        return None
    s = str(value).strip()
    if s == "":
        return None
    low = s.lower()
    if low in ("1", "true", "on", "yes", "开", "高"):
        return True
    if low in ("0", "false", "off", "no", "关", "低"):
        return False
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s


def _match(actual, expected):
    """比较实际值与期望值。浮点带容差。期望为 None 时 match=None（无可比）。"""
    if expected is None:
        return None
    if isinstance(expected, bool) and isinstance(actual, bool):
        return actual == expected
    if isinstance(expected, float) or isinstance(actual, float):
        try:
            return abs(float(actual) - float(expected)) < 1e-6
        except (TypeError, ValueError):
            return False
    if isinstance(expected, bool) != isinstance(actual, bool):
        # bool 与非 bool 混：都转 1/0 再比（如期望 1 实际 True）
        return (1 if actual else 0) == (1 if expected else 0)
    return actual == expected


def _parse_txt(text):
    """解析 TXT 点位表：每行 `地址[=/:空白]名称`。

    地址不含空白，所以行首到第一个空白或 =/: 之间就是地址，其余整体当名称
    （名称可含空格，如 `I0.0 电机 启动`）。需要类型/期望值请用 CSV 或 JSON。
    """
    points = []
    for lineno, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith(("#", "//", ";")):
            continue
        m = re.match(r"^([^\s=:：]+)\s*(?:[=:：]\s*)?(.*)$", s)
        if not m:
            continue
        addr = normalize_address(m.group(1))
        if not addr or not re.match(r"^[IQMV]", addr):
            continue
        pt = {"address": addr, "raw": f"line {lineno}: {s}"}
        name = m.group(2).strip()
        if name:
            pt["name"] = name
        points.append(pt)
    return points


def _parse_json(text):
    """解析 JSON 点位表。"""
    data = json.loads(text)
    points = []
    if isinstance(data, dict):
        # 可能是 {地址: 名称} 或 {地址: {..}}
        for addr, v in data.items():
            pt = {"address": normalize_address(addr)}
            if isinstance(v, dict):
                if "address" in v:
                    pt["address"] = normalize_address(v.get("address"))
                pt["name"] = v.get("name") or v.get("注释") or v.get("名称")
                pt["type"] = v.get("type") or v.get("类型")
                pt["expected"] = _parse_expected(
                    v.get("expected") or v.get("期望") or v.get("期望值"), pt.get("type"))
                if v.get("comment"):
                    pt.setdefault("comment", v.get("comment"))
            else:
                pt["name"] = str(v) if v is not None else None
            points.append(pt)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                addr = normalize_address(item.get("address") or item.get("地址")
                                         or item.get("addr") or item.get("点位"))
                pt = {"address": addr}
                pt["name"] = item.get("name") or item.get("名称") or item.get("符号")
                pt["type"] = item.get("type") or item.get("类型")
                pt["expected"] = _parse_expected(
                    item.get("expected") or item.get("期望") or item.get("期望值"),
                    pt.get("type"))
                if item.get("comment"):
                    pt["comment"] = item.get("comment")
                points.append(pt)
            elif isinstance(item, str):
                points.append({"address": normalize_address(item)})
    return points


def _detect_delimiter(text):
    """嗅探分隔符：Tab 还是逗号（Excel 粘贴的点位表常是 Tab）。"""
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith(("#", "//", ";")):
            return "\t" if s.count("\t") > s.count(",") else ","
    return ","


def _parse_csv(text):
    """解析 CSV/TSV 点位表：自动识别表头列与分隔符（逗号或 Tab）。"""
    delim = _detect_delimiter(text)
    reader = csv.reader(io.StringIO(text), delimiter=delim)
    rows = [r for r in reader]
    if not rows:
        return []
    header = [(c or "").strip().lower() for c in rows[0]]

    def col_idx(names):
        for i, h in enumerate(header):
            if h in names:
                return i
        return None

    i_addr = col_idx(_ADDR_COLS)
    i_name = col_idx(_NAME_COLS)
    i_type = col_idx(_TYPE_COLS)
    i_expect = col_idx(_EXPECT_COLS)

    # 没表头时：第 1 列当地址、第 2 列当名称（常见的两列点位表）
    if i_addr is None:
        i_addr = 0
        if i_name is None and len(header) > 1:
            i_name = 1
        start = 0
    else:
        start = 1

    points = []
    for ridx, row in enumerate(rows[start:], start + 1):
        def cell(idx):
            if idx is None or idx >= len(row):
                return None
            v = row[idx].strip()
            return v if v != "" else None

        addr = normalize_address(cell(i_addr))
        if not addr:
            continue
        pt = {"address": addr, "raw": f"row {ridx}"}
        if i_name is not None:
            pt["name"] = cell(i_name)
        if i_type is not None:
            pt["type"] = cell(i_type)
        if i_expect is not None:
            pt["expected"] = _parse_expected(cell(i_expect), pt.get("type"))
        points.append(pt)
    return points


_HEADER_HINTS = _ADDR_COLS | _NAME_COLS | _TYPE_COLS | _EXPECT_COLS | {
    "序号", "编号", "no", "index", "id", "#"}


def _looks_like_csv(text):
    """内容嗅探：首条非空行是表头（逗号/Tab 分隔、且含已知列名）或含逗号 → 当 CSV。

    点位表 TXT 一般是"地址 名称"（地址在行首、无表头），所以靠表头识别来区分。
    """
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith(("#", "//", ";")):
            fields = [f.strip().lower() for f in re.split(r"[,，\t]", s) if f.strip()]
            if len(fields) > 1 and any(f in _HEADER_HINTS for f in fields):
                return True
            return "," in s
    return False


def parse_pointmap(path=None, text=None):
    """解析点位图文件（或文本），返回点列表 [{address,name,type,expected,raw}]。

    传 path 读文件；传 text 直接解析内容。两者都传以 path 为准。
    返回 [] 且文件为空/无有效行时，如实返回空列表，由调用方决定是否报错。
    """
    if path is not None:
        if not os.path.exists(path):
            raise FileNotFoundError(f"点位图不存在：{path}")
        text = _read_text(path, os.path.splitext(path)[1].lower())
    if text is None:
        raise ValueError("parse_pointmap 需要 path 或 text 之一")

    text = text.lstrip("\ufeff")  # 去 BOM
    ext = os.path.splitext(path)[1].lower() if path else ""

    if ext == ".json" or text.lstrip().startswith(("{", "[")):
        points = _parse_json(text)
    elif ext == ".xlsx":
        points = _parse_xlsx(path)
    elif ext in (".csv", ".tsv") or _looks_like_csv(text):
        points = _parse_csv(text)
    else:
        points = _parse_txt(text)
    return [p for p in points if p.get("address")]


def _read_text(path, ext):
    if ext == ".xlsx":
        return ""  # xlsx 走 _parse_xlsx 单独读
    with open(path, "rb") as f:
        raw = f.read()
    # 优先 UTF-8；失败退回 GBK（现场点表常见编码）
    for enc in ("utf-8-sig", "gbk", "latin1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def _parse_xlsx(path):
    try:
        import openpyxl
    except ImportError:
        raise OnlineErrorPointmap(
            "读取 .xlsx 需要 openpyxl（pip install openpyxl）。"
            "也可以把点表在 Excel 里另存为 .csv 再喂给本工具。")
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    ws = wb.active
    rows = [[("" if c is None else str(c)) for c in row] for row in ws.iter_rows(values_only=True)]
    wb.close()
    if not rows:
        return []
    buf = io.StringIO()
    csv.writer(buf).writerows(rows)
    return _parse_csv(buf.getvalue())


class OnlineErrorPointmap(Exception):
    pass


def compare(plc_values, points):
    """把 PLC 实时值并进点位图，产出比对结果。纯函数。

    plc_values: {地址: 值}（来自 online.Plc.read_many）。
    points: parse_pointmap 的输出。
    返回 {"points": [...], "total", "matched", "mismatched", "no_expected", "missing"}。
    每个 point 在原字段上追加 actual 与 match（True 一致 / False 不一致 / None 无期望）。
    """
    merged = []
    matched = mismatched = no_expected = missing = 0
    for p in points:
        addr = p["address"]
        actual = plc_values.get(addr)
        row = dict(p)
        row["actual"] = actual
        row["read"] = addr in plc_values
        if not row["read"]:
            row["match"] = None
            missing += 1
            merged.append(row)
            continue
        expected = row.get("expected")
        m = _match(actual, expected)
        row["match"] = m
        if m is None:
            no_expected += 1
        elif m:
            matched += 1
        else:
            mismatched += 1
        merged.append(row)

    return {
        "total": len(merged),
        "matched": matched,
        "mismatched": mismatched,
        "no_expected": no_expected,
        "missing": missing,
        "points": merged,
        "mismatches": [r for r in merged if r.get("match") is False],
    }
