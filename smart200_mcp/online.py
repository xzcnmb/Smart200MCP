"""在线通讯层（snap7 / S7 协议，TCP 102）。

S7-200 SMART 的 V 存储区在 S7 协议上映射为 DB1，这是本层全部读写的基础。
连接参数固定 rack=0, slot=1。

为什么用 snap7 而不是注入软件的监控接口：STEP 7-Micro/WIN SMART 自己的
"状态图表 / 程序监控" 也是走 S7 协议 —— 软件内部经 Communications\\tcpipl4.dll
（一个 COM server）说话，datamanagers.dll 里的 MWStatusLoopMgr::ReadComm 把地址
打包成 sCOMMCOMPASS_MEM_STRUCT 再经 ICommCompass COM 接口下发。逆向结论是：
后台监控接口存在，但它是 COM vtable + 私有结构，且要求软件本身在线；
而 snap7 用同一份 S7 协议独立实现，不依赖软件在线，可直接对 PLC 读点位/监控。
详见 docs/ONLINE_MONITOR.md。

⚠ 状态：本层按 S7 协议规范编写，未经真机验证（开发时手边无 CPU）。
   首次接真机请先用 cpu_info() 试探，勿直接写值。
"""

import re
import struct
import time

import snap7

V_DB_NUMBER = 1  # S7-200 SMART: V 区 == DB1

_AREA_ENUM = {
    "V": snap7.type.Area.DB,   # V 区走 db_read/db_write，不走 read_area
    "M": snap7.type.Area.MK,
    "I": snap7.type.Area.PE,
    "Q": snap7.type.Area.PA,
}

_ADDR_RE = re.compile(
    r"^(?P<area>VB|VW|VD|MB|MW|MD|IB|IW|ID|QB|QW|QD|V|M|I|Q)"
    r"(?P<byte>\d+)(?:\.(?P<bit>[0-7]))?$", re.I)

_SIZE = {"B": 1, "W": 2, "D": 4}

# 格式名归一：点表里写 "BOOL/REAL/INT..." 都能对上
_FMT_ALIASES = {
    "auto": "auto", "": "auto", None: "auto",
    "bool": "bool", "bit": "bool",
    "byte": "byte", "b": "byte", "uint8": "byte", "usint": "byte",
    "word": "word", "w": "word", "uint16": "word", "uint": "word", "u16": "word",
    "dword": "dword", "d": "dword", "uint32": "dword", "udint": "dword", "u32": "dword",
    "int": "int", "i16": "int", "short": "int",
    "dint": "dint", "i32": "dint", "long": "dint",
    "real": "real", "float": "real", "r": "real",
    "string": "string", "str": "string",
}


class OnlineError(Exception):
    pass


def parse_address(addr):
    """'VW100' / 'V10.3' / 'M0.0' -> (area, byte, bit, size)。非法地址抛异常。

    area ∈ {V,M,I,Q}；bit 为 None 表示字节/字/双字地址；size ∈ {1,2,4}。
    """
    if not isinstance(addr, str):
        raise OnlineError(f"地址必须是字符串，收到 {type(addr).__name__}: {addr!r}")
    m = _ADDR_RE.match(addr.strip())
    if not m:
        raise OnlineError(
            f"无法解析地址 {addr!r}（支持 VB/VW/VD/MB/MW/MD/IB/IW/ID/QB/QW/QD 与位地址如 V10.3）")
    area = m.group("area").upper()
    byte = int(m.group("byte"))
    bit = m.group("bit")
    bit = int(bit) if bit is not None else None
    if len(area) == 2:
        if bit is not None:
            raise OnlineError(f"{addr}: 字节/字/双字地址不能带位号")
        return area[0], byte, None, _SIZE[area[1]]
    if bit is None:
        raise OnlineError(f"{addr}: 位地址需写成 {area}{byte}.0 形式")
    return area, byte, bit, 1


def normalize_fmt(fmt):
    """把点表里的类型串归一成 decode 认识的键。不认识的回 auto。"""
    key = str(fmt).strip().lower() if fmt is not None else "auto"
    return _FMT_ALIASES.get(key, "auto")


def decode(raw, size, fmt="auto"):
    """把读回的原始字节按宽度+格式解码成 Python 值。

    raw: bytes（S7 协议 big-endian）。size: 1/2/4。fmt: 见 normalize_fmt。
    纯函数，无 PLC 依赖，可单测。
    """
    fmt = normalize_fmt(fmt)
    if fmt == "bool":
        return bool(raw[0] & 1)
    if fmt == "string":
        # S7-200 SMART 字符串：首字节是长度（Pascal 风格）
        n = raw[0]
        return raw[1:1 + n].decode("latin1", "replace")
    if fmt == "real":
        if size < 4:
            raise OnlineError("REAL 需要 4 字节（用 VD/MD/ID/QD），当前宽度 %d" % size)
        return round(struct.unpack(">f", raw[:4])[0], 6)
    if fmt == "int":
        if size != 2:
            raise OnlineError("INT 需要 2 字节（用 VW/MW/IW/QW）")
        return struct.unpack(">h", raw)[0]
    if fmt == "dint":
        if size != 4:
            raise OnlineError("DINT 需要 4 字节（用 VD/MD/ID/QD）")
        return struct.unpack(">i", raw)[0]
    # 无符号 / auto：按宽度给整数
    return int.from_bytes(raw[:size], "big")


def cpu_state_from_szl(data):
    """从 SZL 0x0424 的 Data 原始字节判 CPU 状态。纯函数，可单测。

    数据区偏移 7 处：0x08=RUN；其余一律 STOP（snap7 s7_micro_client 的
    opGetPlcStatus 注释：老 CPU 可能用 0x03 表示 STOP，非 0x08 按 STOP）。
    """
    if len(data) > 7 and data[7] == 0x08:
        return "RUN"
    return "STOP"


class Plc:
    """一次连接的上下文。用法：with Plc('192.168.2.1') as plc: ..."""

    def __init__(self, ip, rack=0, slot=1):
        self.ip, self.rack, self.slot = ip, rack, slot
        self._c = None

    def __enter__(self):
        self._c = snap7.client.Client()
        try:
            self._c.connect(self.ip, self.rack, self.slot)
        except Exception as e:
            raise OnlineError(f"连接 {self.ip} 失败: {e}") from e
        return self

    def __exit__(self, *exc):
        if self._c is not None:
            try:
                self._c.disconnect()
            finally:
                self._c = None

    def _area_read(self, area, byte, size):
        if area == "V":
            return self._c.db_read(V_DB_NUMBER, byte, size)
        return self._c.read_area(_AREA_ENUM[area], 0, byte, size)

    def _area_write(self, area, byte, payload):
        if area == "V":
            return self._c.db_write(V_DB_NUMBER, byte, payload)
        return self._c.write_area(_AREA_ENUM[area], 0, byte, payload)

    def cpu_state(self):
        """读 CPU 运行状态：SZL 0x0424。

        ⚠ python-snap7 v3 的 get_cpu_state() 是 stub（纯 Python 实现恒返回
        RUN），不能用 —— 必须走 SZL（据 snap7 s7_micro_client 的 opGetPlcStatus）。
        """
        szl = self._c.read_szl(0x0424, 0)
        data = bytes(b & 0xFF for b in szl.Data[: szl.Header.LengthDR])
        return cpu_state_from_szl(data)

    def cpu_info(self):
        """型号、固件、运行状态、保护级别、CP 信息。接真机时先跑这个。

        各分项独立 try：某一项读不通（老固件不支持该 SZL）不影响其余字段，
        如实记到对应字段里，不静默吞掉。
        """
        info = self._c.get_cpu_info()
        out = {
            "ip": self.ip,
            "module_type": info.ModuleTypeName.decode("latin1", "ignore").strip("\x00"),
            "serial": info.SerialNumber.decode("latin1", "ignore").strip("\x00"),
            "as_name": info.ASName.decode("latin1", "ignore").strip("\x00"),
            "module": info.ModuleName.decode("latin1", "ignore").strip("\x00"),
        }
        for label, fn in (
                ("cpu_state", self.cpu_state),
                ("protection", self._protection),
                ("cp_info", self._cp_info),
                ("order_code", self._order_code)):
            try:
                out[label] = fn()
            except Exception as e:
                out[label] = {"error": str(e)}
        return out

    def _protection(self):
        """保护级别（SZL 0x0232）。下载保护开启时 S7 块下载会被拒。"""
        p = self._c.get_protection()
        return {"download_protected": bool(p.sch_schal),
                "raw": [p.sch_schal, p.sch_par, p.sch_rel, p.bart_sch, p.anl_sch]}

    def _cp_info(self):
        """CP 信息（SZL 0x0131）：协商 PDU / 最大连接数 —— 排连接问题的第一手数据。"""
        cp = self._c.get_cp_info()
        return {"max_pdu": cp.MaxPduLength, "max_connections": cp.MaxConnections,
                "max_mpi_rate": cp.MaxMpiRate, "max_bus_rate": cp.MaxBusRate}

    def _order_code(self):
        """订货号 + 固件版本（SZL 0x0011）。"""
        oc = self._c.get_order_code()
        return {"order_code": oc.OrderCode.decode("latin1", "ignore").strip("\x00"),
                "firmware": "%d.%d.%d" % (oc.V1, oc.V2, oc.V3)}

    def plc_stop(self):
        """STOP CPU。返回执行前后状态回显（SZL 0x0424）。"""
        before = self.cpu_state()
        self._c.plc_stop()
        return {"before": before, "after": self.cpu_state()}

    def plc_run(self):
        """RUN CPU（热启动）。返回执行前后状态回显。"""
        before = self.cpu_state()
        self._c.plc_hot_start()
        return {"before": before, "after": self.cpu_state()}

    def get_datetime(self):
        return self._c.get_plc_datetime()

    def set_datetime(self, dt):
        self._c.set_plc_datetime(dt)
        return {"set": dt.isoformat(sep=" "),
                "now": self.get_datetime().isoformat(sep=" ")}

    def sync_datetime(self):
        self._c.set_plc_system_datetime()
        return {"synced_to_pc": True,
                "now": self.get_datetime().isoformat(sep=" ")}

    def diag_probe(self):
        """实验性诊断探测：逐个试读候选 SZL，把支持情况如实记下来。只读。

        S7-200 SMART 没有公开的 SZL 支持清单，下列 ID 是 S7-300/1200 系的
        实现先例，真机首次接入时用这个摸底，探通的再考虑转正。
        """
        probes = {}
        for szl_id, label in (
                (0x00A0, "诊断缓冲(python-snap7 read_diagnostic_buffer 所用)"),
                (0x040C, "诊断缓冲(S7-300/1200 标准 ID)"),
                (0x0025, "强制表(预期不支持)"),
                (0x0131, "CP 信息(连通性自查)"),
                (0x0424, "CPU 状态(状态字节应在偏移 7)")):
            try:
                szl = self._c.read_szl(szl_id, 0)
                data = bytes(b & 0xFF for b in szl.Data[: szl.Header.LengthDR])
                probes[label] = {"supported": True, "bytes": len(data),
                                 "hex_head": data[:32].hex(" ")}
            except Exception as e:
                probes[label] = {"supported": False, "error": str(e)[:200]}
        return probes

    def list_blocks(self):
        """CPU 里的块计数（S7 块列表）。⚠ S7-200 SMART 的块到 S7 块类型的
        映射未验证，先如实给原始计数，真机核对后再解读。"""
        bl = self._c.list_blocks()
        return {"OB": bl.OBCount, "FB": bl.FBCount, "FC": bl.FCCount,
                "SFB": bl.SFBCount, "SFC": bl.SFCCount,
                "DB": bl.DBCount, "SDB": bl.SDBCount}

    def read(self, addr, fmt="auto"):
        """按地址读一个值。位地址返回 bool，其余按 fmt 解码。"""
        area, byte, bit, size = parse_address(addr)
        raw = self._area_read(area, byte, size)
        if bit is not None:
            return bool(raw[0] >> bit & 1)
        return decode(raw, size, fmt)

    def read_many(self, addrs, fmt=None):
        """读一批地址。addrs 可为 [str] 或 {地址: 格式}。返回 {地址: 值}。

        fmt 是这批地址的统一格式；dict 形式可逐地址指定格式（覆盖 fmt）。
        """
        if isinstance(addrs, dict):
            return {a: self.read(a, addrs[a]) for a in addrs}
        return {a: self.read(a, fmt) for a in addrs}

    def read_area_bytes(self, area, byte, size):
        """读一块原始字节（I/Q/M 区），用于批量点位解码。"""
        return self._area_read(area, byte, size)

    def write(self, addr, value):
        """按地址写一个值。位地址走读-改-写。"""
        area, byte, bit, size = parse_address(addr)
        if bit is not None:
            raw = bytearray(self._area_read(area, byte, 1))
            if value:
                raw[0] |= 1 << bit
            else:
                raw[0] &= ~(1 << bit) & 0xFF
            self._area_write(area, byte, bytes(raw))
        else:
            self._area_write(area, byte, int(value).to_bytes(size, "big"))
        return {"address": addr, "written": value}


# ---------------- 点位（I/O/M）批量读与监控 ----------------

# S7-200 SMART 各 CPU 本机 I/O 点数：(DI, DO)。用于"读全部点位"时自动定范围。
CPU_IO = {
    "SR20": (12, 8), "ST20": (12, 8), "CR20": (12, 8), "CR20S": (12, 8),
    "SR30": (18, 12), "ST30": (18, 12), "CR30": (18, 12),
    "SR40": (24, 16), "ST40": (24, 16), "CR40": (24, 16),
    "SR60": (36, 24), "ST60": (36, 24), "CR60": (36, 24),
}


def cpu_io_sizes(module_type):
    """从 CPU 型号字符串推 (DI 点数, DO 点数)。认不出返回 None。

    纯函数可单测。模块名形如 'CPU SR40' / 'CPU ST60' / '6ES7 288-1SR40-0AA0'。
    """
    if not module_type:
        return None
    s = module_type.upper()
    for key in sorted(CPU_IO, key=len, reverse=True):
        if key in s:
            return CPU_IO[key]
    return None


def bits_from_bytes(raw, area, start_byte):
    """把一块原始字节展开成 [(地址, bool)] 列表。纯函数。

    raw: 若干字节，每字节 8 个位，位 0 是低位。start_byte 是首字节号。
    """
    out = []
    for i, b in enumerate(raw):
        for bit in range(8):
            out.append((f"{area}{start_byte + i}.{bit}", bool(b >> bit & 1)))
    return out


def read_points(plc, di_count=None, do_count=None, include_m=None, m_bytes=0,
                module_type=None):
    """批量读 I/Q（可选 M）点位，返回 [(地址, bool)]。

    di_count/do_count 缺省时用 module_type 推；还推不出就默认 ST40 的范围
    （24DI/16DO），宁可多读几个字节也不漏点位 —— 读整字节是无损的。
    """
    sizes = cpu_io_sizes(module_type)
    if sizes is None:
        sizes = (24, 16)
    di = di_count if di_count else sizes[0]
    do = do_count if do_count else sizes[1]
    in_bytes = (di + 7) // 8
    out_bytes = (do + 7) // 8

    points = []
    points += bits_from_bytes(plc.read_area_bytes("I", 0, in_bytes), "I", 0)
    points += bits_from_bytes(plc.read_area_bytes("Q", 0, out_bytes), "Q", 0)
    if include_m and m_bytes > 0:
        points += bits_from_bytes(plc.read_area_bytes("M", 0, m_bytes), "M", 0)
    return points


def monitor(ip, addresses, interval=0.5, duration=0.0, max_samples=0,
            fmt=None, di_count=None, do_count=None, include_m=None, m_bytes=0,
            on_tick=None):
    """轮询读一批地址，返回时间序列。

    addresses: 地址列表或 {地址: 格式}。interval: 轮询间隔秒。
    停止条件：duration>0 按秒跑满；否则 max_samples>0 按采样数；两者都给取先到的。
    两者都不给，默认采 5 个点（duration 会由 max_samples 推出，等于一个快照轮询）。
    on_tick(seq, values) 可选回调，每轮拿到 (序号, {地址:值})，便于流式输出。

    返回 {"addresses": [...], "samples": [{"t": 时刻, "seq": 序号, "values": {地址:值}}, ...]}。
    纯轮询编排，具体读走 Plc —— 不读 PLC 时可用 on_tick 注入假数据做单测。
    """
    if not addresses:
        raise OnlineError("monitor: addresses 不能为空")
    if max_samples <= 0 and duration <= 0:
        max_samples = 5
    deadline = time.time() + duration if duration > 0 else None
    samples = []
    seq = 0
    addr_list = list(addresses.keys()) if isinstance(addresses, dict) else list(addresses)
    prev = None

    # 整轮监控只开一条连接：PG 连接在 S7-200 SMART 上独占，
    # 每轮重连既慢又抢通道（python-snap7 issue #765）。
    with Plc(ip) as plc:
        while True:
            if max_samples > 0 and seq >= max_samples:
                break
            if deadline is not None and time.time() >= deadline:
                break
            if isinstance(addresses, dict):
                values = plc.read_many(addresses)
            else:
                values = plc.read_many(addr_list, fmt)
            changed = [a for a in addr_list
                       if prev is not None and prev.get(a) != values.get(a)]
            sample = {"t": round(time.time(), 3), "seq": seq,
                      "values": values, "changed": changed}
            samples.append(sample)
            if on_tick:
                on_tick(seq, values)
            prev = values
            seq += 1
            if max_samples > 0 and seq >= max_samples:
                break
            if deadline is not None and time.time() >= deadline:
                break
            time.sleep(interval)
    latest = samples[-1]["values"] if samples else {}
    changed_overall = sorted({a for s in samples for a in s["changed"]})
    return {"ip": ip, "addresses": addr_list,
            "sample_count": len(samples), "latest": latest,
            "changed_overall": changed_overall, "samples": samples}
