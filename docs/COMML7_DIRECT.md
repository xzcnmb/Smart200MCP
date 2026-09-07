# S7-200 SMART 脱机直连协议文档与实现路径（commL7/commL8 逆向）

> 逆向日期：2026-09-07。方法：纯静态（pefile 导出/导入、capstone 反汇编、
> ASCII/UTF-16 字符串、资源段、二进制 GUID 扫描、注册表只读核查）。
> 未运行/附加任何西门子进程。
>
> 前序情报：`A_web_research.md`（协议公开事实）、`C_binary_recon.md`（全 PE 侦察）、
> 本报告补齐：S7DOS 遗留传输栈（SysWOW64 + Common Files）、SPS7_PDU/L4RB 内部帧、
> 全部 eCOMMCOMPASS 枚举与结构字段、点火链（CLSID/AppID/entry point）、
> s7200.sig / Features.dvp 文件格式、分层直连计划与真机验证步骤。
>
> 标记约定：**[已确认]** = 二进制证据（文件+偏移）或公开实现一致；
> **[推断]** = 静态强相关但需真机/运行时确认；**[待抓包]** = 必须 Wireshark 验证。

---

## 1. 结论先行

1. **MicroWIN SMART 的在线栈 = "S7-Compass" 分层 COM 架构 + 遗留 S7DOS 传输内核**。
   L7（commL7.dll）做 S7-Compass 命令序列，L4（tcpipl4.dll 等）只是
   `inet_pton` + 调 `S7ONLINX.dll` 的 `SCP_open/SCP_send/SCP_receive`；
   **真正的 TCP socket 与 S7-200 PDU 编码在 S7DOS 内核里**
   （`C:\Windows\SysWOW64\s7otbxsx.exe` 服务 + `C:\Program Files\Common Files\Siemens\Automation\Simatic OAM\bin\s7onlinx64.dll`
   + 运行时按 SINEC LogDevice 注册表加载的 L4DRIVER）。
2. **对 S7-200 SMART 的以太网上线协议 = 标准 S7 协议（COTP + S7 PDU，TCP 102）**
   ——snap7 的 `TSnap7MicroClient` 按同一协议实现且社区有真机实证。
   commL7 里的 `P_PROGRAM` 域常量、`Go To Run/Stop`、`Upload Begin/Segment/End`
   与 S7 功能码 0x28/0x29、0x1A–0x1F 一一对应 **[已确认+公开实现]**。
   → **直连不需要 COM/S7DOS，直接 socket 102 发 COTP/S7 PDU 即可**；
   S7-Compass 只是它的 COM 封装。
3. snap7 已覆盖：变量读写、RUN/STOP、SZL、时钟、块目录/上传下载框架。
   **snap7 没覆盖、而 comm 栈证明 CPU 支持的能力**（= 我们的差异化空间）：
   事件日志（COM_GetEventLog，sCOMMCOMPASS_EVENT_LOG，27 个事件码/26 个原因码，
   枚举已全量逆出）、块插入/删除（InsertBlock/DeleteBlock，含 RTE 变体）、
   Legitimize 密码认证序列、DST、MC 卡、强制（ForceWW，**S7-200 SMART 固件是否
   实现 S7 协议侧 force 待真机验证** —— snap7 micro client 无实现）、
   站管理（Identify 闪 LED/IP 配置，S7IE_* 服务）、扫描时间。
4. **点火链两条路都已定位**（§7）：in-proc COM（CLSID_CommCompassL7 等已提取候选值）
   与 commL8Host.exe 独立 COM 宿主（AppID/ProgID/typelib 已提取，运行时注册）。
   但注意：**点火链是"借道"，不是目标** —— 直连协议（§8）不需要任何 COM。

---

## 2. 通讯栈全貌（实测 import 关系）

```
MWSmart.exe (CCompassApp, x86)
 ├─ executive.dll ──────────── 644 import（COM_*/PRJ_*/CHT_* 门面）
 │    └─ storeretrieveverify.dll（MWStore/MWRetrieve，导出 3536 个，含全部在线 API）
 │         └─ datamanagers.dll（CLoadMgr 下载/上传编排，g_pIComm/g_pIBlockBuilder）
 │
 └─ 运行时 LoadLibrary（无静态 import）：
      Communications\commL8.dll     L8 宿主对象 CCommCompass（ICommCompass/ICommCompassUDM）
      Communications\commL7.dll     L7 S7-Compass 命令（ICommCompassL7/NonPublic）
      Communications\blockbuilder.dll 块组装/解组（IBlockBuilder，28 方法）
      Communications\device.dll       能力矩阵（IDeviceFeatures，190 方法）
      Communications\signature.dll    指令签名库（ISignature，175 方法；数据=s7200.sig 类）
      Communications\tcpipl4.dll      L4 TCP/IP（ICommCompassL4，CLSID_TCPIP）
      Communications\tcpip64l4.dll    L4 TCP/IPv6（CLSID_TCPIP64）
      Communications\smartusbl4.dll   L4 USB（CLSID_SmartUSB，HID+SETUPAPI）
      Communications\smartcablel4.dll L4 PPI 电缆（CLSID_SmartCable）
      变体数据 DLL（无导出目录，按 CPU 家族 %s\commL8%x.dll 加载）：
        commL8404/409/804.dll、device404/409/804.dll、
        blockbuilder404/409/804.dll、signature404/409/804.dll

tcpipl4.dll ──import──> S7ONLINX.dll (C:\Windows\SysWOW64, 32位, 19 导出:
                          SCP_open/SCP_openW/SCP_open_async/SCP_close/SCP_send/
                          SCP_receive/SCP_send_receive/SCP_get_errno/SCP_get_dev_list(W)/
                          OnlDll_CheckDevOpen/OnlDll_SimulationOnOff*/SCI_time/SCI_conv_time/
                          SetSinecHWnd(Msg))
s7onlinx.dll（x86, "S7DOS Online DLL 32->64", 2020-07 编译）
 ├─ 32 位宿主（MicroWIN 自身）：原生执行
 └─ 64 位宿主：CreateProcess("\S7elonls64.exe")（C:\Windows\SysWOW64, x64）
      └─ LoadLibrary("\S7onlinx64.dll")  ← 本机位于
         C:\Program Files\Common Files\Siemens\Automation\Simatic OAM\bin\s7onlinx64.dll (x64, 17 导出)
         共享内存 Local\S7DosEmulationLayerSharedMem_ + 窗口消息 ...WinMsg_ + 命名管道
         （Local\S7DosEmulationLayerMutex_；SOFTWARE\Siemens\Shared Tools\S7DOS64）
s7onlinx64.dll 的 LoadDrv.c（源码路径 D:\agent\_work\1\s\SRC\S7DOS64\online\s7onlinx64\）：
  ├─ ReadLogDevice：设备名 → SINEC LogDevice 注册表 → "L4DRIVER = %s"（DLL/SYS 动态加载）
  ├─ S7OSCPT.DLL 隧道（SCPTunnel_OpenW/Send/Receive/Close...，远程/隧道模式开关
  │    OnlDll_TunnelSwitchCheck/OnOff；"s7onlinx64 as a tunnel client!"）
  └─ SETUPAPI USB 设备接口枚举（USB 传输）
s7otbxsx.exe（C:\Windows\SysWOW64, x86, "S7DOS TIS&Block Server"）
  ← s7otbxdx.dll（"S7DOS Block Administration" API，S7DOS_API：Send_Message，
     共享内存 S7OTBX_sm_%08.8X_ + 事件 S7OTBX_ev_%08.8X + 窗口消息）
  职责：L7 请求块(L7RB)管理、连接复用(mux)、重试队列、legitimation(密码)队列、
        DSGW/RPC7 段式传输状态机、PDU 编码（cnv_ag_header_to_pg / ag_bst_header）
  服务：PST_SET_NAME_OF_STATION / PST_SEARCH_FOR_FREE_IPADDRESS / CHECK_IS_IPADDRESS_FREE /
        SEARCH_AND_SET_PGIP_ADDRESS / GET_PGIP_ADDRESS_LIST / DELETE_PGIP_ADDRESS /
        S7O_S7NET_GET_{BUS_PARAMS,LIFE_LIST,DIRECT_PLC,REPORT,BAUDRATE} /
        USB_GET_DEVICE_ADDRESS / USB_RESET_DEVICE
s7owpstx.dll（"S7OWPSTX"，另一组 SCP_* 导出 + CD7/DCP 以太网发现：
  CD7_IDENTIFY_REQ/CD7_GET_REQ/CD7_SET_REQ/CD7_SHOWLOCATION_REQ，SNAP 头，
  DcpOpen/DcpRegisterHello，PnDiscovery COM）—— 站识别/LED 定位/PG IP 搜索用。
s7oniepgx.dll（WS2_32: htonl/ntohl/inet_addr/inet_ntoa + IPHLPAPI SendARP/
  AddIPAddress/DeleteIPAddress）—— PG 侧 IP 管理/ARP 可达性。
s7oniemmx.dll（"S7DOS PGtoIE DLL"）—— s7ie_* 的 IP 搜索/配置封装。
S7O.CommonServices.dll（.NET WCF：net.pipe://localhost/S7TunnelConfiguration，
  TCP_Port=/TCP_HostName=/S7DosHandles/KeepAlive）—— S7 远程隧道配置服务（与 PLC 数据路径无关）。
S7EPATDX.cpl / s7epaapi.dll / s7epatdx 家族（SysWOW64）—— PG/PC 接口面板 +
  LogDevice 配置（S7EPAAPI：LogDevice*/LogName*/PGSP_*；被 commL7/commL8/tcpipl4 import）。
```

**关键推论 [已确认]**：MicroWIN 的 L4 不自己开 socket。TCP 数据路径最终落在
S7DOS 动态加载的 L4DRIVER（本机 SINEC LogDevice 注册表为空 —— 该配置随
MicroWIN 首次通信时写入，或来自安装器；本机未留下痕迹，**驱动名待真机观察**）。
但 wire 协议与 S7DOS 内部实现无关 —— 对 S7-200 SMART 就是标准 S7/COTP（§8）。

---

## 3. 导出函数清单（本次实测，pefile）

### 3.1 Communications\ 各 COM 模块（PE 导出 = ATL 标准五件套，无协议 API）

| 模块 | PE 导出 | 实际 API（COM 接口，MIDL 字符串确认） |
|---|---|---|
| commL7.dll | DllGetClassObject/DllRegisterServer/DllUnregisterServer/DllCanUnloadNow/AutoRegister(AutoRegisterAll) | **ICommCompassL7**：BlockExists, CloseAllDevices, DeleteBlock, DownloadBlockWW, GetAllDevicesWW, GetBlockTimeStampsW, GetOpModeWW, GetPortInfo, GetEventLog, LegitimizeW, LockPortWWW, ReleaseLegitimizationWW, SetOpModeWW, UnlockPortW, UploadBlock, GetAlarmWWW；**ICommCompassL7NonPublic**：InsertBlock, SendPDU(pbyPDUBuffer,nPDUBufferSize)；**INotifyCompass**：FoundStation, StationData |
| commL8.dll | 同上（无 AutoRegister） | **ICommCompass**（L8 超集，89 方法，见 C 报告 §2.7）+ ICommCompassUDM + INotifyCompass(_2/_3) |
| tcpipl4.dll / tcpip64l4.dll | 五件套（无 AutoRegister） | **ICommCompassL4WW**：SCP_Open, SCP_Close, SCP_Send(pnResponsePDULength, ppbyResponsePDUBuffer, lMaxPDUSize), SCP_Receive, LifeList, GetPDUSize(lpnPDUSize), SetLegitimized(bLegitimized), **SetCOMMCompassL7(pCommL7)**（L4 持有 L7 反向指针）, UseLongTimeouts(userLongTimeouts)；INotifyCompass |
| smartusbl4.dll / smartcablel4.dll | 五件套 | ICommCompassL4（USB HID / PPI 电缆） |
| device.dll | 五件套 | IDeviceFeatures（190 能力位，C 报告 §2.7）+ IDeviceFeatureServer(+Configure) |
| signature.dll | 五件套 | ISignature 175 方法（GetSimaticMnemonic/GetOpCode/GetParameterCount/GetStackUsage/Serialize...） |
| blockbuilder.dll | 五件套 | IBlockBuilder 28 方法（AssembleBlockWWW/DisassembleBlockWWW/ComposeBlockWWW/ParseAndReturnSectionWW/AssembleFWW/AuthorizePOUWWW/GenProgramOffsetsWW/GetCpuBlocksWWW/GPB...） |
| commL8404/409/804、device404/409/804、blockbuilder404/409/804、signature404/409/804 | **无导出目录**（纯数据/变体 DLL，PDB 名 comm404/commL8409/comm804） | 按 `%s\commL8%x.dll` 被 commL8/commL8Host 加载，CPU 家族变体数据 [推断] |
| IComm*.ps.dll（18 个代理存根） | DllGetClassObject 五件套 | 接口名=文件名去 ps：IComm/ICommL4/ICommL7/ICommL7NonPublic/ICommUDM/ICommHost/IBlock/IBlockStore/IBlockRetrieve/IDeviceFeatures*/IDeviceOpcode/IGPB/INotify/ISignature/ISysData/ITagData/IWizData |

### 3.2 S7DOS 传输内核（SysWOW64 + Common Files）

| 模块 | 导出（实测） |
|---|---|
| s7onlinx.dll (x86) | SCP_open/SCP_openW/SCP_open_async/SCP_close/SCP_send/SCP_receive/SCP_send_receive/SCP_get_errno/SCP_get_dev_list(W)、OnlDll_CheckDevOpen/OnlDll_IsSimulationOn/OnlDll_SimulationOnOff(Check/SetMsg)、SCI_time/SCI_conv_time、SetSinecHWnd(Msg) |
| s7onlinx64.dll (x64, OAM\bin) | 同上 + OnlDll_TunnelSwitchCheck/OnlDll_TunnelSwitchOnOff（无 SCP_open/SCP_get_dev_list 32 版） |
| s7otbxsx.exe (x86) | 无导出（服务进程；命令行状态查询 "STATE of S7OTBXSX-Server: %d ... %s, users = %d"） |
| s7otbxdx.dll (x86) | 147 个 s7* API：s7ag_{bsnd,brcv_create/delete,bub_read_var(_seg),bub_write_var(_seg),bub_cycl_read_*,start,stop,resume,mem_mode,msg_mode,pmc_*,read_szl,read_time(_ex),write_time(_ex),test(_delete),link_in,compress,be sy_update,password(_ex)}、s7blk_{dir1,dir2,findfirst,findnext,read,write,delete}、s7db_{open,close,copy,create,delete}、s7dos_{release,trace,version}、s7dp_set_slave_address、s7dpt_read/write、s7epr_{image_read,image_write,kb_memory,kennbit,physical_rd,physical_wr,property,service}、s7ie_{CheckIsIPAddressFree,CloseServer,DeletePGIPAddress,GetAdapterInfo,GetDataset,GetIeParam,GetMacAddress,GetNetworkParam(Ext),GetPGIPAddressList,GetPbParam,Identify(Name)(_Cancel),IsReachable,SearchAndSetPGIPAddress,SearchForFreeIPAddress,SetDataset,SetIeParam,SetNameOfStation,SetNetworkParam(Ext),SetOpenTCPConnections,SetPbParam,ShowLocation}、s7l7_{dataexchange2,download_domain,pi_service(_ex),upload_domain}、s7net_{get_baudrate,get_bus_params,get_diagnose,get_direct_plc,get_life_list,get_report,start/stop_diagnose}、s7pnio_{open/close_cd7,epmap_*,read/write_record*}、s7prog_{laden_init,blk_laden,laden_ende}、s7sim_get_life_list、s7usb_{get_detailed_info,get_device_address,reset_device,show_location}、s7H_{start,stop}_cpu、s7_{set,get,clear}_password(_ex)、s7ag_password |
| s7owpstx.dll (x86) | SCP_close/SCP_get_errno/SCP_open(W)/SCP_receive/SCP_send/SetSinecHWnd(Msg) |
| s7oniemmx.dll (x86) | CheckIPAddressAndSubnetMask/CheckIsIPAddressFree/CloseServer/DeletePGIPAddress/GetAdapterInfo/GetMacAddress(Subnet)/GetPGIPAddressList/IsReachable/SearchAndSetPGIPAddress/SearchForFreeIPAddress/SetNetworkIPAddress |
| s7epromapi.dll (x86) | IsInternalPrommerActive/IsPgWithInternalPrommer/ReadEpSettings |
| s7_sr.dll (x86) | Call_Ina/ResetSR/SRMD_{Request,Reset,Set}/SR_CfgDiag/SR_Trace/SetSR |
| S7EPATDX.cpl (x86) | 232 个 PGSP_*/LogDevice*/LogName*/S7Reg* + RunPGPCPanal(AsAdmin)/GetPortList/DeviceIDGetEnum/NetTypeGetEnum |

**SCP_* 错误码（s7onlinx 字符串，0xC488–0xC624）**：SCP_SOFTWARE / SCP_MEM /
SCP_RESOURCE / SCP_NOMESS / SCP_NO_WIN_SERV / SCP_TIMEOUT / SCP_PARAM /
SCP_ILLEGAL / SCP_DEVOPEN。S7DOS L7 返回码样本：0x0112 INVALID_PARAM、
0x0140 CALLOC_ERROR、0x011F、0x2032 EPR_DEV_NOT_SUPPORTED、0x4022 Layer7 Timeout、
0x4023 Applikation not available、0x4024 PBK Timeout。

---

## 4. 关键常量 / 枚举表（含十六进制值来源）

### 4.1 传输与连接（tcpipl4.dll / commL7.dll MIDL 串，偏移见左）

| 名称 | 值/成员 | 来源 |
|---|---|---|
| TCP 端口 | **102** | [公开实现+社区真机] snap7 `connect(ip,0,1)` 默认 tcp_port=102（A 报告 §2）；MicroWIN 二进制中**无端口字符串常量**（端口在 S7DOS 驱动的代码立即数里，静态未定位）→ 抓包复核 |
| rack/slot | 0 / 1 | [已确认] snap7 micro client `RemoteTSAP=(ConnType<<8)+(Rack*0x20)+Slot`，真机 issue #786 |
| 远端 TSAP | PG=0x101, OP=0x201 | [已确认] 由上式推出（CONNTYPE_PG=0x01/OP=0x02） |
| 本地 TSAP | 0x0100 | [已确认] snap7 micro client 构造器 |
| PDU 长度 | 协商（SETUP_COMM 0xF0），SMART 典型 **240** | [已确认] snap7 协商逻辑；MicroWIN 侧 `MaxPDUSize` 注册表值（commL7 0x2EC1C）+ `sps7_max_PDU_size is set to: %d`（s7otbxsx 0x83550/0x475A0）、`Invalid PDU-Size in Registry, max_pdu_size=%d`（0x45464） |
| 下载域 | ASCII **"P_PROGRAM"**（9 字节）；S7DOS 内部亦见 "P_PROGRAMM" | commL7 0x2E92C **[已确认]**；s7otbxdx 0x7F098/0x7F304；snap7 0x28/0x29 参数段 `...09 P_PROGRAM` 一致 |
| S7 功能码 | RUN(热)=0x28 `28 00 00 00 00 00 00 FD 00 00 09`+P_PROGRAM；RUN(冷)=0x28 `...FD 00 02 43 20 09`+P_PROGRAM；STOP=0x29 `29 00 00 00 00 00 09`+P_PROGRAM | [已确认] snap7 micro client opPlcStop/Hot/ColdStart；commL7 "Go To Run %s"/"Go To Stop %s"（0x2EE98/0x2EECC）语义对应 |
| 块传输 | 下载 0x1A/0x1B/0x1C；上传 0x1D/0x1E/0x1F；块列表 gr=0x43；SZL gr=0x44；时钟 gr=0x47 | [已确认] snap7 常量；commL7 "Upload Begin/Segment/End request/response"（0x2F0CC–0x2F140）、"Load Segment (Master/Master)/(Master/Slave) request/response"（0x2EF84–0x2F064）、"Insert Block"/"RTE Insert Block"/"Delete Block"（0x2F154–0x2F1D4）语义一一对应 |
| 块目录 | dir1=块计数，dir2=块号+位置+状态，dir3=类型+长度+版本+属性 | [已确认] ICommCompassL7 GetBlockTimeStampsW + sCOMMCOMPASS_DIR2_DATA/DIR3_DATA 字段（§5）；commL7 打印 "Block %d  Mode = %X  Status = %X  Language = %02X ... for OB/DB/SDB/FC/SFC/FB/SFB blocks"（0x2F875–0x2F920） |
| 连接模型 | 多连接池（数据手册 8），**PG 通道互斥**（同连接类型抢占）；`s7ie_SetOpenTCPConnections`/`Global\SetOpenTCPConnections`（s7otbxsx 0x4BE38/0x4BE50）控制并发 | [已确认] 社区 issue #765 + 二进制常量 |
| 保活 | `CKeepAliveThread (0x%X) waiting... Address = %d, timeout = %d`（tcpipl4 0x163A9） | [已确认] 字符串；超时值=注册表 TCPIPRCV/TCPIPUpDown |

### 4.2 eCOMMCOMPASS 枚举（commL7.dll 0x21F78–0x42317 + tcpipl4 0x21F78–0x23BFC 的 MIDL 串全量）

**eCOMMCOMPASS_NETWORK_TYPE**：INVALID / PPI / TCPIP
**eCOMMCOMPASS_DEVICE_TYPES**：NONE, PPI_CABLE, MODEM, MPICARD, 802_CABLE, MPI_CABLE, MPI_TELE, EM_241, CELL_PHONE, RADIO_MODEM, SERIAL, TCPIP, SMART_CABLE, SMART_USB, SMART_MODEM, SMART_RADIO, TELE_IE
**eCOMMCOMPASS_PROTOCOLS**：NONE_SELECTED, PPI, DPT, H1, ADV_PPI
**eCOMMCOMPASS_BAUDRATES**：NONE, 9_6K, 9_6K_B, 19_2K, 38_4K, 45_45K, 57_6K, 93_75K, 115_2K, 187_5K, 500K, 750K, 1_5M, 3M, 6M, 12M
**eCOMMCOMPASS_OPMODES**：STOP, RUN（COM_GetOpMode/SetOpMode 单字节；**1/2 具体值待真机核实**，与 0x04/0x08 对照）
**eCOMMCOMPASS_BLOCK_TYPES**：ALL, AREA1, OB, DB, SDB, CSR, CERT, USER_WEB
**eCOMMCOMPASS_BLOCK_STATUS**：ACTIVE, PASSIVE, MC, INVALID
**eCOMMCOMPASS_BLOCK_LOCATION**：INVALID, MC, EPROM, OS
**eCOMMCOMPASS_MEM_AREAS**：SD, SW, SM, AI, AQ, C, T, HC, I, Q, M, V
**eCOMMCOMPASS_MEM_TYPE_CODE**：BOOL, BYTE, CHAR, WORD, INT, DWORD, DINT, REAL, C, T, HC
**eCOMMCOMPASS_ADDRESSING_MODE**：DIRECT_ADDRESS, ADDRESS_OF, INDIRECT_ADDRESS, INVALID_MODE
**eCOMMCOMPASS_STATION_TYPES**：SLAVE, MASTER_WAITING, MASTER, INVALID
**eCOMMCOMPASS_BASE_PLC_TYPES**：210, 212, 214, 215, 216, 221, 222, 224, 226, 802, TD200, UNKNOWN, NOT_PRESENT, TD100
**eCOMMCOMPASS_DIR_PGM_LANG**：INVALID, STMT_LST, LADDER, SDB, DB, S7_STL, S7_LAD, S7_FBD, IEC_LD, IEC_FBD
**eCOMMCOMPASS_DIR3_SYS_VERSION**：STD, EXT；**eCOMMCOMPASS_DIR3_ATTRIBUTE**：USER_BLOCK, STD_BLOCK
**eCOMMCOMPASS_RESTART_COMMANDS**：COLD, WARM, HOT；**eCOMMCOMPASS_FACTORY_RESET_COMMANDS**：RETAIN_IP_ADDRESS, DO_NOT_RETAIN_IP_ADDRESS
**eCOMMCOMPASS_DST_SELECTIONS**：DISABLED, EU00…EU12, US, AUS, NZ, RELATIVE, ABSOLUTE
**eCOMMCOMPASS_MOTION_AXIS_TYPES**：HEARTBEAT, COMMAND, …
**eCOMMCOMPASS_ALARM_LOG**：CONNECTED, DISCONNECTED, NORNAL_ALARM（原文拼写）
**eCOMMCOMPASS_EVENT_LOG_CODES**（13）：NO_EVENT, POWER_UP, TRANSITION_TO_RUN, TRANSITION_TO_STOP, WARM_RESTART, POWER_DOWN, RUN_INHIBIT, RESET_TO_FACTORY, ALARM_EVENT, MODECHG_WEBSERVER, MODECHG_CERTIFICATE, FATAL_ERROR
**eCOMMCOMPASS_EVENT_LOG_REASONS**（26）：UNKNOWN, POWER_ON_ACTION, COMMUNICATION, PROGRAM_EXEC, SCAN_CNT_LIMIT, MC_INSERTED, MISSING_DEVICE, DEVICE_PARAM, FW_UPDATE, BROWNOUT, SB_SM_BOARD_FAIL, WATCHDOG, START_APPWEB_OK, START_APPWEB_OK_WITH_MINOR_CERT_ERR, START_APPWEB_FAIL_WITH_CRITICAL_CERT_ERR, START_APPWEB_FAIL_WITH_INTERNAL_ERR, STOP_APPWEB, START_OSSSERVER_OK, START_OSSSERVER_FAIL_INTERNAL_ERR, STOP_OSSSERVER, REISSUE_CERT_TIME_EXPIRED, REISSUE_CERT_IP_NOT_IN_SAN, REISSUE_CERT_TIME_EXP_IP_NOT_IN_SAN, LOAD_USER_WEB_RESOURCE_SUCCESS, CHECK_USER_WEB_RESOURCE_SIZE_FAILURE, CHECK_USER_WEB_RESOURCE_INFO_FAILURE, COPY_USER_WEB_RESOURCE_TO_FS_FAILURE

**eCOMMCOMPASS_ERRORS**（commL8.dll 0x24108–0x251xx，88 项，摘选）：NONE, INVALIDCONFIG, PDU_TOO_LARGE, RECEIVE_ERROR, TIMEOUT, PORT_INUSE, NOTOPEN, AP_INVALID, INVALID_REQUEST, NOTCLOSED, TRANSMIT_ERROR, VERIFY_CHECKSUM, VERIFY_CRC, INVALID_IP_ADDRESS, SCAN_COUNT, ALREADY_CONNECTED, AREA_TYPE_MISMATCH, OUT_MEMORY, EEPROM, NOT_CONNECTED, LOST_CONNECTION, LOST_ALL_CONNECTIONS, FAIL_SMART_CONFIG, NO_USB_DEVICE_FOUND, NO_CREATE_USB_DEVICE, INVALID_BAUD_RATE …（完整清单见 r3_hits.json / commL_hits_view.txt）

**sCOMMCOMPASS_TIMEOUTS**（38 项，commL7 0x3F71F–0x3FE3C）：RECEIVE_MASTER_TIMEOUT, RCV_PPI_SERIAL_CHAR_DELAY, SND_PPI_SERIAL_TIMEOUT, PPI_SERIAL_QUIET, RCV/SND_PPI_MODEM_CHAR_DELAY, RCV/SND_PPI_RADIO_CHAR_DELAY, LIFELIST_RADIO_10/11_BIT_CHAR_DELAY, LIFELIST_PPI_SERIAL/MODEM_CHAR_DELAY, LIFELIST_10BIT_MODEM_CHAR_DELAY, MODEM_10_BIT_QUIET/SLOT, MODEM_CONNECT/CALLBACK/DISCONNECT/INITIAL_INFO/INFORMATION_TIMEOUT, RCV_S7DOS_TIMEOUT, RCV_S7DOS_SHORT_TIMEOUT, SND_S7DOS_TIMEOUT, LIFELIST_S7DOS_VXD_TIMEOUT, LIFELIST_S7DOS_ABORT, LIFELIST_S7DOS_TIMEOUT, RCV_SERIAL_TIMEOUT/FIND/SAVE/PIN, **RCV_TCPIP_TIMEOUT, LIFELIST_TCPIP_TIMEOUT, UP_DOWN_TCPIP_TIMEOUT**, RCV/SND/SNP_SC_TIMEOUT, RCV_SC_SHORT_TIMEOUT, SC_KA_TIMEOUT, RCV/SND_SC_USB_TIMEOUT, RCV_SC_USB_SHORT_TIMEOUT, RCV/SND/SNP_SC_MODEM_TIMEOUT, RCV_SC_MODEM_SHORT_TIMEOUT, RCV/SND/SNP_SC_RADIO_TIMEOUT, RCV_SC_RADIO_SHORT_TIMEOUT
**sCOMMCOMPASS_RETRIES**：PPI_MASTER_RETRY, S7DOS_MASTER_RETRY, MM_ADVPPI_MASTER_RETRY, SMART_MASTER_RETRY, ETHERNET_MASTER_RETRY, PPI_SERIAL_OVERRUN_RETRY, SC_SNP_RETRIES, SC_AUTOBAUD_RETRIES

### 4.3 注册表键（字符串证据，值待运行时读）

| 键 | 值 | 来源 |
|---|---|---|
| `Software\Siemens\MWSmart` | MaxPDUSize；LastConnectedDevice（调试默认 208.200.1.1） | commL7 0x2EC40/0x2EC1C；C 报告 §2.8 |
| `Software\Siemens\MWSmart\Communications` | Retries: PPIMaster/S7DOSMaster/MMADVPPIMaster/SmartMaster/SerialOverrun/SCAutobaud；Timeouts: PPIRCVCharDelay…TCPIPRCV/TCPIPLL/TCPIPUpDown/SCRCVTimeout…；Smart Data: SoftEntryMode/SmartBaud/SmartSwap | commL7 0x2FF60–0x30344 |
| `SOFTWARE\SIEMENS\SINEC\LogDevices` | ComPort / DeviceID / search_baud（SINEC LogDevice 定义；TCP 设备的 L4DRIVER 亦在此体系） | commL7 0x2EAF4–0x2EB1C；s7onlinx64 LoadDrv（"L4DRIVER = %s, Use GUID ? %s" 0x20D60） |
| `SOFTWARE\Siemens\Shared Tools\S7DOS64` | 64 位 S7DOS 服务配置 | s7onlinx 0xC09C；s7onlinx64 0x1F9F8 |
| `Software\Siemens\MWSmart`（commL8Host 读） | CommCompassHostThreadDelay | commL8Host 0xE300/0xE39C |
| 命名对象 | `S7200CommMutex`（commL7 0x2E998）；`ICommCompassL4IntMutex`（tcpipl4 0x142A0）；`Global\Eprom_Sync`；`S7OTBX_SM0_/MUTEX_/SX_MUTEX_/sm_%08.8X_/ev_%08.8X`；`Global\SetOpenTCPConnections` | 各文件偏移见字符串表 |

### 4.4 S7DOS 内部帧（非 wire 帧！客户端↔S7DOS 服务之间的请求块）

**SPS7_PDU 头（8 字节）[已确认，格式串 s7otbxsx 0x45318]**：
`PROTID(1B) ROSCTR(1B) PDUREF(2B) PARLEN(2B) DATLEN(2B)`
（"PROTOCOL ERROR: Wrong SPS7_PDU: PROTID=%2.2XH, ROSCTR=%2.2XH, PDUREF=%4.4XH, parlen=%d, datlen=%d"）

**L4RB（L4 Request Block）**：`opc`（如 0x0810/0x0811/0x410E 等，见 "Unknown SEND_EOM_DATA ==> 0x0810"、"Unknown RECEIVE_DATA ==> 0x0811/0x410e"）、`user_id`、`cn_id`、`pduref`；
**L7RB（L7 Request Block）**：`service`、`id1`、`id2`（"service = %d, class = %d, id1 = %d" commL7 0x2EE51；"service=0x%x, id2=0x%x"）、`errcls/errcod`（"Retry of BSEND, errcls/errcod=0x%2.2x%2.2x"）。
**L7 服务名**：L7_AA_EINRICHTEN（连接建立）, L7_CLOSE_CONN, L7_READ_SEG, L7_DPT_READ/WRITE（via DSGW / via DRAP）, L7_PMC_MSG_MODE, L7_NET_DIAGNOSE_STOP, L7_PST_CLOSE, OPEN_REQ/CLOSE_REQ/SEND_CONN_REQ/SEND_CONN_EXT_REQ/RECEIVE_DATA/SEND_EOM_DATA/RECEIVE_PDU/RECEIVE_DIAG_RB/FDL_READ_VALUE/FDL_CANCEL_GET_RESULT。
**DSGW（Data Stream Gateway）/RPC7 状态机**：RPC7_IF_BIND/_BIND_PENDING/_UNBIND/_UNBIND_PENDING；rpc_BIND_CNF/rpc_UNBIND_IND/dsgw_CONNECT_CNF/dsgw_DISCONNECT_CNF；"Unknown Segment Id"；FLOWCTRL_STOP；SEGMENTED。
**AG 头**：`ag_bst_header`（AG-Order-Header），`cnv_ag_header_to_pg()` 做 AG↔PG 头转换；块文件内部用 DBF 表（字段 PASSWORD/BLOCKFNAME/BLOCKNAME/CHECKSUM，A1CreateTable 串 s7otbxdx 0x78928–0x7988C）。
**Legitimation（密码会话）**：Legitimation_Create/Find_TABuf/Delete_TABuf/Cleanup_of_chan；"Create Legitimation: channel=%d, password=***"；"SUCCESS: use already existing legitimation"；"No more Legitimations available"；默认密码 Find_default_password。commL7 对应命令 "Legitimize Password %s"/"Release Password %s"（0x2ED78/0x2ED90）+ 7 种密码错误（0x2FB44–0x2FCF8：Password required / Protection error / Password syntax error / Password incorrect / Password already established / Password already released / No password in CPU）。
**S7IE（站管理）PDU 缓冲名**：S7IE_SET_NETWORK_PARAM(_EXT)_req_buf/res_buf、S7IE_GET_IE_PARAM_req/res、S7IE_GET_PB_PARAM_req/res、S7IE_GET_MAC_ADDR_req/res、S7IE_DELETE_PGIP_ADDRESS_req/res、S7IE_SEARCH_AND_SET_PGIP_ADDRESS_req、S7IE_SEARCH_FOR_FREE_IPADDRESS_req/res、S7IE_GET_ADAPTER_INFO_req/res、S7IE_IDENTIFY_req/res、S7IE_IDENTIFY_NAME_req/res、S7IE_IS_REACHABLE_req、S7IE_CHECK_IS_IP_ADDRESS_FREE_req、S7IE_SET_NAME_OF_STATION_req、S7IE_SHOW_LOCATION_req —— 这些是"闪 LED 定位 / 改站名 / 改 IP / IP 搜索"的底层服务 [已确认存在]，wire 编码 [待抓包]。

### 4.5 错误文案表（L4 → 用户，tcpipl4 0x142B8–0x15B50，可作直连库的 errno 映射）

"Communications time-out. Check the port number, network address, baud rate..."、
"The transmitted PDU length is incorrect."、"Invalid header response in response RB!!"（0x16AD4）、
"Upload sequence error."、"The PLC is password protected for the requested command."、
"The link is already legitimized for another user, access is not authorized."、
"The operating mode has not changed."、"The block is in EEPROM." / "The block is not present in the CPU." / "The block is too large for PLC memory."、
"Error: Switch in wrong position"（RUN/STOP 开关，commL7 0x2FAB4）、
"Failed to connect to the current IP address."、
"Error when verifying the checksum (FCS)" / "Error when verifying the CRC."

---

## 5. 结构逆向线索（字段名清单，MIDL/调试串）

| 结构 | 字段（按出现顺序线索） | 来源 |
|---|---|---|
| sCOMMCOMPASS_AP_DATA（访问点/连接参数） | m_eDeviceType (eCOMMCOMPASS_DEVICE_TYPES), m_szDeviceName[?], m_eBaudRate, m_sTimeouts (sCOMMCOMPASS_TIMEOUTS 38 项), m_sRetries (8 项), m_nComPort, m_hMsgFrameWnd, m_bUseSmartBaud | commL7 0x3EFC0–0x400FC |
| sCOMMCOMPASS_NETWORK_INFO | eNetworkType (INVALID/PPI/TCPIP) + 传输参数联合体 | commL7 0x3DBD4–0x3DC80 |
| sCOMMCOMPASS_TCPIP_INFO | m_lDefaultGateway (u32), m_bUseLifeListTimeout (bool), m_sTCPIPInfo (CString) | commL7 0x3DD00–0x3DDCC |
| sCOMMCOMPASS_SMART_DATA | m_bAutoBaud, m_sSmartData | commL7 0x40080–0x400FC |
| sCOMMCOMPASS_DEVICE | m_eStationType, m_bIsS7DOS, m_eLifeListType | commL7 0x40210–0x4035C |
| sCOMMCOMPASS_DEVICE_LIFE_LIST | m_aszDeviceType[], m_nDeviceAddr, m_nDeviceBaudRate（+ 上行结构含 m_eStationType 等） | commL7 0x41FC8–0x42048 |
| sCOMMCOMPASS_CONNECTION_INFO | m_nPDUSize | commL7 0x40133/0x40173 |
| sCOMMCOMPASS_ADDRESS | m_eMemMode (eCOMMCOMPASS_ADDRESSING_MODE) | commL7 0x3E149–0x3E234 |
| sCOMMCOMPASS_MEM_STRUCT（变量读写的元素） | m_lErrorCode（其余成员=地址+类型+值，DataReadWWW/Write 批量数组） | commL7 0x3E110–0x3E133；**完整布局待抓包/OD** |
| sCOMMCOMPASS_DIR2_DATA | m_nBlockNumber, m_eBlockLocation (MC/EPROM/OS), m_eBlockStatus (ACTIVE/PASSIVE/MC) | commL7 0x3E7D8–0x3E92F |
| sCOMMCOMPASS_DIR3_DATA | m_eBlockType, m_lBlockLength（+ sys version/attribute 字段） | commL7 0x3EB7C–0x3ED3C |
| sCOMMCOMPASS_EVENT_LOG | m_eEventCode (13 码), m_nFatalErrorCode（+ 时间戳/原因字段） | commL7 0x40A07–0x41488；**完整布局待真机**（EVENTLOG 命令已接线，见 ENGINE_ONLINE.md） |
| sAlarmEventHistory_tag | m_wDeviceNum, m_wAlarmType, m_tAlarmLog | commL7 0x414D8–0x415BE |
| sCOMMCOMPASS_MC_DATA | m_aszDeviceType, m_aszDeviceVersion, m_lBlockBytesUsed | commL7 0x408EC–0x409D0 |
| sCOMMCOMPASS_PROGRAM_MC_DATA | m_bProgramBlock, m_bDataBlock, m_bSystemBlock | commL7 0x41717–0x41794 |
| sCOMMCOMPASS_DST_STATUS / _SYSTEMTIME | DST_SELECTION + 系统时间 | commL7 0x4059B–0x408EC |
| sCOMMCOMPASS_RME_INFORMATION | （RUN 模式编辑信息，CLoadMgr::Download/Upload 出参） | C 报告 §2.4 |
| sCOMMCOMPASS_ES_DEF | （NonPublic InsertBlock 相关） | commL7 0x41D64 |
| sCOMMCOMPASS_NETWORK_INFO（MW 引擎侧别名 MWNetworkInfo） | 未逆向（注入层用 filler 策略，见 ENGINE_ONLINE.md） | — |

**内存区→S7 协议映射 [已确认，社区+引擎约定]**：I/Q/M/V/HC/T/C；V 区=DB1。
**块域**：P_PROGRAM（程序区，下载/上传/删块域）；块位置 EPROM/OS/MC 对应
S7-200 的固定存储/RAM/存储卡。

---

## 6. s7200.sig 与 Features.dvp 文件格式（本次 hexdump 定案）

### 6.1 s7200.sig（223,838 B）= **S7-200 指令签名表**（非固件签名！）

- 头（0x00）：`01 00 00 00`（version=1）| `d1 02 00 00`（=721，条目/记录数）| `01 00 00 00` | `01 20 01 20` | `14 00 00 00`（=20）| `fb f7 12 00`（=0x12F7FB，≈数据区偏移/大小）
- 内容：序列化条目，每条含助记符名 + 参数名 + 操作数类型字节。实测可见助记符：
  READ_RTC, SET_RTC, XMT, RCV, NETR, NETW, GET_ADDR, SET_ADDR,
  ==B/<>=B/>=B/<=B, ==I/<>=I/>=I/<=I, ==D/…, ==R/…, S_RTR, S_RTI, SRTR, SRTI,
  =ALT/ALTH/ALTF/ALTG/ALTP/ALTPW/ALTPU/ALTPV, LPF/LPFI/LPFX, IN/ISH/ISL/OSH/OSL,
  BIT, NOP, AND, ORU, OUT, NOT…；参数名 ENO/OUT/PORT/TBL/ADDR/MASK/GIP/SIP/GIP_ADDR/SIP_ADDR/GET_ERROR/Coef/COMMAND/MODE/STOP/TRUNC…
- 用途：SigCompass（signature.dll）在 STL/LAD 编译与块组装校验时按"助记符+参数+类型"
  核对指令合法性（"GetSimaticMnemonic/GetOpCode/GetParameterCount/GetStackUsage"）。
  → 与固件签名/加密无关（块加密是 CPU 侧，见 hev0x/S7200-toolkit-decrypt 线索）。
  解析器可按"长度前缀 + 名称 + 类型字节"写（条目边界需按 721 条对齐微调）[推断，解析器未写]。

### 6.2 Features.dvp（56,768 B）= **设备能力/限制数据库**

- 头（0x00）：`01 00 00 00`（version=1）| `84 00 00 00`（=132 条目）| `00 00 00 00` | `d4 00 00 00`（=212 字节/条）
- 每条 212 B：`CPU ST60        `（16B 设备名 ASCII）| `V`+`01 00`（版本）| 特性字（0x22/0x43/0xFC03…）| I/O 计数（0x0E,0x0E,0x30,0x28…）| 0x06DB（1755，疑似 I/O 点数/字长）| 内存限制 | 大位图（0x3FFF/0x1FFF/0x007D/0x007F… + 0xFFFB 0x740F 0x1037 0x007F 等 I/O 点位掩码）| 尾部 0x00C8 0x00D4（子偏移）
- 实测条目：CPU ST60 / CPU CR40 / CPU ST40…（V2.8 目录 132 条，覆盖 SR/ST/CR 全系 + 模块）
- 用途：IDeviceFeatures（device.dll 190 个 IsXxxSupported/GetTotalXxx）的离线数据源。
  → 可做"某 CPU 型号支持哪些在线功能"的纯离线查询（无需 CPU）。

---

## 7. 点火链（"独立进程如何拿到 IComm"——两条路径）

### 7.1 引擎侧事实（storeretrieveverify.dll 导出签名，本次反汇编/符号确认）

- `PRJ_GetCommEntryPoint@MWRetrieve: long __thiscall (CString&)`（mangled @0x1245F1）
  → 返回 **CString 字符串 = L4 模块名**（"tcpipl4"/"smartusbl4"/"smartcablel4" 一类）。
  解析表就在 commL7/commL8 的 0x2DA00–0x2DCA0：
  `CLSID_TCPIP→tcpipl4.dll`、`CLSID_TCPIP64→tcpip64l4.dll`、
  `CLSID_SmartUSB→smartusbl4.dll`、`CLSID_SmartCable→smartcablel4.dll`、
  `CLSID_CommCompassL7→commL7.dll`、`CLSID_CommCompass→comm.dll`（字符串存在，
  文件未见 → 可能是历史名或运行时拼装 [推断]）、
  `CLSID_BlockCompass→blockbuilder.dll`、`CLSID_DeviceCompassFeature(s)→device.dll`、
  `CLSID_SigCompass*→signature.dll`。
- `PRJ_SetCommEntryPoint@MWStore: long (const CString&)`（0x126159）；
  `MWProject::Get/SetCommEntryPoint(MWString)`、`MWPrjDataMgr` 同名对。
- `PRJ_GetCommCompassHostGUID@MWStore: long (GUID&)`（0x1245BB）→ 返回
  **commL8Host 的类 CLSID**（运行时值；静态提取见 7.3）。
- 连接参数：`PRJ_Get/SetCommRemoteAddress(MWNetworkInfo&)`、
  `COM_Get/SetAccessPoint(COMPASS_AP_DATA&)`、`SYS_GetPlcCommData(PLC_COMM_DATA&)`。

### 7.2 路径 A：in-proc COM（同进程内起 L8/L7/L4）

1. `LoadLibrary("...\Communications\commL8.dll")` → `DllGetClassObject`
   （或 CoCreateInstance 对应 CLSID，需注册）。
2. 得到 `ICommCompass`（L8 对象 CCommCompass）。commL8 内部按 CPU 家族
   `LoadLibrary("%s\commL8%x.dll")`（0x156D8–0x15728：comm409/407/40a/40c/410/804/412 ——
   这些旧名对应 commL8404/409/804 家族 [推断]），再创建 L7（commL7.dll 的
   CLSID_CommCompassL7）与 L4（按 PRJ_GetCommEntryPoint 的字符串选 tcpipl4/smartusbl4/…）。
3. L4 的 `SetCOMMCompassL7(pCommL7)` 建立 L7↔L4 回环；`SCP_Open` 起 SINEC 通道
   （消息窗口 + 保活线程）→ S7ONLINX SCP_* → S7DOS。
- 优点：无跨进程；缺点：必须在 32 位进程里（MWSmart 是 x86），且 S7DOS 命名
  互斥（S7200CommMutex/ICommCompassL4IntMutex）会与正在运行的 MicroWIN 互斥。

### 7.3 路径 B：commL8Host.exe 独立 COM 宿主（官方多进程方案）

- 文件：`Communications\commL8Host.exe`（ATL LocalServer，"Compass Communications Host Class"）。
- **ProgID：`CommCompassHost.CommCompassHost`**（0xE858）
- **AppID GUID：{77243F98-3E23-40dc-9457-ECFDD7EBB1B6}**（0xE938，后随 "APPID"/
  "CommCompassHost"/"CommCompassL8Host.EXE"）
- 类别（CATID，所有 Compass 类共享）：{18F8D6F3-0485-4b00-945F-7A9CA295632B}
- **注册是运行时的**（C 报告已证 HKCR 无静态注册）：进程内
  `RegisterTypeLibForUser`（"MicroSystems - CommCompassHostLib Type Library"，
  类 "MicroSystems - CommCompassHost Class"，接口 "MicroSystems - ICommCompassHost Interface"，
  typelib 名 CommCompassHostLib/CommCompassHostW/ICommCompassHostd @0x19870–0x19952）
  + `CoRegisterClassObject`（ATL 资源模板 "NoRemove CLSID/ForceRemove %CLSID%/
  'TypeLib'=%LIBID%/'Implemented Categories'={CATID}" @0x17E70–0x18134）。
- 客户端点火序列 [推断，基于 ATL LocalServer 标准行为 + 字符串]：
  `PRJ_GetCommCompassHostGUID(&clsid)` → `CoCreateInstance(clsid, NULL,
  CLSCTX_LOCAL_SERVER, IID_ICommCompassHost, &pHost)` → COM 自动拉起
  commL8Host.exe（读 `Software\Siemens\MWSmart\CommCompassHostThreadDelay`）→
  宿主起 `CCommCompassHostThrd`（主 STA 线程）+ 每个访问点一个
  `CCommCompassAptThrd`（Access Point 线程，refcount 管理）→
  LoadLibrary("...\commL8%x.dll") 建 L8/L7/L4。
- 二进制 GUID 静态提取（v4+代码引用启发式，**赋值推断，建议运行时
  PRJ_GetCommCompassHostGUID 一次性取真值**）：

  | 对象 | 候选 GUID | 依据 |
  |---|---|---|
  | CLSID_CommCompassL7 | **{9851F581-DD10-4950-8EDE-09626C70E656}** | commL7 rdata rva 0x30580，被类注册函数引用（0xE7FF push 该址 → 注册调用） |
  | LIBID_CommCompassL7Lib | {1245B29B-225C-4A1B-9D13-EF7BCC2D2FF1} | commL7 rva 0x30570，同函数中 GUID 拷贝（RegisterTypeLib 参数位） |
  | ICommCompassL7 / ICommCompassL7NonPublic / INotifyCompass（顺序未定） | {A3EFE34E-BB3E-4ED4-BFCA-5B2F8DB6AF4C} / {E5D9B940-5E36-4984-8DDF-9F41982FE36F} / {82BAA541-0EF2-4C9A-BBE1-E8918042E384} | commL7 rva 0x305A0/0x305C0/0x305E0，在"接口枚举"函数里被 `movups xmm0`（16B 整块加载） |
  | 共享 IID（INotifyCompass，两 DLL 都用） | {02B293B6-5510-46DC-87E4-1BCC2DD88347} | commL7 rva 0x30540 且 tcpipl4 rva 0x15470 同值 |
  | CLSID_TCPIP（候选） | {B0168DA1-45BE-4893-8390-56158950F9DE} | tcpipl4 rva 0x18000，tcpipl4 独有+代码引用 |
  | AppID_CommCompassHost | {77243F98-3E23-40dc-9457-ECFDD7EBB1B6} | commL8Host 资源串（确定值） |

  ⚠ CLSID/IID 的最终归属（哪个是哪个接口）**待运行时核实**（OleView 或
  PRJ_GetCommCompassHostGUID + DumpInterface 一次即可）——但这不影响直连路线。

---

## 8. 分层可执行计划（直连 = 纯 Python，无 MWSmart、无 COM、无 S7DOS）

### L4 传输 [已确认]
- TCP → `ip:102`。COTP（ISO 8073 over TCP）：CR（TPDT，`03 00 xx xx 11 00 00`+
  src/dst TSAP 各 6B：dst `10 02 00 00 xx 01`，xx=ConnType，rack0/slot1→
  PG=0x101/OP=0x201；src `10 02 00 xx 00 00`+任意 id 如 0x0100）→ DT 数据帧。
- PDU 长度：CR 里请求 240；CPU 回 AC/DT 后按 SETUP_COMM（0xF0）协商，
  回退 240（snap7 逻辑）。SZL 0x0131 可回读 MaxPduLengt/MaxConnections。
- 单 PG 长连接复用（PG 通道互斥）；socket 超时取 RCV_TCPIP_TIMEOUT 语义
  （值在注册表，默认 ~10s，直连库自定 5–15s）。

### L7 应用 [已确认 80%，剩余项标注]
按 S7 PDU（`32 01 <ParLen16> <DataLen16> <seq:8> <R/P:8> 00 <FCT:8> <params> <data>`）：

| 功能 | 参数 | 状态 |
|---|---|---|
| 读/写变量（I/Q/M/V=T/C 区；V=DB1） | Read/WriteArea gr=0x04/0x05；datatype 0x01 BOOL…0x08 REAL | [已确认] snap7+社区 |
| RUN/STOP | 0x28 热/冷、0x29（§4.1 字节序列） | [已确认] snap7；commL7 Go To Run/Stop 对应 |
| SZL | gr=0x44：0x0011 订货/固件、0x001C CPU 信息、0x0131 CP/PDU/连接数、0x0232 保护、0x0424 状态（Data[7]：0x08=RUN/0x04=STOP） | [已确认] snap7 micro client |
| 时钟 | gr=0x47 读 0x01/写 0x02，7B BCD | [已确认] snap7 |
| 块目录 | gr=0x43：ListAll 0x01 / ListBoT 0x02 / BlkInfo 0x03 | [已确认] snap7；S7-200 条目布局 [待抓包] |
| 块上传/下载 | 0x1D/0x1E/0x1F、0x1A/0x1B/0x1C；域 P_PROGRAM | [已确认] snap7 框架；**S7-200 SMART 块映像布局（AWL 编码/compact 头/校验）待真机** |
| 删块/压缩/RAM→ROM | SFun_Delete=0x42、Compress、CopyRamToRom（_MSZL） | [已确认] snap7 有实现 |
| 保护/会话密码 | SZL 0x0232 读；安全组功能 set/clear | [已确认] snap7 |
| **事件日志** | commL7 GetEventLog → sCOMMCOMPASS_EVENT_LOG（13 码 26 原因，§4.2） | [存在已确认/编码待抓包] S7 协议侧无 snap7 实现 → 抓 MicroWIN"事件"读包，或探测 SZL 0x040C/0x00A0 |
| **强制 Force** | commL7 ForceWW/UnForce/UnForceAll | [存在已确认/CPU 支持待真机] S7-200 SMART 的 S7 协议侧 force 无公开实现；抓 MicroWIN"强制"操作包验证 |
| **RTE（RUN 模式在线编辑）** | commL7 "RTE Insert Block" + RME_INFORMATION | [存在已确认/编码待抓包] |
| 站管理（Identify 闪 LED/改 IP/站名/IP 搜索） | S7IE_* 服务（§4.4） | [存在已确认/编码待抓包] 低优先 |
| DST/扫描时间/MC 卡/固件升级 | GetDSTStatus/SetDSTStatus、GetScanTimes、GetMCSize/ProgramMC、UpdateFW | [存在已确认/编码待抓包] 低优先 |
| USB/PPI 电缆路径 | smartusbl4（HID）/smartcablel4（PPI over 串口，ADV_PPI） | 不在直连以太网范围 [跳过] |

### 落地顺序（建议）
1. **P0**（1 天）：COTP/S7 PDU 裸客户端（python socket）实现 读/写变量 +
   SZL 0x0424 状态 + 0x28/0x29 RUN/STOP + 0x47 时钟 —— 与现有 snap7 工具互为对照，
   零新增风险。
2. **P1**（2–3 天，需真机+Wireshark）：块上传 `0x1D/0x1E/0x1F` 解析 S7-200 块映像
   （对照 smart_export_all 的 AWL 文本定结构）；事件日志探测（先 SZL 0x040C/0x00A0，
   不通再抓 MicroWIN 包）；force 探测。
3. **P2**：块下载 `0x1A/0x1B/0x1C`（应急刷块，experimental 标记）+ 删块/压缩。
4. 任何一步的抓包对照物 = MicroWIN 同一操作（见 §9）。

---

## 9. 真机验证步骤（Wireshark 对照法）

前置：一台 S7-200 SMART（配好 IP，如 192.168.0.10），PC 直连或同网段；
Wireshark 过滤 `tcp.port == 102`（+ 需要时 `cotp`）。

| # | MicroWIN 操作（先做一遍留包） | 抓包对照点 | 验证目标 |
|---|---|---|---|
| 1 | 打开工程 → 连接 CPU（状态栏显示已连接） | 首包 COTP CR（看 dst TSAP 0x101/0x201、PDU 请求长度）、SETUP_COMM 0xF0 | 端口 102、TSAP、PDU 240 [已确认→实测复核] |
| 2 | 在线 → 状态表 加 VW100 并启用连续监视 | ReadArea PDU 的 area/len 字段（V→DB1 偏移） | V=DB1 映射、批量读格式 |
| 3 | 在线 → RUN/STOP CPU | 0x29/0x28 参数段逐字节（对照 §4.1） | RUN/STOP 序列定案 |
| 4 | 在线 → 时钟 读取/设置 | gr=0x47 PDU | 时钟格式 |
| 5 | 在线 → 事件（读事件缓冲） | 该操作走的 PDU（若走 SZL 记 ID/Index；若走专用功能记 FCT+参数） | 事件日志 wire 编码（commL7 GetEventLog 对应） |
| 6 | 强制 某 I 点（在线→强制） | Force PDU（FCT/参数）或"不支持"错误响应 | Force 是否 CPU 支持 + 编码 |
| 7 | 下载 全部（小工程，STOP 态） | 0x1A/0x1B/0x1C 序列：域名 P_PROGRAM、块头、分段、校验和 | 下载块映像布局 |
| 8 | 上传 全部 | 0x1D/0x1E/0x1F：块映像字节（与 smart_export_all 的 AWL 对照逆结构） | 上传块映像布局（最高价值） |
| 9 | 设备 → 属性（CPU 信息/订货号） | SZL 0x0011/0x001C/0x0131/0x0232/0x0424 的实际 ID/Index 与数据布局 | SZL 表定案（含 S7-200 SMART 支持的 SZL 全集探测记录） |
| 10 | （可选）RUN 态改程序（RTE） | "RTE Insert Block" 序列 | RME/RTE 编码（低优先） |
| 11 | （可选）站名/IP 设置向导 | S7IE_SET_IE_PARAM / SET_NAME_OF_STATION 对应 PDU | 站管理编码（低优先） |

产出：每行一张"MicroWIN 包 vs 我们裸 PDU"的逐字节对照表，回填本文档 §8 的
[待抓包] 项为 [已确认]。注意：抓包期间不要并发跑 MCP 的 snap7 连接
（PG 通道互斥会干扰）；用 OP 连接（set_connection_type(2)）抓数据面、
PG 连接抓控制面可分开做。

---

## 10. 风险与注意

1. **PG 通道独占**：MicroWIN/MCP 的 PG 连接与我们的 PG 连接互斥；实现单连接
   复用 + 重连逻辑（python-snap7 issue #765 行为）。
2. **python-snap7 坑**（A 报告 §4.7 全适用）：get_cpu_state 是 stub、force_bit
   非真强制、字符串 latin-1/GBK、AIW 偏移。
3. **S7-200 SMART ≠ S7-200 经典**：经典 S7-200 的 PPI/ADV_PPI 串口协议与本文
   S7DOS 内部帧（SPS7_PDU/L4RB/DSGW）**不是** SMART 以太网的 wire 协议；
   SMART 以太网 = 标准 S7（snap7 已证）。别把 S7DOS 内部帧当成 wire 帧去发。
4. **块加密**：部分固件的块可带加密（S7200-toolkit-decrypt 线索）；上传回来的
   块若解不开，走引擎路线（smart_export_all）兜底。
5. **S7DOS 组件版本漂移**：s7onlinx64.dll 来自 Simatic OAM（共享组件），
   可能随其他西门子产品升级变化；本文所有 S7DOS 内部细节只用于理解
   MicroWIN 行为，直连协议不依赖它。
6. **注册表 SINEC LogDevice**：本机为空（未留下 MicroWIN 通信配置）；
   直连路线完全不需要它。

---

## 附：本次逆向产出文件（C:\Users\ASUS\AppData\Local\Temp\smart200_research\）

- r1_exports.json / r1_exports.txt —— comm 栈 + 根目录全部 PE 导出/导入
- r2_legacy.json —— s7onlinx/s7epatdx/s7otbxdx/s7epaapi 导出全表
- r3_hits.json + commL_hits_view.txt —— commL7/L8/L8Host/device/blockbuilder/tcpipl4/smartusbl4 关键词命中（含偏移）
- r5_hits.json + r5_view2.txt —— s7elonls64/s7otbxsx/s7eptcpa/s7eiepga/s7epmpia/s7oniemmx/s7owpstx/s7epromapi/S7O.CommonServices 命中
- s7onlinx_all.txt / s7onlinx64_strings.txt / sig_strings.txt —— 全量字符串
- port_scan.txt —— 端口常量扫描（结论：无字符串级端口常量）
- r6c_res.py / r8_clsid.py / r9_dllgco.py —— CLSID/GUID 提取脚本与中间结果
- 前序：A_web_research.md、B_engine_exports.md、C_binary_recon.md、D_gap_analysis.md、
  curated.json、string_hits.json、pe_scan.json、exports_final.txt
