# -*- coding: utf-8 -*-
r"""★ 本地补丁模块（2026-10-27）：绕开 frida，直接读 HID 输入报告。

为什么需要它：
  上游的按键映射是在 WUDFHost.exe 里钩 `ntdll!NtDeviceIoControlFile` + IOCTL
  0x80018483 来旁路 HID 报告。但在这台机器（Windows 11 + 这支 Google「A3」遥控器）
  上，自检显示「该宿主上『遥控器读』0 次」—— 那个 IOCTL 从来没被调用过，
  说明这个蓝牙驱动的读路径和上游假设的不一样，整条 frida 旁路是空的。

  而用常规的 ReadFile 打开 HID 集合（`\\?\HID#...`，Consumer 集合）**能正常收到
  `01 03 00` 这样的三字节报告**——这是另一条独立项目（遥控器按键桥）实测跑通的路径。

  所以这里把它做成一个可选后端：能打开就直接读，打不开再退回 frida，
  frida 也没有就退化成"只能语音、没有按键"。

    · 好处：不需要提权、不往系统进程注入、不注册 frida-* 临时服务、不会再弹 UAC
    · 代价：拿不到"清位"能力（把 usage 写 0 抹掉原生动作）。这支遥控器的
      0x03~0x0F 在 Windows 上没有对应的原生动作，所以没有双发问题。
"""
from __future__ import annotations

import ctypes
import threading
from ctypes import wintypes

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
setupapi = ctypes.WinDLL("setupapi", use_last_error=True)
hid = ctypes.WinDLL("hid", use_last_error=True)

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE = ctypes.c_void_p(-1).value


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]


class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("InterfaceClassGuid", GUID),
                ("Flags", wintypes.DWORD), ("Reserved", ctypes.c_void_p)]


class HIDD_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Size", wintypes.ULONG), ("VendorID", wintypes.USHORT),
                ("ProductID", wintypes.USHORT), ("VersionNumber", wintypes.USHORT)]


class HIDP_CAPS(ctypes.Structure):
    _fields_ = [("Usage", wintypes.USHORT), ("UsagePage", wintypes.USHORT),
                ("InputReportByteLength", wintypes.USHORT),
                ("OutputReportByteLength", wintypes.USHORT),
                ("FeatureReportByteLength", wintypes.USHORT),
                ("Reserved", wintypes.USHORT * 17),
                ("NumberLinkCollectionNodes", wintypes.USHORT),
                ("NumberInputButtonCaps", wintypes.USHORT),
                ("NumberInputValueCaps", wintypes.USHORT),
                ("NumberInputDataIndices", wintypes.USHORT),
                ("NumberOutputButtonCaps", wintypes.USHORT),
                ("NumberOutputValueCaps", wintypes.USHORT),
                ("NumberOutputDataIndices", wintypes.USHORT),
                ("NumberFeatureButtonCaps", wintypes.USHORT),
                ("NumberFeatureValueCaps", wintypes.USHORT),
                ("NumberFeatureDataIndices", wintypes.USHORT)]


HID_GUID = GUID(0x4D1E55B2, 0xF16F, 0x11CF,
                (ctypes.c_ubyte * 8)(0x88, 0xCB, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30))

kernel32.CreateFileW.restype = ctypes.c_void_p
kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                 ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                 ctypes.c_void_p]
kernel32.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
                              ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]

# ⚠ 这几个 restype/argtypes 不声明就会"枚举到 0 个设备"：64 位下 HANDLE 会被截成
#   int32，SetupDiEnumDeviceInterfaces 拿到的句柄直接是坏的，而且不报错。
setupapi.SetupDiGetClassDevsW.restype = ctypes.c_void_p
setupapi.SetupDiGetClassDevsW.argtypes = [ctypes.POINTER(GUID), ctypes.c_void_p,
                                          ctypes.c_void_p, wintypes.DWORD]
setupapi.SetupDiEnumDeviceInterfaces.restype = wintypes.BOOL
setupapi.SetupDiEnumDeviceInterfaces.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                                 ctypes.POINTER(GUID), wintypes.DWORD,
                                                 ctypes.POINTER(SP_DEVICE_INTERFACE_DATA)]
setupapi.SetupDiGetDeviceInterfaceDetailW.restype = wintypes.BOOL
setupapi.SetupDiGetDeviceInterfaceDetailW.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(SP_DEVICE_INTERFACE_DATA), ctypes.c_void_p,
    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
setupapi.SetupDiDestroyDeviceInfoList.argtypes = [ctypes.c_void_p]

PAGE_CONSUMER = 0x0C


def open_collections(vid=0x18D1, pid=0x9450, pages=None):
    """枚举这台遥控器的 HID 集合，返回 [(usage_page, handle, report_len)]。

    ★ 2026-10-27 改：默认 `pages=None` = **打开所有 usage page**。
      原来只开 Consumer(0x0C)，把厂商自定义那个集合（COL02）整个丢了 ——
      而静音键在这个遥控器上就是「按了没有任何报文被解析」，最可能就是落在
      另一个集合里。只开一个集合等于自己把眼睛蒙上一半。

    每个 usage page 只要一个句柄（同一个 page 的重复集合没有必要各开一个）。
    """
    pages = None if pages is None else set(pages)
    found = []
    hidset = setupapi.SetupDiGetClassDevsW(ctypes.byref(HID_GUID), None, None, 0x12)  # PRESENT|DEVICEINTERFACE
    if hidset == INVALID_HANDLE or hidset is None:
        return found
    did = SP_DEVICE_INTERFACE_DATA()
    did.cbSize = ctypes.sizeof(SP_DEVICE_INTERFACE_DATA)
    index = 0
    try:
        while True:
            if not setupapi.SetupDiEnumDeviceInterfaces(hidset, None, ctypes.byref(HID_GUID),
                                                        index, ctypes.byref(did)):
                break
            index += 1
            need = wintypes.DWORD(0)
            setupapi.SetupDiGetDeviceInterfaceDetailW(hidset, ctypes.byref(did), None, 0,
                                                      ctypes.byref(need), None)
            if not need.value:
                continue
            buf = ctypes.create_string_buffer(need.value)
            ctypes.memset(buf, 0, need.value)
            ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD))[0] = 8   # cbSize（64 位固定 8）
            if not setupapi.SetupDiGetDeviceInterfaceDetailW(hidset, ctypes.byref(did), buf,
                                                             need.value, ctypes.byref(need), None):
                continue
            path = ctypes.wstring_at(ctypes.addressof(buf) + 4)
            handle = kernel32.CreateFileW(path, GENERIC_READ,
                                          FILE_SHARE_READ | FILE_SHARE_WRITE,
                                          None, OPEN_EXISTING, 0, None)
            if handle is None or handle == INVALID_HANDLE:
                continue
            attr = HIDD_ATTRIBUTES()
            attr.Size = ctypes.sizeof(HIDD_ATTRIBUTES)
            if not hid.HidD_GetAttributes(ctypes.c_void_p(handle), ctypes.byref(attr)) \
                    or attr.VendorID != vid or attr.ProductID != pid:
                kernel32.CloseHandle(ctypes.c_void_p(handle))
                continue
            preparsed = ctypes.c_void_p()
            if not hid.HidD_GetPreparsedData(ctypes.c_void_p(handle), ctypes.byref(preparsed)):
                kernel32.CloseHandle(ctypes.c_void_p(handle))
                continue
            caps = HIDP_CAPS()
            hid.HidP_GetCaps(preparsed, ctypes.byref(caps))
            hid.HidD_FreePreparsedData(preparsed)
            if (pages is None or caps.UsagePage in pages) \
                    and caps.UsagePage not in [p for p, _, _ in found]:
                found.append((caps.UsagePage, handle, caps.InputReportByteLength))
            else:
                kernel32.CloseHandle(ctypes.c_void_p(handle))
    finally:
        try:
            setupapi.SetupDiDestroyDeviceInfoList(hidset)
        except Exception:
            pass
    return found


def close_collections(cols):
    for _, handle, _ in cols or []:
        try:
            kernel32.CloseHandle(ctypes.c_void_p(handle))
        except Exception:
            pass


def read_loop(handle, on_report, stop_event, buffer_len=64):
    """阻塞读 HID 输入报告。句柄失效（设备被重新枚举/蓝牙断开）时返回。

    ★ 和「按键桥」踩过的坑一样：ReadFile 失败必须让调用方知道（返回），
    由上层重新枚举设备重开句柄 —— 只在内部 while 循环里静默重试的话，
    进程还活着、界面还显示"运行中"，但一个报文都收不到。
    """
    buf = ctypes.create_string_buffer(buffer_len)
    read = wintypes.DWORD(0)
    h = ctypes.c_void_p(handle)
    while not stop_event.is_set():
        ok = kernel32.ReadFile(h, buf, buffer_len, ctypes.byref(read), None)
        if not ok:
            return False
        if read.value:
            on_report(bytes(buf.raw[:read.value]))
    return True


def to_report_hex(payload: bytes) -> str:
    """'01 03 00' 这种形式（keys.py 的 _on_report 认这个）。"""
    return " ".join(f"{b:02x}" for b in payload)


import sys  # noqa: E402  （放最后，避免影响上面的 ctypes 定义顺序）

if __name__ == "__main__":
    cols = open_collections()
    print(f"找到 {len(cols)} 个 Consumer 集合")
    for page, handle, length in cols:
        print(f"  usage_page=0x{page:04X} 报告长度={length}")
    if cols:
        stop = threading.Event()
        def show(p):
            print("  ", to_report_hex(p), flush=True)
        t = threading.Thread(target=read_loop, args=(cols[0][1], show, stop), daemon=True)
        t.start()
        print("按遥控器按键，Ctrl+C 结束")
        try:
            while True:
                import time
                time.sleep(0.2)
        except KeyboardInterrupt:
            stop.set()
            close_collections(cols)
            sys.exit(0)
