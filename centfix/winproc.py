# -*- coding: utf-8 -*-
"""Windows 进程/模块枚举 + 跨进程内存读取（纯 ``ctypes``，不需要调试器）。

用途有两个：

* ``apply.py`` 用它确认「没有进程正加载着我们要替换的 chrome.dll」；
* ``runtime_check.py`` 用它读取运行中浏览器的内存，直接看
  ``BrowserViewLayout::is_compact_mode_`` 到底是 0 还是 1。

踩过的坑（写在前面省得再踩）：
``ctypes`` 调 Win32 时**必须给每个函数声明 ``argtypes``/``restype``**，
否则 64 位下 ``HANDLE`` 会被当成 32 位 int 截断，表现为句柄无效或静默失败。
"""
from __future__ import annotations

import ctypes
import struct
from ctypes import wintypes
from typing import List, Optional, Set, Tuple

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
u32 = ctypes.WinDLL("user32")

INVALID_HANDLE = 0xFFFFFFFFFFFFFFFF
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
MAX_USER_ADDR = 0x7FFFFFFFFFFF

k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.CloseHandle.restype = wintypes.BOOL
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.OpenProcess.restype = wintypes.HANDLE
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = wintypes.BOOL
k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                               ctypes.c_void_p, ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t

u32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
u32.GetWindowThreadProcessId.restype = wintypes.DWORD
u32.IsWindowVisible.argtypes = [wintypes.HWND]
u32.IsWindowVisible.restype = wintypes.BOOL
u32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
u32.GetWindowTextLengthW.restype = ctypes.c_int
u32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
u32.GetWindowTextW.restype = ctypes.c_int


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD), ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wintypes.DWORD), ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * 256), ("szExePath", wintypes.WCHAR * 260),
    ]


class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong), ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", wintypes.DWORD), ("__align1", wintypes.DWORD),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", wintypes.DWORD), ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD), ("__align2", wintypes.DWORD),
    ]


k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
k32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
k32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]


# --------------------------------------------------------------------- 枚举
def iter_processes() -> List[Tuple[int, str]]:
    """返回 [(pid, exe 文件名), ...]。"""
    out = []
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap in (0, INVALID_HANDLE, None):
        return out
    try:
        e = PROCESSENTRY32W()
        e.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = k32.Process32FirstW(snap, ctypes.byref(e))
        while ok:
            out.append((e.th32ProcessID, e.szExeFile))
            ok = k32.Process32NextW(snap, ctypes.byref(e))
    finally:
        k32.CloseHandle(snap)
    return out


def iter_modules(pid: int) -> List[Tuple[str, str, int]]:
    """返回 [(模块名, 模块路径, 加载基址), ...]。"""
    out = []
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap in (0, INVALID_HANDLE, None):
        return out
    try:
        m = MODULEENTRY32W()
        m.dwSize = ctypes.sizeof(MODULEENTRY32W)
        ok = k32.Module32FirstW(snap, ctypes.byref(m))
        while ok:
            base = int(ctypes.cast(m.modBaseAddr, ctypes.c_void_p).value or 0)
            out.append((m.szModule, m.szExePath, base))
            ok = k32.Module32NextW(snap, ctypes.byref(m))
    finally:
        k32.CloseHandle(snap)
    return out


def find_processes_loading(dll_path_substr: str, module_name: str = "chrome.dll"):
    """找出所有加载了「路径包含 ``dll_path_substr``」的 ``module_name`` 的进程。

    返回 [(pid, exe 文件名, dll 完整路径, dll 加载基址), ...]。
    """
    needle = dll_path_substr.lower()
    want = module_name.lower()
    out = []
    for pid, exe in iter_processes():
        for name, path, base in iter_modules(pid):
            if name.lower() == want and needle in path.lower():
                out.append((pid, exe, path, base))
                break
    return out


# --------------------------------------------------------------------- 窗口
def visible_window_pids() -> Set[int]:
    """返回所有「有可见顶层窗口」的 pid。"""
    pids = set()

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def cb(hwnd, _lp):
        if not u32.IsWindowVisible(hwnd):
            return True
        pid = wintypes.DWORD(0)
        u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        pids.add(pid.value)
        return True

    u32.EnumWindows(cb, 0)
    return pids


def window_titles(pid: int) -> List[str]:
    """返回指定进程所有可见顶层窗口的标题。"""
    titles = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def cb(hwnd, _lp):
        p = wintypes.DWORD(0)
        u32.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
        if p.value == pid and u32.IsWindowVisible(hwnd):
            n = u32.GetWindowTextLengthW(hwnd)
            if n > 0:
                buf = ctypes.create_unicode_buffer(n + 2)
                u32.GetWindowTextW(hwnd, buf, n + 2)
                if buf.value:
                    titles.append(buf.value)
        return True

    u32.EnumWindows(cb, 0)
    return titles


# ------------------------------------------------------------- 跨进程读取
class RemoteProcess(object):
    """打开一个进程并读取它的内存。用 ``with`` 管理句柄。"""

    def __init__(self, pid: int):
        self.pid = pid
        self.handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not self.handle:
            raise OSError("OpenProcess(%d) 失败，错误码 %d（权限不足或进程已退出）"
                          % (pid, ctypes.get_last_error()))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def close(self):
        if self.handle:
            k32.CloseHandle(self.handle)
            self.handle = None

    def read(self, addr: int, size: int) -> Optional[bytes]:
        """读 ``size`` 字节；失败返回 ``None``（不抛异常，方便批量扫描）。"""
        if not self.handle or size <= 0:
            return None
        buf = (ctypes.c_char * size)()
        got = ctypes.c_size_t(0)
        ok = k32.ReadProcessMemory(self.handle, ctypes.c_void_p(addr),
                                   ctypes.byref(buf), size, ctypes.byref(got))
        if not ok or got.value != size:
            return None
        return buf.raw

    def read_u64(self, addr: int) -> Optional[int]:
        b = self.read(addr, 8)
        return struct.unpack("<Q", b)[0] if b else None

    def regions(self, max_size: int = 0x40000000):
        """迭代可读的已提交内存区 [(base, size, protect), ...]。"""
        mbi = MEMORY_BASIC_INFORMATION64()
        addr = 0
        while addr < MAX_USER_ADDR:
            if k32.VirtualQueryEx(self.handle, ctypes.c_void_p(addr),
                                  ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
                break
            base, size = mbi.BaseAddress, mbi.RegionSize
            if size == 0:
                break
            readable = (mbi.State == MEM_COMMIT
                        and (mbi.Protect & 0xFF) not in (0, PAGE_NOACCESS)
                        and not (mbi.Protect & PAGE_GUARD)
                        and size <= max_size)
            if readable:
                yield base, size, mbi.Protect
            addr = base + size

    def find_qwords(self, value: int, limit: int = 64, chunk: int = 0x800000) -> List[int]:
        """全内存扫描，找出所有等于 ``value`` 的 8 字节对齐指针。"""
        needle = struct.pack("<Q", value)
        hits = []
        for base, size, _prot in self.regions():
            off = 0
            while off < size:
                n = min(chunk, size - off)
                data = self.read(base + off, n)
                if data:
                    q = 0
                    while True:
                        i = data.find(needle, q)
                        if i < 0:
                            break
                        q = i + 1
                        hits.append(base + off + i)
                        if len(hits) >= limit:
                            return hits
                off += n
        return hits
