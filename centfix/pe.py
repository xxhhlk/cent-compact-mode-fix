# -*- coding: utf-8 -*-
"""极简 PE 解析器（仅标准库，无第三方依赖）。

只做本补丁真正需要的事：

* 读节表 / ImageBase / 可选头 magic
* RVA <-> 文件偏移 互转
* 解析 ``.pdata`` 得到函数边界（用来判断某个地址是否落在函数体内）
* 读数据目录（判断 SECURITY 目录是否为空，即有没有 Authenticode 签名）

刻意不引入 ``pefile``：一是让仓库零依赖，二是我们要对「写进文件里的那 25 个字节」
负责，自己解析一遍反而更可信。
"""
from __future__ import annotations

import bisect
import hashlib
import struct
from typing import List, Optional, Tuple

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_DIRECTORY_ENTRY_SECURITY = 4


class PEError(Exception):
    pass


class Section(object):
    __slots__ = ("name", "vsize", "va", "rsize", "ptr", "chars")

    def __init__(self, name, vsize, va, rsize, ptr, chars):
        self.name = name        # 节名
        self.vsize = vsize      # VirtualSize
        self.va = va            # VirtualAddress（即 RVA）
        self.rsize = rsize      # SizeOfRawData
        self.ptr = ptr          # PointerToRawData
        self.chars = chars      # Characteristics

    @property
    def span(self) -> int:
        """地址映射时以 max(VirtualSize, SizeOfRawData) 为准，兼容两种打包写法。"""
        return max(self.vsize, self.rsize)

    @property
    def executable(self) -> bool:
        return bool(self.chars & IMAGE_SCN_MEM_EXECUTE)

    def __repr__(self):
        return "<Section %-8s rva=%#x vsz=%#x raw=%#x>" % (
            self.name, self.va, self.vsize, self.rsize)


class PE(object):
    def __init__(self, data: bytes):
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise PEError("不是 PE 文件：缺少 MZ 头")
        self.data = data
        e = struct.unpack_from("<I", data, 0x3C)[0]
        if e + 24 > len(data) or data[e:e + 4] != b"PE\0\0":
            raise PEError("不是 PE 文件：缺少 PE 签名")
        self.e_lfanew = e

        coff = e + 4
        self.machine, self.nsections = struct.unpack_from("<HH", data, coff)
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        self.opt_off = coff + 20
        self.opt_size = opt_size

        magic = struct.unpack_from("<H", data, self.opt_off)[0]
        if magic == 0x20B:          # PE32+
            self.is_pe32plus = True
            self.image_base = struct.unpack_from("<Q", data, self.opt_off + 24)[0]
        elif magic == 0x10B:        # PE32
            self.is_pe32plus = False
            self.image_base = struct.unpack_from("<I", data, self.opt_off + 28)[0]
        else:
            raise PEError("未知的可选头 magic: %#x" % magic)

        self.sections: List[Section] = []
        st = self.opt_off + opt_size
        for i in range(self.nsections):
            o = st + i * 40
            name = data[o:o + 8].rstrip(b"\0").decode("latin1")
            vsize, va, rsize, ptr = struct.unpack_from("<IIII", data, o + 8)
            chars = struct.unpack_from("<I", data, o + 36)[0]
            self.sections.append(Section(name, vsize, va, rsize, ptr, chars))

        self._funcs = None
        self._func_starts = None

    # ------------------------------------------------------------------ 换算
    def section_of_rva(self, rva: int) -> Optional[Section]:
        for s in self.sections:
            if s.va <= rva < s.va + s.span:
                return s
        return None

    def rva_to_off(self, rva: int) -> int:
        s = self.section_of_rva(rva)
        if s is None:
            raise PEError("RVA %#x 不在任何节内" % rva)
        off = s.ptr + (rva - s.va)
        if not (0 <= off < len(self.data)):
            raise PEError("RVA %#x 换算出的文件偏移 %#x 越界" % (rva, off))
        return off

    def off_to_rva(self, off: int) -> int:
        for s in self.sections:
            if s.ptr <= off < s.ptr + s.rsize:
                return s.va + (off - s.ptr)
        raise PEError("文件偏移 %#x 不在任何节内" % off)

    def va_to_off(self, va: int) -> int:
        return self.rva_to_off(va - self.image_base)

    def read_rva(self, rva: int, size: int) -> bytes:
        off = self.rva_to_off(rva)
        return self.data[off:off + size]

    def section_by_name(self, name: str) -> Optional[Section]:
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def executable_sections(self) -> List[Section]:
        return [s for s in self.sections if s.executable]

    # -------------------------------------------------------------- 数据目录
    def data_directories(self) -> List[Tuple[int, int]]:
        # 目录表起点：PE32 = opt_off+96，PE32+ = opt_off+112
        base = self.opt_off + (112 if self.is_pe32plus else 96)
        n_off = self.opt_off + (108 if self.is_pe32plus else 92)
        n = struct.unpack_from("<I", self.data, n_off)[0]
        out = []
        for i in range(min(n, 16)):
            rva, size = struct.unpack_from("<II", self.data, base + i * 8)
            out.append((rva, size))
        return out

    def security_dir(self) -> Tuple[int, int]:
        d = self.data_directories()
        return d[IMAGE_DIRECTORY_ENTRY_SECURITY] if len(d) > IMAGE_DIRECTORY_ENTRY_SECURITY else (0, 0)

    @property
    def is_signed(self) -> bool:
        rva, size = self.security_dir()
        return rva != 0 and size != 0

    # ---------------------------------------------------------------- .pdata
    def functions(self) -> List[Tuple[int, int]]:
        """返回按起始地址排序的 [(begin_rva, end_rva), ...]。"""
        if self._funcs is None:
            out = []
            s = self.section_by_name(".pdata")
            if s is not None:
                raw = self.data[s.ptr:s.ptr + s.rsize]
                for x in range(0, len(raw) - 11, 12):
                    begin, end, _unwind = struct.unpack_from("<III", raw, x)
                    if end > begin:
                        out.append((begin, end))
                out.sort()
            self._funcs = out
            self._func_starts = [a for a, _ in out]
        return self._funcs

    def function_at(self, rva: int):
        funcs = self.functions()
        if not funcs:
            return None
        starts = self._func_starts
        i = bisect.bisect_right(starts, rva) - 1
        if i >= 0 and funcs[i][0] <= rva < funcs[i][1]:
            return funcs[i]
        return None

    # ------------------------------------------------------------------ 杂项
    def summary(self) -> str:
        lines = [
            "ImageBase      : %#x" % self.image_base,
            "位数           : %s" % ("PE32+" if self.is_pe32plus else "PE32"),
            "节数           : %d" % self.nsections,
            "Authenticode   : %s" % ("已签名" if self.is_signed else "未签名（SECURITY 目录为空）"),
            ".pdata 函数数  : %d" % len(self.functions()),
        ]
        for s in self.sections:
            lines.append("  %-8s rva=%#010x vsz=%#010x raw=%#010x %s"
                         % (s.name, s.va, s.vsize, s.rsize, "X" if s.executable else " "))
        return "\n".join(lines)


def sha1_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(chunk), b""):
            h.update(blk)
    return h.hexdigest()


def sha1_bytes(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()
