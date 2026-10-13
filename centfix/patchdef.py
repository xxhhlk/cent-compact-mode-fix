# -*- coding: utf-8 -*-
"""补丁描述模型。

设计要点：JSON 里**不存**「打完之后长什么样」的最终字节，只存
「补丁点在哪、原始指令是什么、要把哪个 bool 置成什么值」，最终机器码由本模块**推导**出来。

这样做的两个好处：

1. 跳转的 ``rel32`` 偏移是算出来的，不是抄来的 —— 换代码洞地址时不会算错。
2. 一旦原始字节对不上（版本不符），能在写文件之前就中止。
"""
from __future__ import annotations

import json
import struct
from typing import Dict, List, Optional

from .pe import PE, PEError

# 常见的「16 字节 SSE 存储」指令前缀（ModRM 紧跟其后）
SSE_STORE_PREFIXES = (
    b"\x0f\x11",        # movups / movupd / movss ...
    b"\x0f\x29",        # movaps / movapd
    b"\x66\x0f\x11",    # movupd
    b"\x66\x0f\x29",    # movapd
)


def rel32(from_end: int, to: int) -> bytes:
    """生成从 ``from_end``（即 rel32 字段之后的下一条指令地址）跳到 ``to`` 的 4 字节。"""
    delta = to - from_end
    if not (-0x80000000 <= delta <= 0x7FFFFFFF):
        raise ValueError("跳转距离超出 rel32 范围: %d" % delta)
    return struct.pack("<i", delta)


def _h(x) -> int:
    """把 JSON 里的 '0x...' 字符串或 int 都转成 int。"""
    if isinstance(x, int):
        return x
    return int(str(x), 16)


class PatchDef(object):
    """一份补丁描述。"""

    def __init__(self, d: Dict, path: str = "<memory>"):
        self.raw = d
        self.path = path

        self.product = d["product"]
        self.product_version = d["product_version"]
        self.chromium_version = d.get("chromium_version", "")
        self.module = d.get("module", "chrome.dll")

        self.image_base = _h(d["image_base"])
        self.file_size = int(d["file_size"])
        self.sha1_original = d["sha1"]["original"].lower()
        self.sha1_patched = d["sha1"]["patched"].lower()

        # 以 "_" 开头的键是注释，不参与解析
        self.anchors = {k: (_h(v) if isinstance(v, str) else v)
                        for k, v in d.get("anchors", {}).items()
                        if not k.startswith("_")}

        p = d["patch"]
        self.site_rva = _h(p["site_rva"])
        self.site_original = bytes.fromhex(p["site_original_hex"])
        self.site_note = p.get("site_note", "")
        self.cave_rva = _h(p["cave_rva"])
        self.cave_size = int(p["cave_size"])
        self.cave_fill = int(p.get("cave_fill", "cc"), 16)
        self.flag_offset = _h(p["flag_offset"])
        self.flag_value = int(p["flag_value"])

        self._validate()

    # ------------------------------------------------------------- 加载/校验
    @classmethod
    def load(cls, path: str) -> "PatchDef":
        with open(path, "r", encoding="utf-8") as f:
            return cls(json.load(f), path)

    def _validate(self):
        if len(self.site_original) != 7:
            raise ValueError("site_original 必须是 7 字节（一条 7 字节的 movups）")
        if self.site_original[0:2] not in (b"\x0f\x11", b"\x0f\x29", b"\x66\x0f"):
            raise ValueError("site_original 看起来不是 16 字节 SSE 存储指令: %s"
                             % self.site_original.hex(" "))
        modrm = self.site_original[2]
        if (modrm >> 6) != 0b10:
            raise ValueError("site_original 的 ModRM 不是 [reg+disp32] 形式")
        if (modrm & 0x07) in (0b100, 0b101):
            raise ValueError("site_original 的基址寄存器是 rsp/rip，无法安全复用")
        disp = struct.unpack_from("<i", self.site_original, 3)[0]
        if not (disp <= self.flag_offset <= disp + 15):
            raise ValueError(
                "flag_offset %#x 不在那条 16 字节存储的覆盖范围 [%#x, %#x] 内 —— "
                "这个补丁依赖「编译器把相邻字段合并成一次 16 字节写」，前提不成立"
                % (self.flag_offset, disp, disp + 15))
        if len(self.cave_code()) > self.cave_size:
            raise ValueError("代码洞放不下：需要 %d 字节，洞只有 %d 字节"
                             % (len(self.cave_code()), self.cave_size))

    # ----------------------------------------------------------- 机器码推导
    @property
    def next_rva(self) -> int:
        """补丁点之后紧接着的那条指令地址（跳回目标）。"""
        return self.site_rva + len(self.site_code())

    @property
    def base_reg(self) -> int:
        """补丁点那条 movups 用的基址寄存器编号（从 ModRM 的 rm 字段取）。"""
        return self.site_original[2] & 0x07

    @property
    def merge_disp(self) -> int:
        return struct.unpack_from("<i", self.site_original, 3)[0]

    def flag_instruction(self) -> bytes:
        """``mov byte [<同一基址寄存器>+flag_offset], flag_value``"""
        # C6 /0 ib  —— ModRM: mod=10(disp32), reg=000, rm=基址寄存器
        return (b"\xc6" + bytes([0x80 | self.base_reg])
                + struct.pack("<I", self.flag_offset)
                + bytes([self.flag_value & 0xFF]))

    def site_code(self) -> bytes:
        """覆盖补丁点的 7 字节：``jmp <cave>`` + 2 个 NOP 填满原指令。"""
        return b"\xe9" + rel32(self.site_rva + 5, self.cave_rva) + b"\x90\x90"

    def cave_code(self) -> bytes:
        """代码洞内容：重放被覆盖的原指令 -> 置 flag -> 跳回。"""
        head = self.site_original                    # 重放 movups（保持原语义）
        flag = self.flag_instruction()               # 追加 mov byte [reg+off], val
        tail = b"\xe9" + rel32(self.cave_rva + len(head) + len(flag) + 5, self.next_rva)
        return head + flag + tail

    # ------------------------------------------------------------- 施加/验证
    def apply_to_bytes(self, data: bytes) -> bytes:
        """返回打过补丁的副本（不改原对象）。会先做全部前置校验。"""
        if len(data) != self.file_size:
            raise ValueError("文件大小不符：期望 %d，实际 %d" % (self.file_size, len(data)))

        pe = PE(data)
        if pe.image_base != self.image_base:
            raise ValueError("ImageBase 不符：期望 %#x，实际 %#x" % (self.image_base, pe.image_base))

        site_off = pe.rva_to_off(self.site_rva)
        got = data[site_off:site_off + len(self.site_original)]
        if got != self.site_original:
            raise ValueError(
                "补丁点原始字节不符。\n  期望: %s\n  实际: %s\n"
                "=> 这不是本补丁所针对的版本，或文件已被改动。"
                % (self.site_original.hex(" "), got.hex(" ")))

        cave_off = pe.rva_to_off(self.cave_rva)
        fill = data[cave_off:cave_off + self.cave_size]
        if fill != bytes([self.cave_fill]) * self.cave_size:
            raise ValueError("代码洞不是 %d 字节的 %02X 填充：%s"
                             % (self.cave_size, self.cave_fill, fill.hex(" ")))

        fn = pe.function_at(self.cave_rva)
        if fn is not None:
            raise ValueError("代码洞 %#x 落在函数 %#x..%#x 内，不能用作代码洞"
                             % (self.cave_rva, fn[0], fn[1]))

        out = bytearray(data)
        out[site_off:site_off + len(self.site_code())] = self.site_code()
        out[cave_off:cave_off + len(self.cave_code())] = self.cave_code()
        return bytes(out)

    def verify_bytes(self, data: bytes) -> List[str]:
        """检查 ``data`` 是否是「已正确打过本补丁」的样子，返回问题列表（空 = 通过）。"""
        problems = []
        try:
            pe = PE(data)
        except PEError as e:
            return ["PE 解析失败: %s" % e]

        try:
            site_off = pe.rva_to_off(self.site_rva)
            cave_off = pe.rva_to_off(self.cave_rva)
        except PEError as e:
            return ["地址换算失败: %s" % e]

        site = data[site_off:site_off + len(self.site_code())]
        if site != self.site_code():
            problems.append("补丁点字节不符：期望 %s，实际 %s"
                            % (self.site_code().hex(" "), site.hex(" ")))
        else:
            got = self.site_rva + 5 + struct.unpack_from("<i", site, 1)[0]
            if got != self.cave_rva:
                problems.append("补丁点跳转目标 %#x != 代码洞 %#x" % (got, self.cave_rva))

        cave = data[cave_off:cave_off + len(self.cave_code())]
        if cave != self.cave_code():
            problems.append("代码洞字节不符：期望 %s，实际 %s"
                            % (self.cave_code().hex(" "), cave.hex(" ")))
        else:
            rel = struct.unpack_from("<i", cave, len(cave) - 4)[0]
            got = self.cave_rva + len(cave) - 5 + 5 + rel
            if got != self.next_rva:
                problems.append("代码洞回跳目标 %#x != %#x" % (got, self.next_rva))

        return problems

    # --------------------------------------------------------------- 展示
    def describe(self) -> str:
        L = []
        L.append("%s %s (Chromium %s)" % (self.product, self.product_version, self.chromium_version))
        L.append("模块            : %s" % self.module)
        L.append("ImageBase       : %#x" % self.image_base)
        L.append("文件大小        : %d" % self.file_size)
        L.append("原始 SHA1       : %s" % self.sha1_original)
        L.append("补丁 SHA1       : %s" % self.sha1_patched)
        L.append("")
        L.append("补丁点 RVA      : %#x" % self.site_rva)
        L.append("  原指令        : %s   (%s)" % (self.site_original.hex(" "), self.site_note))
        L.append("  合并写位移    : %#x .. %#x" % (self.merge_disp, self.merge_disp + 15))
        L.append("  基址寄存器    : %s" % ("rax rcx rdx rbx rsp rbp rsi rdi".split()[self.base_reg]))
        L.append("  改为          : %s" % self.site_code().hex(" "))
        L.append("")
        L.append("代码洞 RVA      : %#x (容量 %d 字节)" % (self.cave_rva, self.cave_size))
        L.append("  写入          : %s" % self.cave_code().hex(" "))
        L.append("  其中          : %s  =  mov byte [%s+%#x], %d"
                 % (self.flag_instruction().hex(" "),
                    "rax rcx rdx rbx rsp rbp rsi rdi".split()[self.base_reg],
                    self.flag_offset, self.flag_value))
        L.append("  回跳          : %#x" % self.next_rva)
        return "\n".join(L)
