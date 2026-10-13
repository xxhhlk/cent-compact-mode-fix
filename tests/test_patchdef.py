#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""补丁描述的自洽性自检（不需要 chrome.dll，可在任何环境跑）。

跑法::

    python tests/test_patchdef.py

它校验的是「描述文件本身」是否自洽：推导出来的机器码长度对不对、
两处 ``rel32`` 跳转能不能首尾衔接、``flag_offset`` 是否真的落在那条 16 字节写的
覆盖范围内。这些一旦写错，打出来的补丁就是错的，所以值得单独测。
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from centfix import paths                     # noqa: E402
from centfix.pe import PEError                # noqa: E402
from centfix.patchdef import PatchDef, rel32  # noqa: E402

FAILED = []


def check(cond, msg):
    if cond:
        print("  [OK] %s" % msg)
    else:
        print("  [!!] %s" % msg)
        FAILED.append(msg)


def test_patch(p: PatchDef):
    print("== %s %s ==" % (p.product, p.product_version))

    site = p.site_code()
    cave = p.cave_code()

    check(len(site) == 7, "站点码 7 字节（实际 %d）" % len(site))
    check(len(cave) <= p.cave_size,
          "代码洞放得下：%d <= %d" % (len(cave), p.cave_size))

    # 站点跳转
    dst = p.site_rva + 5 + struct.unpack_from("<i", site, 1)[0]
    check(dst == p.cave_rva, "站点 jmp 目标 %#x == 代码洞 %#x" % (dst, p.cave_rva))
    check(site[5:7] == b"\x90\x90", "站点尾部用 2 个 NOP 填满")

    # 洞内回跳
    tail_off = len(cave) - 5
    back = p.cave_rva + tail_off + 5 + struct.unpack_from("<i", cave, tail_off + 1)[0]
    check(back == p.next_rva, "洞内 jmp 回跳 %#x == %#x" % (back, p.next_rva))

    # 洞头重放的是原始指令
    check(cave[:len(p.site_original)] == p.site_original,
          "洞头原样重放被覆盖的指令")

    # flag 指令
    flag = p.flag_instruction()
    check(len(flag) == 7, "flag 指令 7 字节（实际 %d）" % len(flag))
    check(flag[0] == 0xC6, "flag 指令 opcode = C6 (mov r/m8, imm8)")
    check((flag[1] >> 6) == 0b10, "flag 指令用 [reg+disp32] 寻址")
    check((flag[1] & 0x07) == p.base_reg,
          "flag 指令复用站点同款基址寄存器（%s）"
          % "rax rcx rdx rbx rsp rbp rsi rdi".split()[p.base_reg])
    check(struct.unpack_from("<I", flag, 2)[0] == p.flag_offset,
          "flag 指令位移 = %#x" % p.flag_offset)
    check(flag[6] == p.flag_value, "flag 指令立即数 = %d" % p.flag_value)

    # 语义前提：flag 必须落在那条 16 字节写的覆盖范围内
    check(p.merge_disp <= p.flag_offset <= p.merge_disp + 15,
          "flag %#x 落在合并写 [%#x, %#x] 内"
          % (p.flag_offset, p.merge_disp, p.merge_disp + 15))

    # 反推：拿一段错误数据应该被拒绝
    try:
        p.apply_to_bytes(b"\x00" * p.file_size)
        check(False, "对全零数据应该拒绝")
    except (ValueError, PEError):
        check(True, "对错误数据正确拒绝（不会盲写）")


def test_rel32():
    print("== rel32 ==")
    check(rel32(0x1005, 0x2000) == struct.pack("<i", 0x2000 - 0x1005), "rel32 正跳")
    check(rel32(0x1005, 0x1000) == struct.pack("<i", -5), "rel32 负跳")


def main() -> int:
    test_rel32()
    print()
    ps = paths.load_all_patches()
    if not ps:
        print("!! patches/ 下没有可用的补丁描述")
        return 1
    for p in ps:
        test_patch(p)
        print()

    if FAILED:
        print("失败 %d 项：" % len(FAILED))
        for m in FAILED:
            print("  - %s" % m)
        return 1
    print("全部通过。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
