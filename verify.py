#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify.py —— 独立校验一份 chrome.dll 到底有没有正确打上补丁。

刻意不复用 ``apply.py`` 的判断：这里直接从文件字节重新推导期望值，
再和实际字节比对，并把跳转目标反算出来。

用法::

    python verify.py                       # 校验安装目录里的那份
    python verify.py --dll <path>
    python verify.py --baseline <原始文件>  # 额外统计逐字节差异
"""
from __future__ import annotations

import argparse
import os
import struct
import sys

from centfix import paths
from centfix.pe import PE, PEError, sha1_file


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="独立校验补丁是否已正确应用")
    ap.add_argument("--dll", help="要校验的 chrome.dll（默认自动探测）")
    ap.add_argument("--patch", help="补丁描述 JSON（默认按 SHA1 自动匹配）")
    ap.add_argument("--baseline", help="原始文件，用于统计逐字节差异")
    args = ap.parse_args(argv)

    dll = paths.resolve_target(args.dll)
    print("校验对象        : %s" % dll)
    actual = sha1_file(dll)
    print("SHA1            : %s" % actual)

    if args.patch:
        from centfix.patchdef import PatchDef
        pdef = PatchDef.load(args.patch)
    else:
        pdef = paths.match_patch_for(dll)
        if pdef is None:
            print("!! 没有补丁描述匹配这个 SHA1，无法判断。")
            return 2

    print("匹配到补丁      : %s %s" % (pdef.product, pdef.product_version))
    print()

    with open(dll, "rb") as f:
        data = f.read()

    try:
        pe = PE(data)
    except PEError as e:
        print("!! PE 解析失败: %s" % e)
        return 3
    print(pe.summary())
    print()

    if actual == pdef.sha1_original:
        print("结论：这是**原始未打补丁**的版本。")
        print("      （SHA1 与描述文件里的 original 一致）")
        return 0

    if actual != pdef.sha1_patched:
        print("结论：SHA1 既不等于原始也不等于补丁值 —— 文件被第三方改动过。")
        print("      期望补丁值 %s" % pdef.sha1_patched)
        return 4

    # ---- 字节级校验 ----
    site_off = pe.rva_to_off(pdef.site_rva)
    cave_off = pe.rva_to_off(pdef.cave_rva)

    site = data[site_off:site_off + len(pdef.site_code())]
    cave = data[cave_off:cave_off + len(pdef.cave_code())]

    print("补丁点 RVA %#x（文件偏移 %#x）" % (pdef.site_rva, site_off))
    print("  实际字节 : %s" % site.hex(" "))
    print("  期望字节 : %s" % pdef.site_code().hex(" "))
    if site == pdef.site_code():
        dst = pdef.site_rva + 5 + struct.unpack_from("<i", site, 1)[0]
        print("  [OK] jmp 目标 = %#x（应为代码洞 %#x）" % (dst, pdef.cave_rva))
    else:
        print("  [!!] 不符")
        return 5

    print()
    print("代码洞 RVA %#x（文件偏移 %#x）" % (pdef.cave_rva, cave_off))
    print("  实际字节 : %s" % cave.hex(" "))
    print("  期望字节 : %s" % pdef.cave_code().hex(" "))
    if cave == pdef.cave_code():
        rel = struct.unpack_from("<i", cave, len(cave) - 4)[0]
        dst = pdef.cave_rva + len(cave) - 5 + 5 + rel
        print("  [OK] 回跳目标 = %#x（应为 %#x）" % (dst, pdef.next_rva))
        print("  [OK] 其中 %s = mov byte [%s+%#x], %d"
              % (pdef.flag_instruction().hex(" "),
                 "rax rcx rdx rbx rsp rbp rsi rdi".split()[pdef.base_reg],
                 pdef.flag_offset, pdef.flag_value))
    else:
        print("  [!!] 不符")
        return 5

    print()
    problems = pdef.verify_bytes(data)
    if problems:
        print("内部一致性检查发现问题：")
        for x in problems:
            print("  - %s" % x)
        return 5
    print("内部一致性检查 : 通过")

    # ---- 与原始文件对比 ----
    base = args.baseline or paths.newest_backup(os.path.basename(dll))
    if base and os.path.isfile(base):
        with open(base, "rb") as f:
            orig = f.read()
        if len(orig) == len(data):
            diff = [i for i in range(len(orig)) if orig[i] != data[i]]
            print()
            print("与原始文件对比  : %s" % base)
            print("  差异字节数    : %d" % len(diff))
            if diff:
                print("  差异区间      : %#x .. %#x" % (min(diff), max(diff)))
            if len(diff) != 25:
                print("  [注意] 预期恰好 25 字节不同，实际 %d —— 请人工确认。" % len(diff))
    else:
        print()
        print("（没有找到原始备份，跳过逐字节差异统计；可用 --baseline 指定）")

    print()
    print("结论：补丁已正确应用。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
