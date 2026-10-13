#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build.py —— 从**你自己机器上的原始 chrome.dll** 生成打过补丁的副本。

仓库里刻意不放 243 MB 的 DLL。补丁是「把 25 个字节改掉」，所以只要有一份
原始文件 + 一份补丁描述，就能随时重建，而且每一步都能校验。

用法::

    python build.py                                  # 自动探测安装，输出到 out/
    python build.py --dll <chrome.dll> --out <path>
    python build.py --list                           # 只列出可用的补丁描述
"""
from __future__ import annotations

import argparse
import os
import sys

from centfix import paths
from centfix.pe import PE, sha1_bytes, sha1_file


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="从原始 chrome.dll 生成补丁版副本")
    ap.add_argument("--dll", help="原始 chrome.dll 路径（默认自动探测 Cent Browser 安装）")
    ap.add_argument("--patch", help="补丁描述 JSON（默认按 SHA1 自动匹配）")
    ap.add_argument("--out", help="输出路径（默认 out/<版本>/chrome.dll）")
    ap.add_argument("--list", action="store_true", help="列出仓库里的补丁描述后退出")
    args = ap.parse_args(argv)

    if args.list:
        ps = paths.load_all_patches()
        if not ps:
            print("(patches/ 下没有可用的补丁描述)")
            return 1
        for p in ps:
            print("%s %s  (Chromium %s)" % (p.product, p.product_version, p.chromium_version))
            print("   原始 SHA1 %s" % p.sha1_original)
            print("   补丁 SHA1 %s" % p.sha1_patched)
        return 0

    dll = paths.resolve_target(args.dll)
    print("目标 chrome.dll : %s" % dll)

    with open(dll, "rb") as f:
        data = f.read()

    actual = sha1_bytes(data)
    print("实际 SHA1       : %s" % actual)

    if args.patch:
        from centfix.patchdef import PatchDef
        pdef = PatchDef.load(args.patch)
    else:
        pdef = paths.match_patch_for(dll)
        if pdef is None:
            print("!! 没有任何补丁描述匹配这份文件的 SHA1。")
            print("   可能原因：Cent 已升级 / 文件被改过 / 需要先用 locate.py 重新定位。")
            return 2

    print("匹配到补丁      : %s %s" % (pdef.product, pdef.product_version))
    print()

    if actual == pdef.sha1_patched:
        print("=> 这份文件**已经是补丁版本**了，无需再打。")
        return 0
    if actual != pdef.sha1_original:
        print("!! 文件 SHA1 既不等于原始也不等于补丁值，拒绝操作。")
        return 2

    pe = PE(data)
    print(pe.summary())
    print()
    print(pdef.describe())
    print()

    patched = pdef.apply_to_bytes(data)

    got = sha1_bytes(patched)
    if got != pdef.sha1_patched:
        print("!! 生成结果的 SHA1 与描述文件不一致：")
        print("   期望 %s" % pdef.sha1_patched)
        print("   实际 %s" % got)
        return 3
    problems = pdef.verify_bytes(patched)
    if problems:
        print("!! 自检未通过：")
        for x in problems:
            print("   - %s" % x)
        return 3

    diff = [i for i in range(len(data)) if data[i] != patched[i]]
    print("自检通过：与原始文件恰好 %d 字节不同，SHA1 = %s" % (len(diff), got))

    out = args.out or os.path.join(paths.repo_root(), "out",
                                   pdef.product_version, pdef.module)
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "wb") as f:
        f.write(patched)
    print("已写出          : %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
