#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""apply.py —— 把补丁装到 Cent Browser 的安装目录里。

安全措施（每一条都是踩过坑之后加的）：

* 只接受 SHA1 严格等于「原始版本」的文件，任何其他情况直接中止；
* 写入前确认**没有任何进程**正加载着这个 chrome.dll（否则文件被占用 / 换掉也没用）；
* 先把原始文件备份到 ``backups/``，再写；
* 写完立刻校验 SHA1，不一致就自动回滚。

用法::

    python apply.py --dry-run            # 只检查，不写
    python apply.py --yes                # 真正写入
    python apply.py --dll <path> --yes   # 指定目标
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import time

from centfix import paths
from centfix.pe import PE, sha1_bytes, sha1_file
from centfix.winproc import find_processes_loading


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="把紧凑模式补丁应用到 Cent Browser")
    ap.add_argument("--dll", help="目标 chrome.dll（默认自动探测）")
    ap.add_argument("--patch", help="补丁描述 JSON（默认按 SHA1 自动匹配）")
    ap.add_argument("--dry-run", action="store_true", help="只检查，不写文件")
    ap.add_argument("--yes", action="store_true", help="确认执行（不加则只打印计划）")
    args = ap.parse_args(argv)

    dll = paths.resolve_target(args.dll)
    print("目标 chrome.dll : %s" % dll)

    if args.patch:
        from centfix.patchdef import PatchDef
        pdef = PatchDef.load(args.patch)
    else:
        pdef = paths.match_patch_for(dll)
        if pdef is None:
            print("!! 没有补丁描述匹配这份文件（SHA1 %s）。" % sha1_file(dll))
            print("   Cent 可能已升级，需要先用 locate.py 重新定位。")
            return 2

    with open(dll, "rb") as f:
        data = f.read()
    actual = sha1_bytes(data)
    print("实际 SHA1       : %s" % actual)

    if actual == pdef.sha1_patched:
        print("=> 已经是补丁版本，无需操作。")
        return 0
    if actual != pdef.sha1_original:
        print("!! 文件不是预期的原始版本（既不等于原始也不等于补丁 SHA1），已中止。")
        return 2

    print("匹配到补丁      : %s %s" % (pdef.product, pdef.product_version))

    # 先用内存里的副本演练一遍，确认真的能打
    patched = pdef.apply_to_bytes(data)
    if sha1_bytes(patched) != pdef.sha1_patched:
        print("!! 预演失败：生成结果 SHA1 与描述不符，已中止。")
        return 3
    print("预演通过        : 打完后 SHA1 = %s" % pdef.sha1_patched)
    print()

    procs = find_processes_loading(os.path.dirname(dll))
    if procs:
        print("!! 下列进程正加载着这个 chrome.dll，无法替换：")
        for pid, exe, path, _base in procs:
            print("     pid=%-7d %-14s %s" % (pid, exe, path))
        print("   请先**完全退出** Cent Browser（含托盘/后台进程），再重试。")
        return 4
    print("进程检查通过    : 没有进程占用这个 chrome.dll")

    if args.dry_run or not args.yes:
        print()
        if args.dry_run:
            print("=> --dry-run：一切就绪，未写入任何文件。")
        else:
            print("=> 一切就绪。加上 --yes 才会真正写入：")
            print("     python apply.py --yes")
        return 0

    # ---- 备份 ----
    bak = os.path.join(paths.backups_dir(),
                       "%s.orig-%s" % (pdef.module, time.strftime("%Y%m%d-%H%M%S")))
    shutil.copy2(dll, bak)
    if sha1_file(bak) != pdef.sha1_original:
        print("!! 备份校验失败，已中止（未改动原文件）")
        return 5
    print("已备份          : %s" % bak)

    # ---- 写入 ----
    with open(dll, "wb") as f:
        f.write(patched)

    got = sha1_file(dll)
    if got != pdef.sha1_patched:
        print("!! 写入后校验失败（实际 %s），正在回滚 ..." % got)
        shutil.copy2(bak, dll)
        print("   回滚完成，当前 SHA1 = %s" % sha1_file(dll))
        return 6

    print("=> 补丁已应用。当前 SHA1 = %s" % got)
    print()
    print("接下来：")
    print("  1. 启动 Cent Browser，确认标签栏高度正常；")
    print("  2. 关闭再重启一次，确认紧凑模式**不再被还原**；")
    print("  3. 想直接看运行时状态：先启动 Cent，再跑")
    print("       python runtime_check.py")
    print("  4. 需要撤销：python rollback.py --yes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
