#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rollback.py —— 从备份恢复原始 chrome.dll。

用法::

    python rollback.py                # 列出可用备份并说明（不写）
    python rollback.py --yes          # 用最新的备份恢复
    python rollback.py --from <备份文件> --yes
"""
from __future__ import annotations

import argparse
import glob
import os
import shutil
import sys

from centfix import paths
from centfix.pe import sha1_file
from centfix.winproc import find_processes_loading


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="撤销紧凑模式补丁，恢复原始 chrome.dll")
    ap.add_argument("--dll", help="目标 chrome.dll（默认自动探测）")
    ap.add_argument("--from", dest="src", help="指定备份文件")
    ap.add_argument("--yes", action="store_true", help="确认执行")
    args = ap.parse_args(argv)

    dll = paths.resolve_target(args.dll)
    print("目标 chrome.dll : %s" % dll)

    if args.src:
        src = args.src
    else:
        src = paths.newest_backup(os.path.basename(dll))
    if not src or not os.path.isfile(src):
        print("!! 找不到备份文件。备份位于 %s" % paths.backups_dir())
        return 2

    print("使用备份        : %s" % src)

    patches = paths.load_all_patches()
    src_sha = sha1_file(src)
    known = [p for p in patches if src_sha == p.sha1_original]
    if not known:
        print("!! 备份的 SHA1 (%s) 不匹配任何已知补丁的原始值。" % src_sha)
        print("   拒绝恢复（避免拿错文件覆盖）。")
        return 2
    print("备份校验通过    : 这是 %s %s 的原始 chrome.dll"
          % (known[0].product, known[0].product_version))

    if not args.yes:
        print()
        print("=> 未写入。确认无误后加上 --yes：")
        print("     python rollback.py --yes")
        return 0

    procs = find_processes_loading(os.path.dirname(dll))
    if procs:
        print("!! 下列进程正加载着这个 chrome.dll，无法替换：")
        for pid, exe, path, _base in procs:
            print("     pid=%-7d %-14s %s" % (pid, exe, path))
        print("   请先完全退出 Cent Browser。")
        return 4

    # 先把当前（补丁版）也留一份，万一想再打回去
    cur = os.path.join(paths.backups_dir(),
                       "%s.patched-%s" % (os.path.basename(dll),
                                          __import__("time").strftime("%Y%m%d-%H%M%S")))
    shutil.copy2(dll, cur)
    print("已留存当前版本  : %s" % cur)

    shutil.copy2(src, dll)
    got = sha1_file(dll)
    if got != src_sha:
        print("!! 恢复后校验失败（实际 %s）" % got)
        return 5

    print("=> 已恢复原始文件，SHA1 = %s" % got)
    print("   重启 Cent Browser 后，紧凑模式重启失效的 bug 会回来（这是预期行为）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
