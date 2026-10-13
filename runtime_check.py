#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""runtime_check.py —— 浏览器**正在运行时**直接读内存，看补丁到底有没有生效。

原理：``BrowserView`` 对象头部的第一个字段是指向它 vtable 的指针，而 vtable 的
RVA 是固定的。所以只要全内存搜「值等于 ImageBase+vtable_RVA 的 8 字节」，就能
定位到 ``BrowserView`` 实例；再从 ``[BrowserView + 0x3c0]`` 取到 ``BrowserViewLayout``，
读 ``[layout + 0xB8]`` 就是 ``is_compact_mode_``。

    0 = bug 复现（重启后标签栏高度会被还原）
    1 = 补丁生效

用法::

    python runtime_check.py                       # 自动探测
    python runtime_check.py --path centbrowser    # 按安装路径子串筛选进程
"""
from __future__ import annotations

import argparse
import os
import sys

from centfix import paths
from centfix.winproc import (RemoteProcess, find_processes_loading,
                             visible_window_pids, window_titles)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="运行时读取 is_compact_mode_ 的真实值")
    ap.add_argument("--path", default="centbrowser",
                    help="用安装路径子串筛选进程（默认 centbrowser）")
    ap.add_argument("--patch", help="补丁描述 JSON（默认用匹配到安装目录的那份）")
    ap.add_argument("--all", action="store_true",
                    help="不限于有可见窗口的进程，扫描所有匹配进程")
    args = ap.parse_args(argv)

    pdef = None
    if args.patch:
        from centfix.patchdef import PatchDef
        pdef = PatchDef.load(args.patch)
    else:
        installs = paths.find_cent_installs()
        for _v, dll in installs:
            pdef = paths.match_patch_for(dll)
            if pdef:
                print("使用补丁描述    : %s %s" % (pdef.product, pdef.product_version))
                break
    if pdef is None:
        print("!! 找不到可用的补丁描述（无法确定 vtable / 成员偏移）。")
        return 2

    a = pdef.anchors
    bv_vt_rva = a["browserview_vtable_rva"]
    lay_vt_rva = a["browserview_layout_vtable_rva"]
    lay_ptr_off = a["browserview_layout_ptr_offset"]
    flag_off = a["is_compact_mode_offset"]
    print("锚点            : BrowserView vtable RVA=%#x, layout vtable RVA=%#x, "
          "layout 指针偏移=%#x, flag 偏移=%#x"
          % (bv_vt_rva, lay_vt_rva, lay_ptr_off, flag_off))
    print()

    procs = find_processes_loading(args.path)
    if not procs:
        print("!! 没有找到加载着「路径含 %r 的 chrome.dll」的进程。" % args.path)
        print("   请先启动 Cent Browser。")
        return 3

    if not args.all:
        win = visible_window_pids()
        picked = [p for p in procs if p[0] in win]
        if picked:
            procs = picked
    print("匹配进程 %d 个：" % len(procs))
    for pid, exe, path, base in procs:
        t = window_titles(pid)
        print("  pid=%-7d %-12s base=%#x %s"
              % (pid, exe, base, ("窗口: " + " | ".join(t[:2])) if t else ""))
    print()

    ok_any = False
    for pid, exe, path, base in procs:
        try:
            rp = RemoteProcess(pid)
        except OSError as e:
            print("pid %d: 打开失败（%s）" % (pid, e))
            continue
        with rp:
            hits = rp.find_qwords(base + bv_vt_rva, limit=16)
            if not hits:
                print("pid %d: 没找到 BrowserView 实例（页面还没渲染完？稍等再试）" % pid)
                continue
            print("pid %d: 找到 %d 个 BrowserView 实例" % (pid, len(hits)))
            for A in hits:
                layout = rp.read_u64(A + lay_ptr_off)
                if not layout:
                    continue
                vt = rp.read_u64(layout)
                if vt != base + lay_vt_rva:
                    print("   obj=%#x layout=%#x vtable=%#x（不是 BrowserViewLayout，跳过）"
                          % (A, layout, vt))
                    continue
                raw = rp.read(layout + flag_off, 1)
                if raw is None:
                    continue
                flag = raw[0]
                verdict = "1 -> 补丁生效" if flag else "0 -> bug 复现"
                print("   obj=%#x layout=%#x  is_compact_mode_ = %d   [%s]"
                      % (A, layout, flag, verdict))
                if flag:
                    ok_any = True
        print()

    if ok_any:
        print("=> 至少一个 BrowserView 的 is_compact_mode_ 为 1，补丁在真实运行中生效。")
        return 0
    print("=> 没读到值为 1 的实例。若浏览器刚启动，等页面渲染完再跑一次。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
