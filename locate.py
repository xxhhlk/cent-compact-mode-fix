#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""locate.py —— 为新版本的 chrome.dll 重新定位补丁点。

Cent Browser 升级后会重新编译 chrome.dll，所有 RVA 都会变。这个脚本用**语义特征**
去重新找三个东西，然后把结果打印出来供人工确认：

1. ``is_compact_mode_`` 的成员偏移（扫 ``mov byte [reg+disp32], al``）
2. 覆盖该偏移的 16 字节合并写（= 要打补丁的 site）
3. 可用的代码洞（连续 ``0xCC`` 且不在任何 ``.pdata`` 函数体内）

确认之后，把新的 RVA 填进 ``patches/<版本>.json`` 即可。

用法::

    python locate.py --dll <chrome.dll>
    python locate.py --dll <chrome.dll> --flag-offset 0xb8
"""
from __future__ import annotations

import argparse
import sys

from centfix import paths
from centfix.locate import relocate_report
from centfix.pe import PE


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="为新版本 chrome.dll 重新定位补丁点")
    ap.add_argument("--dll", help="chrome.dll 路径（默认自动探测）")
    ap.add_argument("--flag-offset", default=None,
                    help="已知的 is_compact_mode_ 偏移，如 0xb8；给了就跳过步骤 1")
    ap.add_argument("--cave-size", type=int, default=25, help="需要的代码洞字节数")
    args = ap.parse_args(argv)

    dll = paths.resolve_target(args.dll)
    with open(dll, "rb") as f:
        data = f.read()
    pe = PE(data)

    flag = None
    if args.flag_offset is not None:
        flag = int(args.flag_offset, 16) if isinstance(args.flag_offset, str) else args.flag_offset

    print(relocate_report(pe, flag_offset=flag, cave_size=args.cave_size))
    return 0


if __name__ == "__main__":
    sys.exit(main())
