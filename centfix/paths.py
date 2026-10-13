# -*- coding: utf-8 -*-
"""路径与补丁描述的查找辅助。"""
from __future__ import annotations

import glob
import os
from typing import List, Optional, Tuple

from .pe import sha1_file
from .patchdef import PatchDef


def repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def patches_dir() -> str:
    return os.path.join(repo_root(), "patches")


def backups_dir() -> str:
    d = os.path.join(repo_root(), "backups")
    os.makedirs(d, exist_ok=True)
    return d


def load_all_patches() -> List[PatchDef]:
    out = []
    for p in sorted(glob.glob(os.path.join(patches_dir(), "*.json"))):
        try:
            out.append(PatchDef.load(p))
        except Exception as e:            # noqa: BLE001 - 坏描述不该拖垮其他补丁
            print("!! 跳过 %s: %s" % (os.path.basename(p), e))
    return out


def cent_application_roots() -> List[str]:
    """常见的 Cent Browser Application 目录。"""
    roots = []
    local = os.environ.get("LOCALAPPDATA")
    if local:
        roots.append(os.path.join(local, "CentBrowser", "Application"))
    pf = os.environ.get("ProgramFiles")
    if pf:
        roots.append(os.path.join(pf, "CentBrowser", "Application"))
    pf86 = os.environ.get("ProgramFiles(x86)")
    if pf86:
        roots.append(os.path.join(pf86, "CentBrowser", "Application"))
    return [r for r in roots if os.path.isdir(r)]


def find_cent_installs() -> List[Tuple[str, str]]:
    """返回 [(版本号, chrome.dll 路径), ...]，按版本号降序。"""
    out = []
    for root in cent_application_roots():
        for dll in glob.glob(os.path.join(root, "*", "chrome.dll")):
            version = os.path.basename(os.path.dirname(dll))
            out.append((version, dll))
    out.sort(key=lambda t: t[0], reverse=True)
    return out


def resolve_target(explicit: Optional[str] = None) -> str:
    """确定要操作的 chrome.dll：显式指定 > 自动探测（取版本号最高的那个）。"""
    if explicit:
        if not os.path.isfile(explicit):
            raise SystemExit("!! 找不到文件: %s" % explicit)
        return explicit
    installs = find_cent_installs()
    if not installs:
        raise SystemExit(
            "!! 没找到 Cent Browser 安装。请用 --dll <chrome.dll 路径> 显式指定。")
    if len(installs) > 1:
        print("发现多个安装，选用版本号最高的一个：")
        for v, p in installs:
            print("   %-14s %s" % (v, p))
        print()
    return installs[0][1]


def match_patch_for(dll_path: str, patches: Optional[List[PatchDef]] = None) -> Optional[PatchDef]:
    """按 SHA1 找出这份 chrome.dll 对应的补丁描述。"""
    if patches is None:
        patches = load_all_patches()
    h = sha1_file(dll_path)
    for p in patches:
        if h in (p.sha1_original, p.sha1_patched):
            return p
    return None


def newest_backup(dll_name: str = "chrome.dll") -> Optional[str]:
    files = sorted(glob.glob(os.path.join(backups_dir(), "%s.orig-*" % dll_name)))
    return files[-1] if files else None
