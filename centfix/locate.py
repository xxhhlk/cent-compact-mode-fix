# -*- coding: utf-8 -*-
"""版本迁移用的「重新定位」扫描器。

Cent Browser 每次升级都会重新编译 chrome.dll，所有 RVA 都会变。本模块用
**语义特征 + 引用链**（而不是硬编码地址）重新找到补丁点，人工确认后更新
``patches/*.json``。

主方法：顺着 ``base::Feature`` 的引用链走 —— 这条路在版本之间最稳，
因为「特性名」是编译进 chrome.dll 的 C++ 字符串字面量，不会变：

1. 全文件搜 ASCII ``"CompactMode"``（以 NUL 结尾）→ 得到字符串 RVA；
2. 找指向该字符串的 8 字节指针 → 那就是 ``base::Feature kCompactMode`` 对象
   （``Feature`` 结构第一个字段就是 ``const char* name``）；
3. 找 ``lea rip-relative`` 引用该对象的函数 → 其中**最小**的那个就是
   ``ShouldUseCompactMode()``；
4. 找 ``call`` 到 ``ShouldUseCompactMode`` 的地方 → 其中**很小的那个**调用者
   就是 ``BrowserView::ToggleCompactModeUI()``；
5. 在它里面找 ``mov byte [reg+disp32], al`` → 那个 ``disp32`` 就是
   ``is_compact_mode_`` 的成员偏移；
6. 再找「覆盖该偏移的 16 字节 SSE 清零」→ 那就是 ``BrowserViewLayout``
   构造函数里要打补丁的地方；
7. 最后找一段可用的 ``0xCC`` 代码洞。

扫描器只**报告候选**，最终要人工看反汇编确认。
"""
from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple

from .pe import PE
from .patchdef import SSE_STORE_PREFIXES

REG_NAMES = "rax rcx rdx rbx rsp rbp rsi rdi".split()
DEFAULT_FEATURE = "CompactMode"


def _reg_name(rm: int) -> str:
    return REG_NAMES[rm] if 0 <= rm < 8 else "r%d" % rm


# ------------------------------------------------------------------ 代码洞
def find_caves(pe: PE, size: int, min_free: int = 0x40) -> List[Tuple[int, int]]:
    """找可执行节里长度 >= ``size`` 的 ``0xCC`` 连续段。

    ``min_free`` 表示「整段至少多长才算真正的对齐填充」——函数间的 int3 padding
    通常有几十字节；太短的 CC 段可能只是某条指令的操作数，别用。
    返回 [(rva, 长度), ...]，按长度降序。

    实现上用 ``bytes.find`` 跳着找，不逐字节遍历（.text 有两百多 MB）。
    """
    out = []
    for s in pe.executable_sections():
        raw = pe.data[s.ptr:s.ptr + s.rsize]
        i = raw.find(b"\xcc")
        while i >= 0:
            j = i + 1
            while j < len(raw) and raw[j] == 0xCC:
                j += 1
            run = j - i
            if run >= max(size, min_free):
                rva = s.va + i
                if pe.function_at(rva) is None:
                    out.append((rva, run))
            i = raw.find(b"\xcc", j)
    out.sort(key=lambda t: -t[1])
    return out


# --------------------------------------------------- 16 字节 SSE 存储全扫描
def find_sse_stores(pe: PE, max_results: int = 500000) -> List[Dict]:
    """扫出所有 ``[reg+disp32]`` 形式的 16 字节 SSE 存储指令。"""
    out = []
    for s in pe.executable_sections():
        raw = pe.data[s.ptr:s.ptr + s.rsize]
        n = len(raw)
        for prefix in SSE_STORE_PREFIXES:
            plen = len(prefix)
            i = raw.find(prefix)
            while i >= 0:
                if i + plen + 5 > n:
                    break
                modrm = raw[i + plen]
                if (modrm >> 6) == 0b10:
                    rm = modrm & 0x07
                    if rm not in (0b100, 0b101):
                        disp = struct.unpack_from("<i", raw, i + plen + 1)[0]
                        if 0 <= disp < 0x4000:
                            rva = s.va + i
                            out.append({
                                "rva": rva, "disp": disp, "reg": _reg_name(rm),
                                "prefix": prefix.hex(" "),
                                "func": pe.function_at(rva),
                            })
                            if len(out) >= max_results:
                                return out
                i = raw.find(prefix, i + 1)
    return out


def find_merged_stores(pe: PE, flag_offset: int, max_results: int = 100000) -> List[Dict]:
    """找覆盖 ``flag_offset`` 的那些 16 字节存储（按所在函数体积升序）。"""
    hits = [s for s in find_sse_stores(pe) if s["disp"] <= flag_offset <= s["disp"] + 15]
    hits.sort(key=lambda s: (s["func"][1] - s["func"][0]) if s["func"] else 1 << 30)
    return hits[:max_results]


# ------------------------------------------------------------ vtable 识别
def text_range(pe: PE) -> Tuple[int, int]:
    """可执行节的 RVA 范围 ``(lo, hi)``。"""
    lo, hi = None, None
    for s in pe.executable_sections():
        a, b = s.va, s.va + s.span
        lo = a if lo is None else min(lo, a)
        hi = b if hi is None else max(hi, b)
    return (lo or 0, hi or 0)


def lea_targets_in(pe: PE, fn: Optional[Tuple[int, int]]) -> List[int]:
    """列出某函数体内所有 ``lea reg,[rip+disp]`` 的绝对目标地址。"""
    if not fn:
        return []
    lo, hi = fn
    raw = pe.read_rva(lo, hi - lo)
    out = []
    i = raw.find(b"\x48\x8d")
    while i >= 0:
        if i + 7 <= len(raw):
            modrm = raw[i + 2]
            if (modrm & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", raw, i + 3)[0]
                out.append(pe.image_base + lo + i + 7 + disp)
        i = raw.find(b"\x48\x8d", i + 1)
    return out


def function_vtable_refs(pe: PE, fn: Optional[Tuple[int, int]]) -> List[int]:
    """判断函数里有没有 ``lea`` 到某个 vtable（= 它很可能是个构造函数）。

    判据：lea 的目标落在非可执行节，且该处**前 8 个 qword 里至少一个**指向可执行节。
    注意不能只看第一个 qword —— Chromium 用 Clang 的 Itanium ABI，vtable 开头
    是 offset-to-top 和 RTTI 指针，函数指针从 +16 才开始。
    """
    if not fn:
        return []
    tlo = pe.image_base + text_range(pe)[0]
    thi = pe.image_base + text_range(pe)[1]
    out = []
    for va in lea_targets_in(pe, fn):
        rva = va - pe.image_base
        if rva < 0:
            continue
        s = pe.section_of_rva(rva)
        if s is None or s.executable:
            continue
        head = pe.read_rva(rva, 64)
        if len(head) < 16:
            continue
        qs = struct.unpack_from("<%dQ" % (len(head) // 8), head)
        if any(tlo <= q < thi for q in qs):
            out.append(rva)
    return out


# ------------------------------------------------------------- bool 写扫描
def find_bool_flag_stores(pe: PE, lo: int = 0x40, hi: int = 0x4000,
                          max_results: int = 500000) -> List[Dict]:
    """扫「向 [reg+disp32] 写 al / 写立即数」的指令。

    覆盖两种编码：

    * ``88 /r``  ``mov r/m8, r8``   —— reg 字段 = al(0)
    * ``C6 /0``  ``mov r/m8, imm8``
    """
    out = []
    for s in pe.executable_sections():
        raw = pe.data[s.ptr:s.ptr + s.rsize]
        n = len(raw)
        for opcode in (0x88, 0xC6):
            needle = bytes([opcode])
            i = raw.find(needle)
            while i >= 0:
                if i + 7 > n:
                    break
                modrm = raw[i + 1]
                if (modrm >> 6) == 0b10 and (modrm & 0xF8) == 0x80:
                    rm = modrm & 0x07
                    if rm not in (0b100, 0b101):     # rsp / rip 形式，跳过
                        disp = struct.unpack_from("<i", raw, i + 2)[0]
                        if lo <= disp < hi:
                            rva = s.va + i
                            out.append({
                                "rva": rva, "disp": disp, "reg": _reg_name(rm),
                                "opcode": "%02X" % opcode,
                                "len": 6 if opcode == 0x88 else 7,
                                "func": pe.function_at(rva),
                            })
                            if len(out) >= max_results:
                                return out
                i = raw.find(needle, i + 1)
    return out


def find_flag_store_in(pe: PE, func: Tuple[int, int]) -> List[Dict]:
    """在指定函数体内找所有「向 [reg+disp32] 写 al」的指令。"""
    lo, hi = func
    raw = pe.read_rva(lo, hi - lo)
    out = []
    i = raw.find(b"\x88")
    while i >= 0:
        if i + 6 <= len(raw):
            modrm = raw[i + 1]
            if (modrm >> 6) == 0b10 and (modrm & 0xF8) == 0x80:
                rm = modrm & 0x07
                if rm not in (0b100, 0b101):
                    disp = struct.unpack_from("<i", raw, i + 2)[0]
                    out.append({"rva": lo + i, "disp": disp, "reg": _reg_name(rm)})
        i = raw.find(b"\x88", i + 1)
    return out


# --------------------------------------------------------------- 交叉引用
def build_call_index(pe: PE) -> Dict[int, List[int]]:
    """一次扫描建立「被调用函数 -> 调用点列表」的索引，供调用计数 O(1) 查询。"""
    idx: Dict[int, List[int]] = {}
    for s in pe.executable_sections():
        raw = pe.data[s.ptr:s.ptr + s.rsize]
        i = raw.find(b"\xe8")
        while i >= 0:
            if i + 5 > len(raw):
                break
            delta = struct.unpack_from("<i", raw, i + 1)[0]
            idx.setdefault(s.va + i + 5 + delta, []).append(s.va + i)
            i = raw.find(b"\xe8", i + 1)
    return idx


def find_callers(pe: PE, target_rva: int) -> List[int]:
    """找所有 ``call rel32`` 到 ``target_rva`` 的调用点 RVA。"""
    return build_call_index(pe).get(target_rva, [])


def find_lea_refs(pe: PE, va: int) -> List[int]:
    """找所有 ``lea reg, [rip+disp]`` 且结果等于绝对地址 ``va`` 的指令 RVA。"""
    out = []
    for s in pe.executable_sections():
        raw = pe.data[s.ptr:s.ptr + s.rsize]
        i = raw.find(b"\x48\x8d")
        while i >= 0:
            if i + 7 > len(raw):
                break
            modrm = raw[i + 2]
            if (modrm & 0xC7) == 0x05:          # mod=00, rm=101 => RIP 相对
                disp = struct.unpack_from("<i", raw, i + 3)[0]
                if pe.image_base + s.va + i + 7 + disp == va:
                    out.append(s.va + i)
            i = raw.find(b"\x48\x8d", i + 1)
    return out


def find_pointer_to(pe: PE, va: int, limit: int = 16) -> List[int]:
    """在非可执行节里找「内容等于绝对地址 ``va`` 的 8 字节对齐指针」的 RVA。"""
    needle = struct.pack("<Q", va)
    hits = []
    for s in pe.sections:
        if s.executable:
            continue
        raw = pe.data[s.ptr:s.ptr + s.rsize]
        q = 0
        while True:
            i = raw.find(needle, q)
            if i < 0:
                break
            q = i + 1
            if i % 8 == 0:
                hits.append(s.va + i)
                if len(hits) >= limit:
                    return hits
    return hits


def functions_referencing(pe: PE, va: int) -> List[Tuple[int, int]]:
    """找出所有「用 lea 引用了绝对地址 ``va``」的函数（去重）。"""
    out, seen = [], set()
    for a in find_lea_refs(pe, va):
        fn = pe.function_at(a)
        if fn and fn[0] not in seen:
            seen.add(fn[0])
            out.append(fn)
    return out


# ------------------------------------------------------------- 引用链定位
def relocate(pe: PE, feature_name: str = DEFAULT_FEATURE) -> Optional[Dict]:
    """顺着 ``base::Feature`` 引用链自动定位补丁点。失败返回 ``None``。"""
    trace: List[str] = []

    # 1) 特性名字符串
    idx = pe.data.find(feature_name.encode() + b"\0")
    if idx < 0:
        return None
    try:
        rva_str = pe.off_to_rva(idx)
    except Exception:                                    # noqa: BLE001
        return None
    trace.append("特性名字符串 %r @ RVA %#x" % (feature_name, rva_str))

    # 2) Feature 对象
    objs = find_pointer_to(pe, pe.image_base + rva_str)
    if not objs:
        return None
    trace.append("base::Feature 对象 @ RVA %#x（共 %d 个）" % (objs[0], len(objs)))

    should = None
    for obj in objs:
        funcs = functions_referencing(pe, pe.image_base + obj)
        small = [f for f in funcs if f[1] - f[0] <= 256]
        if small:
            should = min(small, key=lambda f: f[1] - f[0])
            trace.append("ShouldUseCompactMode 候选 @ RVA %#x..%#x (size=%d)"
                         % (should[0], should[1], should[1] - should[0]))
            break
    if should is None:
        return None

    # 3) 调用 ShouldUseCompactMode 的小函数 = ToggleCompactModeUI
    callidx = build_call_index(pe)
    callers = []
    seen = set()
    for a in callidx.get(should[0], []):
        fn = pe.function_at(a)
        if fn and fn[0] not in seen:
            seen.add(fn[0])
            callers.append(fn)
    if not callers:
        return None
    small_callers = [f for f in callers if f[1] - f[0] <= 256]
    if not small_callers:
        return None
    toggle = min(small_callers, key=lambda f: f[1] - f[0])
    trace.append("ToggleCompactModeUI 候选 @ RVA %#x..%#x (size=%d, callers=%d)"
                 % (toggle[0], toggle[1], toggle[1] - toggle[0],
                    len(callidx.get(toggle[0], []))))

    # 4) 函数体内的 bool 写 = flag 偏移
    stores = find_flag_store_in(pe, toggle)
    if not stores:
        return None
    flag = stores[0]
    trace.append("is_compact_mode_ 偏移 = %#x（来自 @RVA %#x  mov byte [%s+%#x], al）"
                 % (flag["disp"], flag["rva"], flag["reg"], flag["disp"]))

    # 5) 覆盖该偏移的 16 字节清零 = 补丁点
    merged = find_merged_stores(pe, flag["disp"])
    annotate_sites(pe, merged, flag["disp"], callidx)
    trace.append("覆盖该偏移的 16 字节存储：%d 个（其中 %d 个所在函数引用了 vtable）"
                 % (len(merged), sum(1 for m in merged if m["vtable_refs"])))

    return {
        "trace": trace,
        "feature_string_rva": rva_str,
        "feature_object_rva": objs[0],
        "should_use_rva": should[0],
        "toggle_rva": toggle[0],
        "flag_offset": flag["disp"],
        "flag_store": flag,
        "site_candidates": merged,
        "callers_of_should": callers,
    }


def annotate_sites(pe: PE, merged: List[Dict], flag_offset: int,
                   callidx: Optional[Dict[int, List[int]]] = None) -> List[Dict]:
    """给候选补上「是否在末字节 / 是否引用 vtable / 被调用次数」，并按可信度排序。"""
    if callidx is None:
        callidx = build_call_index(pe)
    for m in merged:
        fn = m["func"]
        m["is_last_byte"] = (m["disp"] + 15 == flag_offset)
        m["vtable_refs"] = function_vtable_refs(pe, fn) if fn else []
        m["callers"] = len(callidx.get(fn[0], [])) if fn else None
    merged.sort(key=lambda m: (0 if m["vtable_refs"] else 1,
                               0 if m["is_last_byte"] else 1,
                               (m["func"][1] - m["func"][0]) if m["func"] else 1 << 30))
    return merged


# ------------------------------------------------------------------ 汇总报告
def relocate_report(pe: PE, flag_offset: Optional[int] = None,
                    cave_size: int = 25, feature_name: str = DEFAULT_FEATURE) -> str:
    """打印一次完整的重新定位报告。"""
    L = []
    L.append("=" * 78)
    L.append("重新定位报告")
    L.append("=" * 78)
    L.append(pe.summary())
    L.append("")

    res = None
    if flag_offset is None:
        L.append("-" * 78)
        L.append("步骤 1~2：顺 base::Feature 引用链定位（特性名 %r）" % feature_name)
        L.append("-" * 78)
        res = relocate(pe, feature_name)
        if res is None:
            L.append("！引用链中断 —— 特性名可能变了，或该特性已被上游移除。")
            L.append("  可以退回人工模式：先手工确认 flag 偏移，再用")
            L.append("  `--flag-offset 0x??` 跑本脚本。")
            L.append("")
        else:
            for t in res["trace"]:
                L.append("  " + t)
            flag_offset = res["flag_offset"]
            L.append("")
    else:
        L.append("已给定 flag 偏移 = %#x，跳过引用链，直接找覆盖它的 16 字节存储。"
                 % flag_offset)
        L.append("")

    if flag_offset is not None:
        L.append("-" * 78)
        L.append("步骤 3：覆盖 flag 偏移(%#x) 的 16 字节 SSE 存储 = 补丁点候选" % flag_offset)
        L.append("-" * 78)
        if res:
            merged = res["site_candidates"]
        else:
            merged = annotate_sites(pe, find_merged_stores(pe, flag_offset), flag_offset)
        if not merged:
            L.append("  ！没找到。编译器这次可能没有合并写 —— 需要换一种补丁思路。")
        vt_only = [m for m in merged if m.get("vtable_refs")]
        show = vt_only if vt_only else merged
        if vt_only:
            L.append("  优先展示「所在函数引用了 vtable」的候选（= 很可能是构造函数）：")
        for i, m in enumerate(show[:15]):
            fn = m["func"]
            marks = []
            if m.get("vtable_refs"):
                marks.append("vtable=%s" % ",".join("%#x" % v for v in m["vtable_refs"][:2]))
            if m.get("is_last_byte"):
                marks.append("bool 在末字节")
            if m.get("callers") is not None:
                marks.append("callers=%d" % m["callers"])
            L.append("  [%2d] @%#010x  %s [%s+%#x]  覆盖 %#x..%#x  函数 %s"
                     % (i, m["rva"], m["prefix"], m["reg"], m["disp"],
                        m["disp"], m["disp"] + 15,
                        ("%#x..%#x (size=%d)" % (fn[0], fn[1], fn[1] - fn[0])) if fn else "?"))
            if marks:
                L.append("       " + "   ".join(marks))
        L.append("")
        L.append("  => 确认哪条在 BrowserViewLayout 构造函数里（它会被某条 lea 引用为")
        L.append("     vtable，且只被调用一次），把它的 rva 当 site_rva。")
        L.append("")

    L.append("-" * 78)
    L.append("步骤 4：找可用代码洞（连续 0xCC 且不在任何函数体内）")
    L.append("-" * 78)
    caves = find_caves(pe, cave_size)
    L.append("可用洞 %d 个（前 10 个，按长度降序）：" % len(caves))
    for rva, run in caves[:10]:
        L.append("  @%#010x  长度 %d" % (rva, run))
    if not caves:
        L.append("  ！没找到。可以改用「把 site 覆盖成 jmp 到函数末尾的 CC 段」或新增节。")
    L.append("")
    L.append("提示：cave 越靠前、越独立越好；选好后务必确认它不在任何 .pdata 函数体内。")
    return "\n".join(L)
