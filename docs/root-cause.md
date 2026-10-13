# 根因分析：紧凑模式为什么重启后失效

本文记录从「现象」到「一行字节补丁」的完整推导过程，便于在新版本上重新定位时对照。

---

## 1. 现象

Cent Browser 5.2.1168.83（Chromium 134.0.6998.136）：

- 打开「紧凑模式」后，**当前会话**一切正常；
- **关闭浏览器再打开**，紧凑模式只恢复了一部分 —— 标签栏（tab strip）高度变回普通高度，  
  但间距、按钮宽度等其余紧凑化效果还在。

也就是「半个紧凑模式」。

## 2. 这不是 Cent 的 bug，是上游实验特性被砍

`CompactMode` 是 Chromium 的 `base::Feature`，flag 为 `chrome://flags/#compact-mode`，  
偏好项名 `compact_mode`（`RegisterBooleanPref`，默认 `false`）。

它在 2025-01-09 被上游删除，提交 `2423efbcd682`，理由是  
"experimental prototype we are no longer pursuing"（不再推进的实验原型）。

所以：

- **不会有官方修复**；
- Cent Browser 作为下游，只是把当年那份未完成的实现继续编译进来了。

## 3. 源码级根因

关键在「初始化时机」和「写到哪个对象上」两件事。

### 3.1 `BrowserView` 构造时布局管理器还不存在

Chromium 的 `views` 框架里：

1. `BrowserView` 的构造函数里会调用 `ToggleCompactModeUI()`，试图把紧凑状态应用到布局上；
2. 但此时 `BrowserView` 还没有被加进任何 widget，`BrowserViewLayout` **尚未被创建**；
3. `ClientView` 的构造函数会先装一个临时的 `FillLayout`；
4. 而 `ToggleCompactModeUI()` 里做的是类似
   ```cpp
   static_cast<BrowserViewLayout*>(GetLayoutManager())->set_is_compact_mode(v);
   ```
   的强转 —— **没有类型检查**。于是这次写入实际落到了那个临时的 `FillLayout` 对象上  
   （写进了它的某个字段），真正的 `BrowserViewLayout` 毫发无损。

### 3.2 真正的布局是后来才建的

`BrowserView` 被 `AddedToWidget()` 时才创建 `BrowserViewLayout`，此时  
`is_compact_mode_` 保持**成员默认值 `false`** —— 构造函数里那次赋值早就写丢了。

### 3.3 为什么只有标签栏出问题

`is_compact_mode_` 这个缓存字段**只被标签栏高度计算读取**：

```cpp
int BrowserViewLayout::GetTopContainerPreferredHeight() {
  if (is_compact_mode_) { ... 紧凑高度 ... }
  ...
}
```

其余紧凑化效果（按钮宽度、间距等）都是**当场读 pref**（`ShouldUseCompactMode()`），  
所以不受这个缓存字段影响 —— 于是出现「只还原了标签栏高度」这种半吊子现象。

### 3.4 正确的修法 vs 我们的修法

源码级正确修法是把 `ToggleCompactModeUI()` 的调用从构造函数挪到 `AddedToWidget()`  
（或让 `BrowserViewLayout` 的构造函数自己从 pref 读初值）。**但没有源码，只有二进制。**

## 4. 反汇编级：那一行到底长什么样

在 `BrowserViewLayout::BrowserViewLayout()`（RVA `0x275de50`，1105 字节，只有 1 个调用者）  
里找到罪魁祸首：

```
0x275e0d0:  0f 11 b6 a9 00 00 00     movups xmmword ptr [rsi+0xA9], xmm6
```

编译器把两个相邻字段的「清零」**合并成了一条 16 字节 SSE 写**：

| 成员                        | 偏移      | 说明            |
| ------------------------- | ------- | ------------- |
| `contents_border_widget_` | `+0xB0` | 8 字节指针        |
| `is_compact_mode_`        | `+0xB8` | **1 字节 bool** |

起始位移 `0xA9 = 0xB8 - 15`，所以 `is_compact_mode_` 恰好落在这 16 字节的**最后一个字节**。  
这一条指令把 `is_compact_mode_` 写成了 `0`。

顺便，`ToggleCompactModeUI`（RVA `0x8b592b0`，95 字节，只有 1 个调用者）里  
存着它的「单独写」形态：

```
0x8b592fc:  88 81 b8 00 00 00        mov byte ptr [rcx+0xB8], al
```

这两处 `0xB8` 互相印证，就是 `is_compact_mode_` 的成员偏移。

## 5. 补丁设计

把那条 7 字节的 `movups` 换成跳转，跳到一段空闲的 `0xCC` 填充区（代码洞），  
在洞里「先重放原指令，再把 flag 置 1，最后跳回来」：

```
站点 0x275e0d0  (7 B)      e9 d2 ef 13 00      jmp 0x289d0a7
                           90 90                (NOP 填满原指令剩余字节)

代码洞 0x289d0a7 (19 B)    0f 11 b6 a9 00 00 00   movups [rsi+0xA9], xmm6   ← 重放
                           c6 86 b8 00 00 00 01   mov byte [rsi+0xB8], 1    ← 置位
                           e9 1d 10 ec ff         jmp 0x275e0d7            ← 跳回
```

要点：

- **`rsi` 全程没被改写**（函数入口处 `mov rsi, rcx` 存了一次 this 指针），  
  所以洞里可以安全复用同一个基址寄存器。
- **`0xB8` 与 `0xA9` 都从「原始指令字节」里推导**，不硬编码 —— 见  
  `centfix/patchdef.py` 的 `base_reg` / `merge_disp`。
- 代码洞选的是一段 25 字节的全 `0xCC` 填充（RVA `0x289d0a7`），  
  并且**不在任何 `.pdata` 函数体内**（用 PE 的异常表验证），不会被当作函数体参与  
  栈回溯/展开。

### 为什么这样是安全的

| 顾虑                             | 结论                                                             |
| ------------------------------ | -------------------------------------------------------------- |
| 会不会被 CFG（Control Flow Guard）拦？ | 不会。`E9` 是**直接相对跳转**，不经过间接跳转表；且跳转目标在 `.text` 内                  |
| 会不会破坏栈展开？                      | 不会。站点与洞都不在任何 `.pdata` 函数体范围内（已用脚本验证）                           |
| 会不会触发签名校验？                     | 不会。chrome.dll **本来就没有 Authenticode 签名**（SECURITY 目录为空），没有东西可破坏 |
| 会不会触发 PE 校验和校验？                | 不会。Windows 不对用户态 DLL 强制校验 `CheckSum`；Loader 只在映射驱动等场景关心它       |
| 改了会不会导致文件被拒绝加载？                | 不会。总共只改了 **25 个字节**，节表、目录、重定位表都没动                              |

### 试过但被否掉的方案

| 方案                                    | 否决原因                                                |
| ------------------------------------- | --------------------------------------------------- |
| 改 `compact_mode` 偏好值                  | 无效。问题不在偏好，而在「布局对象构造时没读偏好」                           |
| 打开书签栏                                 | 用户明确否决 —— 紧凑模式的**目的**就是压缩头部高度，加书签栏完全违背初衷            |
| 改 `ShouldUseCompactMode()` 恒返回 `true` | 会破坏「关掉紧凑模式」的能力：关了也没用                                |
| 修 `BrowserViewLayout` 构造函数去读 pref     | 需要在洞里塞进读 pref 的调用序列，体积远超 25 字节的洞，且要处理调用约定 —— 收益不抵风险 |

## 6. 已知副作用

补丁把初值**硬编码为 `true`**，所以：

- 如果重启时紧凑模式是**开**的 → 行为完全正确（正常使用场景）；
- 如果重启时紧凑模式是**关**的 → 标签栏会矮约 6px，直到你手动切换一次开关  
  （其余部位正常）。

这是「1 字节语义修改」换来的代价，可接受。真要彻底干净，需要按 §3.4 的源码级修法重写。

## 7. 逆向过程中的方法论教训

这轮踩的坑值得记下来，都是「结论看起来对、其实是自己脚本错了」的类型：

1. **capstone 的内存操作数在 `operands[1]`，不是 `operands[0]`。**  
   `mov rcx, [rcx+0x3c0]` 这种「加载」指令，目的操作数是寄存器（`operands[0]`），  
   内存操作数排在后面。只扫 `operands[0]` 会漏掉**所有**内存读取 —— 白跑了好几轮。
2. **别把「看起来像 vtable 的指针数组」当成 vtable。**  
   `0xcacc7f0` 看着像，实际是 118 个 `purecall` 桩。真 vtable 在 `0xcacc430`。  
   判据要加上「数组里的指针确实指向可执行节」。
3. **Chromium 的 vtable 开头不是函数指针。**  
   它用 Clang 的 Itanium ABI：`[+0]` 是 offset-to-top、`[+8]` 是 RTTI 指针，  
   函数指针从 `[+16]` 才开始。只检查第一个 qword 会把真 vtable 全部漏掉  
   （本仓库的 `function_vtable_refs` 就是这么修好的）。
4. **地址算术要拿脚本算，不要心算。**  
   `0x7ffbdbb5c150 - 0x7ffbcf310000` 应该是 `0xc84c150`，手算写成了 `0xa4c150`。
5. **验证脚本本身也要交叉验证。**  
   本轮出现过 3 次「脚本报错、其实是脚本自己错」：切片 off-by-one  
   （`mov byte [rsi+0xB8],1` 是 **7** 字节，按 8 字节切就会假报失败）、  
   RVA/VA 单位混用、忘了给 ctypes 声明 `argtypes`。  
   **任何一个「校验失败」的结论，先怀疑校验代码。**
