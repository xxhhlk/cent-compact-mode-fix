# cent-compact-mode-fix

修复 **Cent Browser 5.2.1168.83（Chromium 134 内核）「紧凑模式重启后标签栏高度被还原」** 的二进制补丁工具链。

项目为AI Agent 代完成。

不改源码、不重打包，直接对安装目录里的 `chrome.dll` 做 **25 字节**语义修补；  
仓库里不含任何二进制产物，补丁由你自己机器上的原始文件现场生成，每一步都可校验、可回滚。

> **根因是上游 Chromium 的 bug**：`CompactMode` 是 Google 的实验特性，2025-01-09 被上游删除  
> （commit `2423efbcd682`，"experimental prototype we are no longer pursuing"），  
> 所以不会有官方修复。详细推导见 [`docs/root-cause.md`](docs/root-cause.md)。

---

## 症状

| 场景                  | 表现                                        |
| ------------------- | ----------------------------------------- |
| 打开紧凑模式，**当前会话**     | 正常                                        |
| 打开紧凑模式，**关闭浏览器再打开** | 标签栏高度变回普通高度，但间距 / 按钮宽度等其余紧凑效果仍在 —— 半个紧凑模式 |

---

## 快速开始

需要 Python 3.8+（**零第三方依赖**，只用标准库）。

```bash
# 0) 完全退出 Cent Browser（含托盘/后台进程），这一步必须做
# 1) 先体检，不写任何文件
python apply.py --dry-run

# 2) 真正应用（会自动备份 + 写后校验，失败自动回滚）
python apply.py --yes

# 3) 启动 Cent Browser 后，直接读运行时内存确认补丁生效
python runtime_check.py
#    is_compact_mode_ = 1   -> 生效
#    is_compact_mode_ = 0   -> 未生效

# 4) 想撤销
python rollback.py --yes
```

---

## 工具一览

| 脚本                 | 作用                                                 |
| ------------------ | -------------------------------------------------- |
| `build.py`         | 从**原始** `chrome.dll` 生成打过补丁的副本（不碰安装目录）             |
| `apply.py`         | 应用到安装目录：进程占用检查 → 备份 → 写入 → 校验（失败自动回滚）              |
| `rollback.py`      | 从备份恢复原始文件                                          |
| `verify.py`        | 独立校验一份 `chrome.dll` 有没有正确打上补丁（重新推导期望字节再比对）         |
| `runtime_check.py` | 浏览器**运行中**直接读内存里的 `is_compact_mode_`，最硬的证据         |
| `locate.py`        | Cent 升级后，为新版本**重新定位**补丁点（顺 `base::Feature` 引用链自动找） |

常用参数：

```bash
python build.py --list                      # 列出仓库里的补丁描述
python build.py --dll <原始dll> --out <路径>  # 指定输入输出
python apply.py --dll <目标dll> --yes        # 指定目标（默认自动探测安装目录）
python verify.py --baseline <原始dll>        # 额外统计逐字节差异
python locate.py --dll <新版本dll>            # 重新定位
python locate.py --dll <新版本dll> --flag-offset 0xb8   # 已知偏移时跳过引用链
```

---

## 补丁内容

针对 `Cent Browser 5.2.1168.83 / chrome.dll`（243,780,096 字节，ImageBase `0x180000000`）：

| 项目      | 值                                                                      |
| ------- | ---------------------------------------------------------------------- |
| 原始 SHA1 | `ade00d3ebc2d61c7a57457d9bf56aa48e3ef9f80`                             |
| 补丁 SHA1 | `495fff8cc9c246b225fc5f4bbf74378ef9415fdb`                             |
| 差异字节数   | **25**                                                                 |
| 站点 RVA  | `0x275e0d0`（`BrowserViewLayout::BrowserViewLayout`，函数 RVA `0x275de50`） |
| 代码洞 RVA | `0x289d0a7`（25 字节全 `0xCC`，不在任何 `.pdata` 函数体内）                          |
| 改动语义    | `is_compact_mode_` 初值 `false` → `true`                                 |

```
站点 0x275e0d0  (7 B)   e9 d2 ef 13 00   jmp 0x289d0a7
                        90 90             NOP 填满

代码洞 0x289d0a7 (19 B) 0f 11 b6 a9 00 00 00   movups [rsi+0xA9], xmm6   重放原指令
                        c6 86 b8 00 00 00 01   mov byte [rsi+0xB8], 1    置位
                        e9 1d 10 ec ff         jmp 0x275e0d7             跳回
```

那两条 `movups` / `mov byte` 的**基址寄存器和位移都是从原始指令字节里推导出来的**  
（见 `centfix/patchdef.py`），不是抄死的常量 —— 所以两处 `rel32` 跳转永远不会算错。

---

## 原理摘要

1. `BrowserView` 构造函数里调用 `ToggleCompactModeUI()`，但此时 `BrowserViewLayout` 还没创建，  
   `static_cast<BrowserViewLayout*>(GetLayoutManager())` 把写入落到了 `ClientView` 装的临时  
   `FillLayout` 上 —— **静默写错对象**。
2. 真正的 `BrowserViewLayout` 在 `AddedToWidget()` 才创建，`is_compact_mode_` 保持默认 `false`。
3. 这个缓存字段**只被标签栏高度读取**，其余紧凑效果都实时读 pref —— 所以只有标签栏出问题。
4. 编译器把 `contents_border_widget_`(+0xB0) 和 `is_compact_mode_`(+0xB8) 的清零**合并成一条  
   16 字节 `movups`**（起始位移 `0xB8 - 15 = 0xA9`），于是这一条指令把 flag 写成了 0。
5. 补丁就是在这条合并写上做手脚：重放它，然后把 flag 改成 1。

完整推导（含反汇编、PE 校验、安全性与被否决的方案）见 [`docs/root-cause.md`](docs/root-cause.md)。

---

## 已知副作用

补丁把初值**硬编码为 `true`**：

- 重启时紧凑模式是**开**的 → 行为完全正确；
- 重启时紧凑模式是**关**的 → 标签栏会矮约 6px，手动切换一次开关即恢复，其余部位正常。

---

## Cent 升级后怎么迁移

Cent Browser 每次升级都会重新编译 `chrome.dll`，所有 RVA 都会变。补丁描述文件  
`patches/<版本>.json` 里的 `sha1.original` 一匹配不上，`apply.py` 就会拒绝操作（这是有意的）。

迁移步骤：

```bash
# 1) 让工具自动找新位置：顺 base::Feature 引用链走
python locate.py --dll "C:\...\CentBrowser\Application\<新版本>\chrome.dll"
```

它会自动完成：

1. 搜字符串 `"CompactMode"` → 定位 `base::Feature kCompactMode` 对象；
2. 找 `lea` 引用该对象的函数 → 最小的那个是 `ShouldUseCompactMode()`；
3. 找 `call` 它的函数 → 很小的那个是 `ToggleCompactModeUI()`；
4. 在它里面找 `mov byte [reg+disp32], al` → 得到 `is_compact_mode_` 偏移；
5. 找覆盖该偏移的 16 字节清零 → 补丁点候选（已按「是否引用 vtable」筛选）；
6. 找可用代码洞。

```bash
# 2) 人工确认候选后，把新的 site_rva / cave_rva / sha1 填进 patches/<新版本>.json
# 3) 用新文件重新生成并验证
python build.py --dll <新版本dll>
python verify.py --dll <生成结果> --baseline <新版本dll>
```

---

## 安全与免责

- **先备份**：`apply.py` 会把原始文件复制到 `backups/`，写后校验失败会自动回滚。
- **只接受预期版本**：SHA1 不是「原始」或「补丁」值时，一律中止，不做任何写入。
- **不改结构**：不动节表、导入表、重定位表、资源；只改 25 个字节的代码。
- **无签名可破坏**：该 `chrome.dll` 本来就没有 Authenticode 签名（SECURITY 目录为空）。
- **风险自担**：这是对商业软件的二进制修改。请自行确认在你的使用场景下合规，  
  并保留备份。因使用本工具造成的任何后果由使用者承担。

---

## 目录结构

```
cent-compact-mode-fix/
├── build.py               # 从原始 dll 生成补丁版
├── apply.py               # 应用到安装目录
├── rollback.py            # 回滚
├── verify.py              # 字节级独立校验
├── runtime_check.py       # 运行时内存校验
├── locate.py              # 新版本重新定位
├── patches/
│   └── 5.2.1168.83.json   # 补丁描述（不含二进制）
├── centfix/               # 共享库（纯标准库）
│   ├── pe.py              #   极简 PE 解析
│   ├── patchdef.py        #   补丁描述模型 + 机器码推导
│   ├── winproc.py         #   进程/模块枚举 + 跨进程读内存
│   ├── locate.py          #   重新定位扫描器
│   └── paths.py           #   安装探测 / 补丁匹配 / 备份管理
├── docs/
│   └── root-cause.md      # 完整根因分析
├── backups/               # 备份（gitignore）
└── out/                   # 生成的补丁版（gitignore）
```

## 许可

MIT，见 [LICENSE](LICENSE)。
