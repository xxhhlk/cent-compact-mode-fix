# -*- coding: utf-8 -*-
"""centfix —— Cent Browser 紧凑模式重启失效修复（二进制补丁工具链）。

模块分工：

* :mod:`centfix.pe`        极简 PE 解析（RVA<->偏移、.pdata 函数表、签名目录）
* :mod:`centfix.patchdef`  补丁描述模型：从 JSON 推导机器码、施加、验证
* :mod:`centfix.winproc`   Windows 进程/模块枚举与跨进程内存读取
* :mod:`centfix.locate`    版本迁移用的重新定位扫描器
* :mod:`centfix.paths`     安装目录探测、补丁匹配、备份管理

命令行入口见仓库根目录的 ``build.py`` / ``apply.py`` / ``rollback.py`` /
``verify.py`` / ``runtime_check.py`` / ``locate.py``。
"""

__version__ = "1.0.0"
__all__ = ["pe", "patchdef", "winproc", "locate", "paths"]
