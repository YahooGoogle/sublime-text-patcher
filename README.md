# Sublime Text x64 自动定位补丁工具

手动更新 Sublime Text 后，退出程序并运行一次脚本，自动定位并禁用：

- 未注册购买提醒的自动调度。
- 后台自动更新检查及其更新提示。

保留 `Help > Check for Updates…` 手动检查入口。无常驻进程、计划任务或在线分析服务。常规运行不需要 IDA 或 Frida。

> **使用前请阅读 [免责声明与合理使用建议](DISCLAIMER.md)。** 本项目为独立研究工具，不提供 Sublime Text 许可证；MIT 仅适用于本项目原创代码。

## 安装依赖

需要 Windows x64 和 Python 3.10 或更新版本。在 PowerShell 中执行：

```powershell
git clone https://github.com/YahooGoogle/sublime-text-patcher.git
Set-Location sublime-text-patcher
python -m pip install -r requirements.txt
```

本机实测：Python 3.13、pefile 2023.2.7、Capstone 5.0.9。

## 每次手动更新后的操作

1. 完成 Sublime Text 更新。
2. 保存编辑内容，退出所有使用目标安装路径的 Sublime 实例。
3. 运行以下命令。若安装在需要管理员写入权限的目录，用管理员 PowerShell 运行。

```powershell
python -X utf8 .\sublime_patch.py
```

默认目标：`D:\Program Files\Sublime Text\sublime_text.exe`。

```powershell
# 指定其他安装位置
python -X utf8 .\sublime_patch.py --exe 'C:\Program Files\Sublime Text\sublime_text.exe'

# 仅分析；不创建报告、备份、修补文件
python -X utf8 .\sublime_patch.py --dry-run

# 在新路径生成修补副本，原程序不变；拒绝覆盖已存在的输出文件
python -X utf8 .\sublime_patch.py --output 'E:\output\sublime_text.patched.exe'

# 自定义备份/报告目录
python -X utf8 .\sublime_patch.py --artifacts-dir 'E:\backups\sublime_patch'
```

退出码 `0` 表示成功、预览成功或无需修改；退出码 `1` 表示失败。两项均已修补时输出“无需修改”，不产生新备份。只有一项修补时，只改变另一项；任意一项定位失败，两项都不会写入。

## 定位方式与边界

工具解析 PE 节区与 x64 `.pdata` 函数边界，在指令边界上验证 RIP 相对引用及调用/跳转关系。

购买提醒从正文、标题和按钮三组英文文本定位对话框构造函数，再查找传入该回调的调度函数。只有比较条件、调度状态写入、回调参数和正常返回路径都吻合，才生成补丁。

自动更新从 `update_check` 的配置读取及内部开关覆盖逻辑定位布尔开关，再沿稳定版更新 URL 的调用关系确认自动检查函数。补丁直接进入该函数的正常返回分支，早于时间判断和更新任务创建。

现有 4200 的地址和 SHA-256 仅用于回归验收，正式定位不依赖固定地址、版本号或哈希白名单。当前支持常见的 `jne` 短/近跳转及本工具生成的已修补形式。只在函数结构、参数传递和唯一候选等条件满足时工作；其他架构、重写的控制流、缺少锚点、重复候选或异常 PE 都会停止，打印诊断。

**不承诺适配任意未来版本。** 已实测 4200 原始、仅购买提醒已修补及完整修补三种真实样本，并通过改变代码/数据 RVA、相对位移和跳转长度的合成 PE 测试。另有 4215 成功定位、应用补丁及写入哈希校验的本地清单证据；4215 尚未完成与 4200 同等级别的受控运行验证，详见 [验收记录](VALIDATION.md)。

`update_check=false` 本身在当前未注册的 4200 中会被内部逻辑覆盖，本工具不以设置文件存在作为成功依据。此工具不会修改许可证状态、手动检查入口或用户配置。修改签名 PE 内容后，原 Authenticode 验证会失效。

## 备份、报告与恢复

默认在脚本所在目录的 `artifacts/sublime_patch/` 下为每次实际写入创建独立目录。可通过 `--artifacts-dir` 指定其他位置。

每次目录包含：

- `original.exe.bak`：修改前的完整文件，创建后逐字节校验。
- `manifest.json`：来源/目标路径、版本、前后哈希、补丁偏移/RVA、前后字节、语义定位证据和操作状态。
- `report.md`：便于阅读的结果摘要。

输出中的 `prepared` 表示备份/写入前清单已就绪，`applied` 表示写入校验通过，`failed` 表示此次失败，`restored` 表示已经恢复。终端会打印本次清单和备份的绝对路径。

恢复前先退出目标 Sublime，然后把以下示例路径替换为本次生成的实际清单：

```powershell
python -X utf8 .\sublime_patch.py --restore '.\artifacts\sublime_patch\本次目录\manifest.json'
```

恢复要求备份内容匹配原始哈希、当前目标匹配修补后哈希。若后来已经升级程序，拒绝用旧备份覆盖新版本。恢复的是本次修改前的完整文件：如果本次只修补自动更新，恢复后会保留此前已存在的购买提醒补丁。

写入前检查目标进程，写入时独占打开文件并再次比对哈希。写入/核验出错会在同一文件锁内恢复修改前内容并验证恢复；权限不足或文件被占用时直接报错，不自动提权，也不结束用户进程。

## 验证

```powershell
Set-Location sublime-text-patcher
python -X utf8 -m unittest -v
```

自动测试包括：三种真实 4200 状态；代码/数据地址移动；短/近跳转与相对位移；缺失或重复锚点；异常返回路径和栈平衡；损坏 PE、架构不符；重复运行；只补缺失项；预览不写入；输出副本/备份恢复；进程占用；来源被安装器替换；备份失败；写入失败后的恢复。

测试只使用临时文件和独立样本，不重写正在使用的安装程序。真实 4200 文件位于项目 `artifacts/sublime_4200`，这些参考文件不存在时，相应真实样本测试会标记跳过。

可选的 `validate_runtime.py` 是开发验收工具，另外需要 `frida`。它只允许操作预先建立且带便携 `Data` 目录的独立测试目录；正常打补丁不需要运行此工具。详细方法和本次结果见 `VALIDATION.md`。

## 许可证

本项目原创代码采用 [MIT License](LICENSE)，Copyright (c) 2026 YahooGoogle。第三方软件、商标和依赖的权利及许可不受本项目 MIT 授权影响。
