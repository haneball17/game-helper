# APC 注入器多 DLL 配置化改造方案

## 1. 现状确认

- `HelperStart` 已是 APC 注入实现，核心流程使用 `QueueUserAPC`。
- 当前配置只支持单个 `dll_path`，且注入流程按单 DLL 设计。
- `injector.ini` 已用于加载配置与日志开关，支持 `--config` 参数。

## 2. 目标

- APC 注入器支持单 DLL 与多 DLL 注入。
- 采用配置文件方式选择 DLL：
  - 默认 `./GameHelper.dll`（与注入器同目录）。
  - 支持相对路径，统一基于注入器目录解析。
- 兼容旧字段 `dll_path`，不破坏已有使用方式。

## 3. 范围与非目标

### 3.1 范围

- 仅改造 `HelperStart/HelperStart/HelperStart.cpp`。
- 扩展 `injector.ini` 配置项说明与示例。

### 3.2 非目标

- 不修改 `InjectDll`（MFC 注入器）。
- 不引入第三方依赖或额外注入方式。

## 4. 配置设计

### 4.1 配置位置与读取

- 默认读取：`<注入器目录>/injector.ini`。
- 可选：命令行 `--config <path>` 覆盖默认路径。

### 4.2 DLL 字段设计（兼容单/多）

在 `[target]` 中新增 `dll_paths`：

```ini
[target]
process_name=dnf.exe
dll_path=./GameHelper.dll
dll_paths=./GameHelper.dll;./MinHookCore.dll;./ExtraHook.dll
```

### 4.3 解析规则

1. `dll_paths` 非空时优先使用；
2. `dll_paths` 为空时回退到 `dll_path`；
3. 两者都为空时默认 `./GameHelper.dll`；
4. `dll_paths` 以 `;` 分隔，忽略空项并去重；
5. 相对路径基于注入器目录归一化为绝对路径。

## 5. 注入流程设计

### 5.1 单次注入（单进程）

对每个 DLL 顺序执行：

1. 远程写入 DLL 路径
2. `QueueUserAPC` 入队
3. 模块加载校验
4. 写入日志（单 DLL 结果）

### 5.2 监控模式（watch_mode）

对每个新进程：

- 逐 DLL 检查是否已加载；
- 未加载则执行注入；
- 仅当 **全部 DLL 加载成功** 才将该 PID 标记为完成。

### 5.3 结果判定

- 单 DLL 成功：`module_check` 返回 loaded。
- 多 DLL 成功：所有 DLL 都成功时才视为整体成功。

## 6. 关键实现点

1. `InjectorConfig` 新增 `std::vector<std::wstring> dll_paths`。
2. 增加 `SplitAndTrim`，解析 `dll_paths` 并去重。
3. 将 `InjectByApc`/`InjectProcessWithRetries` 改为接收单个 DLL
   路径参数，循环调用即可。
4. `LogExtras` 中的 `dll_path` 始终记录当前注入 DLL。
5. 默认值逻辑与路径归一化复用现有 `NormalizePath()`。

## 7. 日志与可观测性

延续 JSON Lines 日志格式，建议补充事件：

- `multi_dll_start`：开始处理 DLL 列表
- `dll_inject_result`：单 DLL 结果
- `multi_dll_result`：整体结果

至少保证 `dll_path` 在每条注入相关日志中可追溯。

## 8. 风险与边界

- APC 依赖线程进入 alertable 状态，可能“入队成功但未执行”。
- DLL 路径过长或包含异常字符可能导致加载失败。
- 多 DLL 顺序依赖（如 MinHook）需要在配置中保证顺序。

## 9. 验证与回归

1. 使用单 DLL 配置，确认行为与改造前一致。
2. 使用多 DLL 配置，检查每个 DLL 的加载日志与结果。
3. 验证相对路径解析与默认 `GameHelper.dll` 回退逻辑。

## 10. 变更清单

- 修改：`HelperStart/HelperStart/HelperStart.cpp`
  - 扩展配置解析
  - 多 DLL 注入循环
  - 日志与结果汇总
- 更新：`HelperStart/HelperStart/injector.ini` 示例（可选）

## 11. 规范确认

- 代码命名使用英文，注释使用中文。
- 该规范已记录于 `AGENTS.md`。
