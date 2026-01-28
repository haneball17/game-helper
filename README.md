# Game Helper 项目说明

## 简介
本仓库用于研究与实践 Windows 下的注入、内存读写与 GUI 状态管理。当前实现以 **APC 注入**为入口，配套 **命令行启动器** 与 **WPF GUI 管理界面**，支持多进程状态读取与运行时控制。

> 说明：本项目面向学习与研究用途，代码与配置需结合实际环境使用。

## 主要目录与项目

### HelperStart（`/HelperStart`）
**角色**：启动与注入控制（无 GUI / 带 GUI 两种入口）。

**当前特性**
- `HelperStart.exe`：默认不启动 GUI。
- `HelperStart_GUI.exe`：默认启动 GUI。
- 读取 `injector.ini`，负责目标进程监控与 DLL 载入。

**适用场景**
需要无界面或带界面的注入启动流程时使用。

---

### version-inject（`/version-inject`）
**角色**：核心功能 DLL（APC 注入载入），提供运行时功能实现与状态共享。

**当前特性**
- APC 注入：由 `HelperStart` 使用 `QueueUserAPC` 完成注入加载。
- `game_helper.ini` 配置支持 **热重载（默认 1000ms）**。
- 状态共享内存（按 PID）：`GameHelperStatus_{pid}`（V3）。
- 控制共享内存（按 PID）：`GameHelperControl_{pid}`（V1）。
- 支持多进程并行、热键控制、全屏技能/攻击/吸怪/透明/召唤等功能。

**构建建议**
目标为 **x86 (Win32)**，以匹配 32 位游戏进程。

---

### GameHelperGUI（`/tools/gui/GameHelperGUI`）
**角色**：多进程 GUI 管理界面（WPF / .NET 6）。

**当前特性**
- 首页展示多 PID 状态（含角色名）。
- 运行时控制：对单个进程进行功能“强制开 / 强制关 / 跟随配置”。
- 热键绑定页、参数配置页。
- 人偶召唤为 **按钮触发（单次召唤）**。
- 通过共享内存读取状态、写入控制指令。

**构建建议**
使用 `net6.0-windows`，可发布为单文件 `win-x64`。

---

## 关键配置文件
- `game_helper.ini`：功能与热键配置（DLL 侧）。
- `injector.ini`：HelperStart 启动配置。
- `tools/gui/GameHelperGUI/config/params.json`：GUI 参数元数据。

## 技术概览
- 技术栈：C++17/20（DLL）、C#/.NET 6 WPF（GUI）。
- 目标架构：DLL 为 **x86**，需与目标进程位数一致。
- 注入类型：APC 注入（`QueueUserAPC`）。
- 通信方式：共享内存 Status/Control 通道（按 PID）。
- 热重载机制：`game_helper.ini` 轮询 1000ms，支持运行时刷新部分参数。
- 多开行为：仅前台进程响应热键。
- 构建环境：Visual Studio 2019/2022。

## 技术细节（可选了解）
- DLL 载入方式：注入器远程写入 DLL 路径，并对目标线程入队 APC。
- 线程模型：输入轮询、全屏攻击守护、吸怪、全屏技能、共享内存写入、控制通道读取、配置热重载。
- 运行时日志：JSONL 格式，默认输出到 DLL/执行目录（可配置）。
- 配置文件/参数表：`game_helper.ini`（运行时配置）、`params.json`（GUI 参数元数据）。

## 构建与运行建议（简要）
1. **version-inject**：以 **Win32/x86** 构建，输出 `GameHelper.dll`（与游戏进程位数一致）。
2. **HelperStart**：构建 `HelperStart.exe` / `HelperStart_GUI.exe`，用于启动注入流程。
3. **GameHelperGUI**：`net6.0-windows`，可发布为 `win-x64` 单文件。

> 配置读取路径：DLL 会优先从 **DLL 所在目录**读取 `game_helper.ini`，失败时再从 **目标进程 exe 目录**读取。

## 运行流程（概览）
1. 编译 `version-inject`（生成 `GameHelper.dll`）。
2. 启动 `HelperStart` 或 `HelperStart_GUI`。
3. 打开 `GameHelperGUI` 进行状态查看与运行时控制。

## 运行时控制与热重载
### 控制通道（GUI → DLL）
- 状态共享内存（只读）：`GameHelperStatus_{pid}`（V3）
- 控制共享内存（写入）：`GameHelperControl_{pid}`（V1）

GUI 可对单个进程做“**强制开启 / 强制关闭 / 跟随配置**”，并支持“**人偶单次召唤**”按钮触发。

### 热重载（DLL 侧）
- `game_helper.ini` 默认 **1000ms** 轮询检测变更
- 变更后立即刷新运行时参数（热键/技能/吸怪参数等）
- 部分配置仅在启动阶段生效（如某些线程开关、抹头/安全模式等）

## 兼容性提示
- 偏移/基址与游戏版本强相关，游戏更新可能导致功能失效。
- 多开时仅前台窗口进程响应热键，避免冲突。

---

如需补充更详细的构建指令、参数字段说明或开发约定，可在 `docs/` 目录中扩展文档。
