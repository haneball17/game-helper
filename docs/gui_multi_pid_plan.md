# 多 PID + 角色名显示 改造方案

## 0. 目标
- 共享内存按 **PID 分离**，GUI 可同时显示多个进程状态。
- 读取角色名（基址 `0x1AC790C`，偏移 `0x258`）。
- GUI 标题显示当前选中角色名与 PID。

---

## 1) DLL 侧改造（version-inject）

### 1.1 共享内存按 PID 分离
- 命名规则：`Global\\GameHelperStatus_{pid}`
- 每个进程只写自己的共享内存，避免多进程覆盖。

### 1.2 共享内存结构升级（V2）
新增角色名字段并升级版本号。

```
#pragma pack(push, 1)
struct HelperStatusV2 {
  DWORD version;               // 2
  DWORD size;                  // sizeof(HelperStatusV2)
  ULONGLONG last_tick_ms;
  DWORD pid;
  BOOL process_alive;

  BOOL auto_transparent_enabled;
  BOOL fullscreen_attack_target;
  BOOL fullscreen_attack_patch_on;
  int attract_mode;
  BOOL attract_positive;
  BOOL summon_enabled;
  ULONGLONG summon_last_tick;

  BOOL fullscreen_skill_enabled;
  BOOL fullscreen_skill_active;
  DWORD fullscreen_skill_hotkey;

  wchar_t player_name[32];     // UTF-16 固定长度
};
#pragma pack(pop)
```

### 1.3 读取角色名
- 基址：`0x01AC790C`
- 偏移：`0x258`
- 读取 `player_ptr + 0x258` 处 `wchar_t` 数组（最多 31 字 + 终止符）
- 读取失败或为空则写空字符串

### 1.4 写入共享内存
- `SharedMemoryWriterThread` 中填充 `player_name`
- 版本号升级为 **2**

---

## 2) GUI 侧改造（多 PID）

### 2.1 PID 枚举与读取
- 枚举 `dnf.exe` 进程
- 对每个 PID 尝试打开 `Global\\GameHelperStatus_{pid}`
- 读取成功显示在线状态，否则显示离线

### 2.2 共享内存结构 V2
```
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct HelperStatusV2 {
  public uint Version;
  public uint Size;
  public ulong LastTickMs;
  public uint Pid;
  public int ProcessAlive;
  public int AutoTransparentEnabled;
  public int FullscreenAttackTarget;
  public int FullscreenAttackPatchOn;
  public int AttractMode;
  public int AttractPositive;
  public int SummonEnabled;
  public ulong SummonLastTick;
  public int FullscreenSkillEnabled;
  public int FullscreenSkillActive;
  public uint FullscreenSkillHotkey;

  [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
  public char[] PlayerName;
}
```

角色名解析：
```
string name = new string(raw.PlayerName).TrimEnd('\\0');
```

### 2.3 首页 UI（多 PID）
- 左侧实例列表：PID / 角色名 / 状态 / 更新时间 / 全屏攻击
- 右侧详情面板：显示选中实例全部状态
- 顶部：在线数量、离线数量

### 2.4 GUI 标题
选中某实例时：
```
Game Helper GUI - {角色名} (PID xxxx)
```
无选中或名称为空则显示默认标题。

---

## 3) 版本兼容
- version 从 1 升到 2
- GUI 若 `version/size` 不匹配：显示“版本不兼容”

---

## 4) 配置页与热键页
- 仍为全局配置，不区分 PID
- 页面提示：“配置为全局配置，保存后重启生效”

---

## 5) 涉及文件（预期）

### DLL
- `version-inject/version_proxy.cpp`

### GUI
- `tools/gui/GameHelperGUI/Models/*`
- `tools/gui/GameHelperGUI/Services/SharedMemoryStatusReader.cs`
- `tools/gui/GameHelperGUI/ViewModels/MainViewModel.cs`
- `tools/gui/GameHelperGUI/MainWindow.xaml`

