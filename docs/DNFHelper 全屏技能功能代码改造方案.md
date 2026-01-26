这是一个针对 `version-inject` 目录的完整代码修改方案。

鉴于 `version-inject/version_proxy.cpp` 已经包含了主要的注入逻辑、配置读取和线程管理，为了保持项目的整洁性和最小化依赖问题，建议**直接在 `version_proxy.cpp` 中扩展功能**，而不是新增文件。

该方案将严格遵循你提供的 CE 汇编逻辑（特别是 `0x90` 类型偏移和 `0x3CE4` 坐标偏移），确保功能与 CE 脚本一致。

### 修改概览

我们需要在 `version_proxy.cpp` 中完成以下 5 步修改：

1. **定义常量**：添加全屏技能专用的地址和偏移。
2. **扩展配置**：在 `HelperConfig` 结构体中增加技能代码、伤害、频率等字段，并实现 INI 读取。
3. **核心函数**：实现 `CallSimulateSkill` (模拟CALL) 和 `FullScreenSkillThread` (遍历逻辑)。
4. **按键监听**：在 `InputPollThread` 中增加 `Home` 键检测。
5. **初始化**：在 `InitializeHelper` 中启动全屏技能线程。

---

### 详细代码修改步骤

请按顺序在 `version-inject/version_proxy.cpp` 中插入或修改以下代码块。

#### 1. 添加常量定义 (插入到 `kPlayerBaseAddress` 附近)

注意：这里我们使用了你 CE 脚本中指定的偏移（如 `0x90` 和 `0x3CE4`），与文件中原有的偏移（如 `0x94`）区分开，防止影响旧功能。

```cpp
// ... 原有代码 ...
static const DWORD kPlayerBaseAddress = 0x01AC790C;

// [新增] 全屏技能相关常量
static const DWORD kSimulateCallAddress = 0x00879320; // 模拟CALL地址
static const DWORD kOffsetType_FS = 0x90;             // 全屏专用类型偏移 (CE脚本指定)
static const DWORD kOffsetPos_X_FS = 0x3CE4;          // 全屏专用X坐标 (CE脚本指定)
static const DWORD kOffsetPos_Y_FS = 0x3CE8;          // 全屏专用Y坐标 (CE脚本指定)
static const DWORD kDefaultSkillCode = 20022;
static const DWORD kDefaultSkillDamage = 13333;
static const DWORD kDefaultSkillInterval = 200;

// ... 原有代码 ...

```

#### 2. 扩展配置结构与全局变量 (修改 `HelperConfig` 和全局变量区域)

我们需要增加运行时变量来存储状态。

```cpp
// ... 原有全局变量 ...
static BOOL g_auto_transparent_enabled = FALSE;

// [新增] 全屏技能全局变量
static BOOL g_fullscreen_skill_enabled = FALSE; // 运行状态开关
static BOOL g_fullscreen_skill_active = FALSE;  // 逻辑激活开关 (由Home键控制)
static DWORD g_fullscreen_skill_code = kDefaultSkillCode;
static DWORD g_fullscreen_skill_damage = kDefaultSkillDamage;
static DWORD g_fullscreen_skill_interval = kDefaultSkillInterval;

// ...

// [修改] 扩展配置结构体
struct HelperConfig {
    // ... 原有字段 ...
    BOOL disable_attract_thread;
    BOOL enable_summon_doll;
    // [新增字段开始]
    BOOL enable_fullscreen_skill;      // 是否启用该功能模块
    DWORD fullscreen_skill_code;       // 技能代码
    DWORD fullscreen_skill_damage;     // 伤害
    DWORD fullscreen_skill_interval;   // 间隔(ms)
    // [新增字段结束]
    DWORD summon_monster_id;
    // ...
};

// [修改] GetDefaultHelperConfig 初始化新增字段
static HelperConfig GetDefaultHelperConfig() {
    HelperConfig config = {0};
    // ...
    config.enable_summon_doll = TRUE;
    // [新增]
    config.enable_fullscreen_skill = TRUE;
    config.fullscreen_skill_code = kDefaultSkillCode;
    config.fullscreen_skill_damage = kDefaultSkillDamage;
    config.fullscreen_skill_interval = kDefaultSkillInterval;
    // ...
    return config;
}

```

#### 3. 实现 INI 读取逻辑 (修改 `LoadHelperConfig`)

在 `LoadHelperConfig` 函数中添加读取逻辑，支持从 `[fullscreen]` 或 `[feature]` 字段读取。

```cpp
static BOOL LoadHelperConfig(const wchar_t* config_path, HelperConfig* config) {
    // ... 原有读取逻辑 ...
    
    // [新增] 读取全屏技能配置
    config->enable_fullscreen_skill = ReadIniBool(config_path, L"feature", L"enable_fullscreen_skill", config.enable_fullscreen_skill);
    // 也可以读取 [fullscreen] 节
    config->fullscreen_skill_code = ReadIniUInt32(config_path, L"fullscreen", L"skill_code", config.fullscreen_skill_code);
    config->fullscreen_skill_damage = ReadIniUInt32(config_path, L"fullscreen", L"skill_damage", config.fullscreen_skill_damage);
    config->fullscreen_skill_interval = ReadIniUInt32(config_path, L"fullscreen", L"skill_interval", config.fullscreen_skill_interval);

    // ...
    return TRUE;
}

```

#### 4. 实现核心功能函数 (插入到 `TrySummonDoll` 函数之后)

这是最关键的部分，包含了内联汇编 CALL 和遍历逻辑。

```cpp
// [新增] 执行模拟技能 CALL (对应 CE 脚本中的 code 段)
static void CallSimulateSkill(DWORD objAddr, int x, int y, int z, int damage, int skillCode) {
    DWORD playerBasePtr = ReadDwordSafely(kPlayerBaseAddress);
    if (playerBasePtr == 0) return;
    DWORD playerObj = ReadDwordSafely(playerBasePtr); // 取出人物对象 [1AC790C]
    if (playerObj == 0) return;

    DWORD callAddr = kSimulateCallAddress;

    __asm {
        pushad
        push 0
        push 0
        push 0
        push 0
        push 0
        push 0
        push 4
        push 0
        push 0
        push z              // Z轴
        push y              // Y坐标 [ecx+3CE8]
        push x              // X坐标 [ecx+3CE4]
        push damage         // 伤害
        push skillCode      // 技能代码
        push playerObj      // 人物对象 ecx
        mov eax, callAddr
        call eax
        popad
    }
}

// [新增] 全屏技能遍历线程
static DWORD WINAPI FullScreenSkillThread(LPVOID param) {
    UNREFERENCED_PARAMETER(param);
    
    while (TRUE) {
        // 1. 检查开关
        if (!g_fullscreen_skill_active) {
            Sleep(200);
            continue;
        }

        // 2. 获取基础指针
        DWORD playerPtr = ReadDwordSafely(kPlayerBaseAddress);
        if (playerPtr == 0) {
            Sleep(1000); continue; 
        }
        DWORD playerObj = ReadDwordSafely(playerPtr);
        if (playerObj == 0) {
            Sleep(1000); continue;
        }

        // 3. 检查地图 (进图判断)
        // CE: mov eax,[eax+b8] -> cmp eax,0
        DWORD mapPtr = ReadDwordSafely(playerObj + kMapOffset); // 0xB8
        if (mapPtr == 0) {
            Sleep(500); continue; 
        }

        // 4. 获取遍历范围
        // CE: mov [ebp-4],ebx (Start); mov [ebp-8],ebx (End)
        DWORD startPtr = ReadDwordSafely(mapPtr + kMapStartOffset); // 0xB0
        DWORD endPtr = ReadDwordSafely(mapPtr + kMapEndOffset);     // 0xB4

        if (startPtr == 0 || endPtr == 0 || startPtr >= endPtr) {
            Sleep(200); continue;
        }

        // 5. 遍历对象
        for (DWORD curr = startPtr; curr < endPtr; curr += 4) {
            DWORD objAddr = ReadDwordSafely(curr);
            if (objAddr == 0) continue;

            // 过滤阵营 (跳过自己人)
            // CE: cmp [ecx+644], 0
            int faction = (int)ReadDwordSafely(objAddr + kFactionOffset);
            if (faction == 0) continue;

            // 过滤类型 (怪物=529, APC=273)
            // CE: cmp [ecx+90], 529
            int type = (int)ReadDwordSafely(objAddr + kOffsetType_FS); // 注意使用 0x90
            if (type == 529 || type == 273) {
                // 读取坐标
                int x = (int)ReadFloatSafely(objAddr + kOffsetPos_X_FS); // 0x3CE4
                int y = (int)ReadFloatSafely(objAddr + kOffsetPos_Y_FS); // 0x3CE8
                int z = 0; // CE 脚本写死为 0

                // 执行攻击
                CallSimulateSkill(objAddr, x, y, z, g_fullscreen_skill_damage, g_fullscreen_skill_code);
            }
        }

        // 6. 频率控制
        Sleep(g_fullscreen_skill_interval);
    }
    return 0;
}

// [新增] 切换全屏技能开关
static void ToggleFullScreenSkill() {
    g_fullscreen_skill_active = !g_fullscreen_skill_active;
    if (g_fullscreen_skill_active) {
        AnnouncePlaceholder(L"全屏技能 [开启]");
        LogEvent("INFO", "fullscreen_skill", "activated");
    } else {
        AnnouncePlaceholder(L"全屏技能 [关闭]");
        LogEvent("INFO", "fullscreen_skill", "deactivated");
    }
}

```

#### 5. 修改按键轮询线程 (修改 `InputPollThread`)

在按键循环中加入 Home 键检测。

```cpp
static DWORD WINAPI InputPollThread(LPVOID param) {
    // ... 
    bool key0_last_down = false;
    // [新增]
    bool home_last_down = false;

    while (TRUE) {
        // ... (获取前景窗口 pid) ...
        if (foreground_pid == self_pid) {
            // ... (获取 F2, F3 等状态) ...
            
            // [新增] 获取 Home 键状态
            SHORT home_state = GetAsyncKeyState(VK_HOME);
            bool home_down = (home_state & 0x8000) != 0;

            // ... (原有按键处理) ...

            // [新增] 处理 Home 键
            if (home_down && !home_last_down) {
                ToggleFullScreenSkill();
            }

            // ... (更新 last_down 状态) ...
            home_last_down = home_down;
        } else {
            // ... (重置其他键) ...
            home_last_down = false;
        }
        Sleep(kInputPollIntervalMs);
    }
    return 0;
}

```

#### 6. 修改应用配置与初始化 (修改 `ApplyRuntimeConfig` 和 `InitializeHelper`)

最后，确保配置被应用，并且线程被创建。

```cpp
// 修改 ApplyRuntimeConfig
static void ApplyRuntimeConfig(const HelperConfig& config) {
    // ...
    // [新增]
    g_fullscreen_skill_enabled = config.enable_fullscreen_skill;
    g_fullscreen_skill_code = config.fullscreen_skill_code;
    g_fullscreen_skill_damage = config.fullscreen_skill_damage;
    g_fullscreen_skill_interval = config.fullscreen_skill_interval;
}

// 修改 InitializeHelper
static void InitializeHelper(const wchar_t* output_directory, const HelperConfig& config) {
    // ...
    
    // [新增] 启动全屏技能线程
    if (config.enable_fullscreen_skill) {
        HANDLE fs_thread = CreateThread(NULL, 0, FullScreenSkillThread, NULL, 0, NULL);
        if (fs_thread != NULL) {
            CloseHandle(fs_thread);
            LogEvent("INFO", "fullscreen_thread", "started");
        } else {
            LogEventWithError("fullscreen_thread", "create_failed", GetLastError());
        }
    } else {
        LogEvent("INFO", "fullscreen_thread", "disabled_by_config");
    }
}

```

---

### INI 配置文件示例 (`game_helper.ini`)

编译并运行后，你需要在 `game_helper.ini` 中添加或修改以下内容以生效：

```ini
[feature]
; 开启全屏技能功能模块
enable_fullscreen_skill=true

[fullscreen]
; 技能代码 (例如 20022)
skill_code=20022
; 技能伤害
skill_damage=13333
; 施放间隔 (毫秒)
skill_interval=200

```