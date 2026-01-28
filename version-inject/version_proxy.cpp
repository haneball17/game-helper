#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>
#include <stdlib.h>
#include <intrin.h>

#include "version_exports.h"

// LDR 断链与抹头（可选）支持，使用私有结构以规避 SDK 结构差异。
typedef struct _PEB_LDR_DATA_PRIVATE {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_PRIVATE, *PPEB_LDR_DATA_PRIVATE;

typedef struct _LDR_DATA_TABLE_ENTRY_PRIVATE {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
} LDR_DATA_TABLE_ENTRY_PRIVATE, *PLDR_DATA_TABLE_ENTRY_PRIVATE;

#pragma pack(push, 1)
// GUI 共享内存状态结构体（V3）
typedef struct _HelperStatusV2 {
	DWORD version;
	DWORD size;
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
	BOOL hotkey_enabled;
	wchar_t player_name[32];
} HelperStatusV2;

// GUI 共享内存控制结构体（V1）
typedef struct _HelperControlV1 {
	DWORD version;
	DWORD size;
	DWORD pid;
	DWORD last_update_tick;
	BYTE fullscreen_attack;
	BYTE fullscreen_skill;
	BYTE auto_transparent;
	BYTE attract;
	BYTE hotkey_enabled;
	BYTE reserved[3];
	DWORD summon_sequence;
} HelperControlV1;
#pragma pack(pop)

static const LONG kHideModuleResultNotAttempted = -1;
static const LONG kHideModuleResultOk = 0;
static const LONG kHideModuleResultLdrMissing = 1;
static const LONG kHideModuleResultNotFound = 2;
static volatile LONG g_hide_module_result = kHideModuleResultNotAttempted;

static PPEB_LDR_DATA_PRIVATE GetPebLdr() {
#ifdef _WIN64
	PBYTE peb = reinterpret_cast<PBYTE>(__readgsqword(0x60));
	if (peb == NULL) {
		return NULL;
	}
	return reinterpret_cast<PPEB_LDR_DATA_PRIVATE>(*(reinterpret_cast<PVOID*>(peb + 0x18)));
#else
	PBYTE peb = reinterpret_cast<PBYTE>(__readfsdword(0x30));
	if (peb == NULL) {
		return NULL;
	}
	return reinterpret_cast<PPEB_LDR_DATA_PRIVATE>(*(reinterpret_cast<PVOID*>(peb + 0x0C)));
#endif
}

static LONG HideModule(HMODULE module) {
	if (module == NULL) {
		return kHideModuleResultNotFound;
	}
	PPEB_LDR_DATA_PRIVATE ldr = GetPebLdr();
	if (ldr == NULL) {
		return kHideModuleResultLdrMissing;
	}
	LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
	for (LIST_ENTRY* entry = head->Flink; entry != head; entry = entry->Flink) {
		PLDR_DATA_TABLE_ENTRY_PRIVATE data = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY_PRIVATE, InLoadOrderLinks);
		if (data->DllBase == module) {
			// 将自身从三条链表中断开，降低被模块枚举发现的概率。
			data->InLoadOrderLinks.Blink->Flink = data->InLoadOrderLinks.Flink;
			data->InLoadOrderLinks.Flink->Blink = data->InLoadOrderLinks.Blink;
			data->InMemoryOrderLinks.Blink->Flink = data->InMemoryOrderLinks.Flink;
			data->InMemoryOrderLinks.Flink->Blink = data->InMemoryOrderLinks.Blink;
			data->InInitializationOrderLinks.Blink->Flink = data->InInitializationOrderLinks.Flink;
			data->InInitializationOrderLinks.Flink->Blink = data->InInitializationOrderLinks.Blink;
			return kHideModuleResultOk;
		}
	}
	return kHideModuleResultNotFound;
}

static BOOL WipeModuleHeader(HMODULE module) {
	if (module == NULL) {
		return FALSE;
	}
	const SIZE_T header_size = 4096;
	DWORD old_protect = 0;
	if (!VirtualProtect(module, header_size, PAGE_EXECUTE_READWRITE, &old_protect)) {
		return FALSE;
	}
	SecureZeroMemory(module, header_size);
	DWORD ignored = 0;
	VirtualProtect(module, header_size, old_protect, &ignored);
	return TRUE;
}

// 透明功能的绝对地址配置（x86）。

// 人物基址
static const DWORD kPlayerBaseAddress = 0x01AC790C;

// 全屏攻击补丁地址
static const DWORD kFullScreenAttackPatchAddress = 0x00825282;

// 透明调用地址
static const DWORD kTransparentCallAddress = 0x011499E0;

// 召唤人偶调用参数（x86）
static const DWORD kSummonCallParam = 0x0119FEF0;
// 召唤函数偏移
static const DWORD kSummonFunctionOffset = 0x354;
// 召唤位置参数
static const DWORD kSummonPositionParam = 0x08AE;
// 召唤默认配置
static const DWORD kSummonDefaultMonsterId = 25301;
static const DWORD kSummonDefaultLevel = 70;
static const DWORD kSummonDefaultCooldownMs = 0;
// 全屏技能模拟调用地址
static const DWORD kFullscreenSkillCallAddress = 0x00879320;
// 全屏技能专用偏移（对应 CE 脚本）
static const DWORD kFullscreenSkillTypeOffset = 0x90;
static const DWORD kFullscreenSkillPosXOffset = 0x3CE4;
static const DWORD kFullscreenSkillPosYOffset = 0x3CE8;
// 全屏技能默认配置
static const DWORD kFullscreenSkillDefaultCode = 20022;
static const DWORD kFullscreenSkillDefaultDamage = 13333;
static const DWORD kFullscreenSkillDefaultIntervalMs = 1000;
static const DWORD kFullscreenSkillDefaultHotkey = VK_HOME;
// 默认热键配置
static const DWORD kHotkeyToggleTransparent = VK_F2;
static const DWORD kHotkeyToggleFullscreenAttack = VK_F3;
static const DWORD kHotkeySummonDoll = VK_F12;
static const DWORD kHotkeyAttractMode1 = '7';
static const DWORD kHotkeyAttractMode2 = '8';
static const DWORD kHotkeyAttractMode3 = '9';
static const DWORD kHotkeyAttractMode4 = '0';
static const DWORD kHotkeyToggleAttractDirection = VK_OEM_MINUS;

// // 0625人物基址
// static const DWORD kPlayerBaseAddress = 0x01AB7CDC;

// // 0625透明调用地址
// static const DWORD kTransparentCallAddress = 0x0113F400;

// // 0625全屏攻击补丁地址
// static const DWORD kFullScreenAttackPatchAddress = 0x0081A892;

// 透明循环间隔
static const DWORD kTransparentLoopIntervalMs = 4000;

// 全屏攻击补丁大小
static const SIZE_T kFullscreenAttackPatchSize = 2;

// 全屏攻击补丁关闭
static const BYTE kFullscreenAttackPatchOffA[kFullscreenAttackPatchSize] = {0x30, 0xC0};
static const BYTE kFullscreenAttackPatchOffB[kFullscreenAttackPatchSize] = {0x32, 0xC0};

// 全屏攻击补丁开启
static const BYTE kFullscreenAttackPatchOn[kFullscreenAttackPatchSize] = {0xB0, 0x01};

// 全屏攻击轮询间隔默认值
static const DWORD kFullscreenAttackPollIntervalMs = 1000;

// 共享内存状态通道（按 PID 区分）
static const wchar_t kSharedMemoryNamePrefixGlobal[] = L"Global\\GameHelperStatus_";
static const wchar_t kSharedMemoryNamePrefixLocal[] = L"Local\\GameHelperStatus_";
static const DWORD kSharedMemoryVersion = 3;
static const DWORD kSharedMemoryWriteIntervalMs = 500;
static const wchar_t kControlMemoryNamePrefixGlobal[] = L"Global\\GameHelperControl_";
static const wchar_t kControlMemoryNamePrefixLocal[] = L"Local\\GameHelperControl_";
static const DWORD kControlMemoryVersion = 1;
static const DWORD kControlMemoryReadIntervalMs = 200;

// 输入轮询间隔
static const DWORD kInputPollIntervalMs = 30;
// 配置热重载间隔
static const DWORD kConfigReloadIntervalMs = 1000;

// 地图与对象偏移
static const DWORD kMapOffset = 0xB8;
static const DWORD kMapStartOffset = 0xB0;
static const DWORD kMapEndOffset = 0xB4;
// 类型偏移
static const DWORD kTypeOffset = 0x94;
// 位置 X 偏移
static const DWORD kPositionXOffset = 0x18C;
// 位置 Y 偏移
static const DWORD kPositionYOffset = 0x190;
// 角色名偏移
static const DWORD kPlayerNameOffset = 0x258;
// 角色名二级偏移
static const DWORD kPlayerNameSecondOffset = 0x0;
// 角色名最大字符数
static const size_t kPlayerNameMaxChars = 32;
// 角色名编码模式
static const int kPlayerNameEncodingAuto = 0;
static const int kPlayerNameEncodingUtf16 = 1;
static const int kPlayerNameEncodingUtf8 = 2;
static const int kPlayerNameEncodingAnsi = 3;
// 对象坐标指针与子偏移
static const DWORD kObjectPositionBaseOffset = 0xA8;
static const DWORD kObjectPositionXOffset = 0x0C;
static const DWORD kObjectPositionYOffset = 0x10;
// 阵营偏移
static const DWORD kFactionOffset = 0x644;
static const int kTypeItem = 289;
static const int kTypeMonster = 529;
static const int kTypeApc = 273;
static const int kMaxObjectCount = 8192;
static const DWORD kAttractLoopIntervalMs = 20;
static const DWORD kAttractIdleIntervalMs = 200;
static const int kAttractModeOff = 0;
static const int kAttractModeAllToPlayer = 1;
static const int kAttractModeMonsterOffset80 = 2;
static const int kAttractModeMonsterOffset150 = 3;
static const int kAttractModeMonsterOffset300 = 4;
static const int kAttractModeMax = 4;
// 怪物 X 坐标偏移默认配置（索引为配置模式）
static const float kDefaultMonsterXOffsetByMode[kAttractModeMax + 1] = {0.0f, 0.0f, 80.0f, 150.0f, 250.0f};
static float g_monster_x_offset_by_mode[kAttractModeMax + 1] = {0.0f, 0.0f, 80.0f, 150.0f, 250.0f};

static const BYTE kControlFollow = 0;
static const BYTE kControlForceOff = 1;
static const BYTE kControlForceOn = 2;

static BOOL g_auto_transparent_enabled = FALSE;
static BOOL g_hotkey_enabled = TRUE;
// 自动吸怪配置（0 为关闭）
static int g_attract_mode = kAttractModeOff;
static int g_attract_last_mode = kAttractModeAllToPlayer;
// 吸怪方向开关（TRUE=正向，FALSE=负向）
static BOOL g_attract_positive_enabled = FALSE;
// 召唤人偶配置（由配置文件覆盖）
static BOOL g_summon_enabled = TRUE;
static DWORD g_summon_monster_id = kSummonDefaultMonsterId;
static DWORD g_summon_level = kSummonDefaultLevel;
static DWORD g_summon_cooldown_ms = kSummonDefaultCooldownMs;
static ULONGLONG g_summon_last_tick = 0;
// 全屏技能运行时状态
static BOOL g_fullscreen_skill_enabled = FALSE;
static BOOL g_fullscreen_skill_active = FALSE;
static DWORD g_fullscreen_skill_code = kFullscreenSkillDefaultCode;
static DWORD g_fullscreen_skill_damage = kFullscreenSkillDefaultDamage;
static DWORD g_fullscreen_skill_interval_ms = kFullscreenSkillDefaultIntervalMs;
static DWORD g_fullscreen_skill_hotkey = kFullscreenSkillDefaultHotkey;
static DWORD g_hotkey_toggle_transparent = kHotkeyToggleTransparent;
static DWORD g_hotkey_toggle_fullscreen_attack = kHotkeyToggleFullscreenAttack;
static DWORD g_hotkey_summon_doll = kHotkeySummonDoll;
static DWORD g_hotkey_attract_mode1 = kHotkeyAttractMode1;
static DWORD g_hotkey_attract_mode2 = kHotkeyAttractMode2;
static DWORD g_hotkey_attract_mode3 = kHotkeyAttractMode3;
static DWORD g_hotkey_attract_mode4 = kHotkeyAttractMode4;
static DWORD g_hotkey_toggle_attract_direction = kHotkeyToggleAttractDirection;
static int g_player_name_encoding = kPlayerNameEncodingAuto;
// 透明线程
static HANDLE g_transparent_thread = NULL;
static BOOL g_character_transparent = FALSE;
static BYTE g_fullscreen_attack_off_patch[kFullscreenAttackPatchSize] = {0};
static BOOL g_fullscreen_attack_off_patch_set = FALSE;
// 全屏攻击目标状态与轮询间隔
static volatile LONG g_fullscreen_attack_target_enabled = 0;
static DWORD g_fullscreen_attack_poll_interval_ms = kFullscreenAttackPollIntervalMs;
static DWORD g_control_last_summon_sequence = 0;
static BYTE g_control_fullscreen_attack = kControlFollow;
static BYTE g_control_fullscreen_skill = kControlFollow;
static BYTE g_control_auto_transparent = kControlFollow;
static BYTE g_control_attract = kControlFollow;
static BYTE g_control_hotkey_enabled = kControlFollow;
// 共享内存写入句柄
static HANDLE g_shared_memory_handle = NULL;
static void* g_shared_memory_view = NULL;
static wchar_t g_shared_memory_name[64] = {0};
static volatile LONG g_shared_memory_ready_logged = 0;
static volatile LONG g_shared_memory_failed_logged = 0;
static HANDLE g_control_memory_handle = NULL;
static void* g_control_memory_view = NULL;
static wchar_t g_control_memory_name[64] = {0};
static volatile LONG g_control_memory_ready_logged = 0;
static volatile LONG g_control_memory_failed_logged = 0;
static const wchar_t kLogFileName[] = L"game_helper.jsonl";
static const wchar_t kConfigFileName[] = L"game_helper.ini";
static HMODULE g_self_module = NULL;

static CRITICAL_SECTION g_log_lock;
static BOOL g_log_lock_ready = FALSE;
static HANDLE g_log_file = INVALID_HANDLE_VALUE;
static BOOL g_log_ready = FALSE;
static wchar_t g_log_path[MAX_PATH] = {0};

static BOOL GetExeDirectory(wchar_t* directory_path, size_t directory_capacity) {
	wchar_t exe_path[MAX_PATH] = {0};
	DWORD length = GetModuleFileNameW(NULL, exe_path, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		return FALSE;
	}
	wchar_t* last_slash = wcsrchr(exe_path, L'\\');
	if (last_slash == NULL) {
		last_slash = wcsrchr(exe_path, L'/');
	}
	if (last_slash == NULL) {
		return FALSE;
	}
	*(last_slash + 1) = L'\0';
	return wcscpy_s(directory_path, directory_capacity, exe_path) == 0;
}

static BOOL GetModuleDirectory(HMODULE module, wchar_t* directory_path, size_t directory_capacity) {
	if (module == NULL) {
		return FALSE;
	}
	wchar_t module_path[MAX_PATH] = {0};
	DWORD length = GetModuleFileNameW(module, module_path, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		return FALSE;
	}
	wchar_t* last_slash = wcsrchr(module_path, L'\\');
	if (last_slash == NULL) {
		last_slash = wcsrchr(module_path, L'/');
	}
	if (last_slash == NULL) {
		return FALSE;
	}
	*(last_slash + 1) = L'\0';
	return wcscpy_s(directory_path, directory_capacity, module_path) == 0;
}

static BOOL GetModuleBaseName(HMODULE module, wchar_t* output, size_t output_capacity) {
	if (module == NULL || output == NULL || output_capacity == 0) {
		return FALSE;
	}
	wchar_t module_path[MAX_PATH] = {0};
	DWORD length = GetModuleFileNameW(module, module_path, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		return FALSE;
	}
	const wchar_t* file_name = wcsrchr(module_path, L'\\');
	if (file_name == NULL) {
		file_name = wcsrchr(module_path, L'/');
	}
	file_name = (file_name != NULL) ? (file_name + 1) : module_path;
	if (wcscpy_s(output, output_capacity, file_name) != 0) {
		return FALSE;
	}
	wchar_t* dot = wcsrchr(output, L'.');
	if (dot != NULL) {
		*dot = L'\0';
	}
	return output[0] != L'\0';
}

static BOOL BuildLogPath(const wchar_t* directory_path, wchar_t* output, size_t output_capacity) {
	if (directory_path == NULL || directory_path[0] == L'\0') {
		return FALSE;
	}
	if (wcscpy_s(output, output_capacity, directory_path) != 0) {
		return FALSE;
	}
	size_t length = wcslen(output);
	if (length == 0 || length >= output_capacity - 1) {
		return FALSE;
	}
	wchar_t last = output[length - 1];
	if (last != L'\\' && last != L'/') {
		if (wcscat_s(output, output_capacity, L"\\") != 0) {
			return FALSE;
		}
	}
	return wcscat_s(output, output_capacity, kLogFileName) == 0;
}

static BOOL BuildConfigPath(const wchar_t* directory_path, wchar_t* output, size_t output_capacity) {
	if (directory_path == NULL || directory_path[0] == L'\0') {
		return FALSE;
	}
	if (wcscpy_s(output, output_capacity, directory_path) != 0) {
		return FALSE;
	}
	size_t length = wcslen(output);
	if (length == 0 || length >= output_capacity - 1) {
		return FALSE;
	}
	wchar_t last = output[length - 1];
	if (last != L'\\' && last != L'/') {
		if (wcscat_s(output, output_capacity, L"\\") != 0) {
			return FALSE;
		}
	}
	return wcscat_s(output, output_capacity, kConfigFileName) == 0;
}

static BOOL BuildSuccessFilePath(const wchar_t* directory_path,
	const wchar_t* dll_base_name,
	DWORD pid,
	wchar_t* output,
	size_t output_capacity) {
	if (directory_path == NULL || directory_path[0] == L'\0' ||
		dll_base_name == NULL || dll_base_name[0] == L'\0') {
		return FALSE;
	}
	if (wcscpy_s(output, output_capacity, directory_path) != 0) {
		return FALSE;
	}
	size_t length = wcslen(output);
	if (length == 0 || length >= output_capacity - 1) {
		return FALSE;
	}
	wchar_t last = output[length - 1];
	if (last != L'\\' && last != L'/') {
		if (wcscat_s(output, output_capacity, L"\\") != 0) {
			return FALSE;
		}
	}
	wchar_t file_name[128] = {0};
	// 成功文件命名：successfile_%dll.name%_%pid%.txt
	if (swprintf_s(file_name,
		sizeof(file_name) / sizeof(file_name[0]),
		L"successfile_%s_%lu.txt",
		dll_base_name,
		pid) <= 0) {
		return FALSE;
	}
	return wcscat_s(output, output_capacity, file_name) == 0;
}

struct HelperConfig {
	DWORD startup_delay_ms;
	BOOL apply_fullscreen_attack_patch;
	DWORD fullscreen_attack_poll_interval_ms;
	BOOL safe_mode;
	BOOL wipe_pe_header;
	BOOL disable_input_thread;
	BOOL disable_attract_thread;
	BOOL enable_summon_doll;
	DWORD summon_monster_id;
	DWORD summon_level;
	DWORD summon_cooldown_ms;
	BOOL enable_fullscreen_skill;
	DWORD fullscreen_skill_code;
	DWORD fullscreen_skill_damage;
	DWORD fullscreen_skill_interval_ms;
	DWORD fullscreen_skill_hotkey;
	DWORD hotkey_toggle_transparent;
	DWORD hotkey_toggle_fullscreen_attack;
	DWORD hotkey_summon_doll;
	DWORD hotkey_attract_mode1;
	DWORD hotkey_attract_mode2;
	DWORD hotkey_attract_mode3;
	DWORD hotkey_attract_mode4;
	DWORD hotkey_toggle_attract_direction;
	int player_name_encoding;
	float monster_x_offset_by_mode[kAttractModeMax + 1];
	wchar_t output_directory[MAX_PATH];
	BOOL output_directory_set;
};

static HelperConfig g_config_snapshot = {0};
static BOOL g_config_snapshot_ready = FALSE;
static wchar_t g_config_path[MAX_PATH] = {0};
static BOOL g_config_path_ready = FALSE;
static FILETIME g_config_last_write = {0};

static HelperConfig GetDefaultHelperConfig() {
	HelperConfig config = {0};
	config.startup_delay_ms = 0;
	config.apply_fullscreen_attack_patch = FALSE;
	config.fullscreen_attack_poll_interval_ms = kFullscreenAttackPollIntervalMs;
	config.safe_mode = FALSE;
	config.wipe_pe_header = TRUE;
	config.disable_input_thread = FALSE;
	config.disable_attract_thread = FALSE;
	config.enable_summon_doll = TRUE;
	config.summon_monster_id = kSummonDefaultMonsterId;
	config.summon_level = kSummonDefaultLevel;
	config.summon_cooldown_ms = kSummonDefaultCooldownMs;
	config.enable_fullscreen_skill = TRUE;
	config.fullscreen_skill_code = kFullscreenSkillDefaultCode;
	config.fullscreen_skill_damage = kFullscreenSkillDefaultDamage;
	config.fullscreen_skill_interval_ms = kFullscreenSkillDefaultIntervalMs;
	config.fullscreen_skill_hotkey = kFullscreenSkillDefaultHotkey;
	config.hotkey_toggle_transparent = kHotkeyToggleTransparent;
	config.hotkey_toggle_fullscreen_attack = kHotkeyToggleFullscreenAttack;
	config.hotkey_summon_doll = kHotkeySummonDoll;
	config.hotkey_attract_mode1 = kHotkeyAttractMode1;
	config.hotkey_attract_mode2 = kHotkeyAttractMode2;
	config.hotkey_attract_mode3 = kHotkeyAttractMode3;
	config.hotkey_attract_mode4 = kHotkeyAttractMode4;
	config.hotkey_toggle_attract_direction = kHotkeyToggleAttractDirection;
	config.player_name_encoding = kPlayerNameEncodingAuto;
	for (int i = 0; i <= kAttractModeMax; ++i) {
		config.monster_x_offset_by_mode[i] = kDefaultMonsterXOffsetByMode[i];
	}
	config.output_directory[0] = L'\0';
	config.output_directory_set = FALSE;
	return config;
}

static BOOL ReadIniStringValue(const wchar_t* path, const wchar_t* section, const wchar_t* key, wchar_t* output, size_t output_capacity) {
	if (output == NULL || output_capacity == 0) {
		return FALSE;
	}
	output[0] = L'\0';
	DWORD read = GetPrivateProfileStringW(section, key, L"", output, static_cast<DWORD>(output_capacity), path);
	return read > 0;
}

// 解析角色名编码配置。
static int ParsePlayerNameEncoding(const wchar_t* value, int default_value) {
	if (value == NULL || value[0] == L'\0') {
		return default_value;
	}
	if (_wcsicmp(value, L"utf16") == 0 || _wcsicmp(value, L"unicode") == 0) {
		return kPlayerNameEncodingUtf16;
	}
	if (_wcsicmp(value, L"utf8") == 0) {
		return kPlayerNameEncodingUtf8;
	}
	if (_wcsicmp(value, L"ansi") == 0 || _wcsicmp(value, L"gbk") == 0 || _wcsicmp(value, L"cp936") == 0) {
		return kPlayerNameEncodingAnsi;
	}
	if (_wcsicmp(value, L"auto") == 0) {
		return kPlayerNameEncodingAuto;
	}
	return default_value;
}

static DWORD ReadIniUInt32(const wchar_t* path, const wchar_t* section, const wchar_t* key, DWORD default_value) {
	wchar_t buffer[32] = {0};
	DWORD read = GetPrivateProfileStringW(section, key, L"", buffer, static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0])), path);
	if (read == 0) {
		return default_value;
	}
	wchar_t* end = NULL;
	unsigned long parsed = wcstoul(buffer, &end, 10);
	if (end == buffer) {
		return default_value;
	}
	return static_cast<DWORD>(parsed);
}

// 读取浮点配置，读取失败时回退默认值。
static float ReadIniFloat(const wchar_t* path, const wchar_t* section, const wchar_t* key, float default_value) {
	wchar_t buffer[64] = {0};
	DWORD read = GetPrivateProfileStringW(section, key, L"", buffer, static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0])), path);
	if (read == 0) {
		return default_value;
	}
	wchar_t* end = NULL;
	double parsed = wcstod(buffer, &end);
	if (end == buffer) {
		return default_value;
	}
	return static_cast<float>(parsed);
}

static BOOL ReadIniBool(const wchar_t* path, const wchar_t* section, const wchar_t* key, BOOL default_value) {
	wchar_t buffer[32] = {0};
	DWORD read = GetPrivateProfileStringW(section, key, default_value ? L"true" : L"false", buffer, static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0])), path);
	if (read == 0) {
		return default_value;
	}
	if (_wcsicmp(buffer, L"1") == 0 || _wcsicmp(buffer, L"true") == 0 || _wcsicmp(buffer, L"yes") == 0 || _wcsicmp(buffer, L"on") == 0) {
		return TRUE;
	}
	if (_wcsicmp(buffer, L"0") == 0 || _wcsicmp(buffer, L"false") == 0 || _wcsicmp(buffer, L"no") == 0 || _wcsicmp(buffer, L"off") == 0) {
		return FALSE;
	}
	return default_value;
}

static BOOL IsDirectoryValid(const wchar_t* path) {
	if (path == NULL || path[0] == L'\0') {
		return FALSE;
	}
	DWORD attrs = GetFileAttributesW(path);
	if (attrs == INVALID_FILE_ATTRIBUTES) {
		return FALSE;
	}
	return (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

static BOOL GetFileLastWriteTime(const wchar_t* path, FILETIME* write_time) {
	if (write_time == NULL || path == NULL || path[0] == L'\0') {
		return FALSE;
	}
	WIN32_FILE_ATTRIBUTE_DATA data = {0};
	if (!GetFileAttributesExW(path, GetFileExInfoStandard, &data)) {
		return FALSE;
	}
	*write_time = data.ftLastWriteTime;
	return TRUE;
}

static BOOL LoadHelperConfig(const wchar_t* config_path, HelperConfig* config) {
	if (config == NULL || config_path == NULL || config_path[0] == L'\0') {
		return FALSE;
	}
	DWORD attrs = GetFileAttributesW(config_path);
	if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
		return FALSE;
	}
	config->startup_delay_ms = ReadIniUInt32(config_path, L"startup", L"startup_delay_ms", config->startup_delay_ms);
	config->safe_mode = ReadIniBool(config_path, L"startup", L"safe_mode", config->safe_mode);
	config->apply_fullscreen_attack_patch = ReadIniBool(config_path, L"patch", L"apply_fullscreen_attack_patch", config->apply_fullscreen_attack_patch);
	config->fullscreen_attack_poll_interval_ms = ReadIniUInt32(config_path, L"patch", L"fullscreen_attack_poll_interval_ms", config->fullscreen_attack_poll_interval_ms);
	config->wipe_pe_header = ReadIniBool(config_path, L"stealth", L"wipe_pe_header", config->wipe_pe_header);
	config->disable_input_thread = ReadIniBool(config_path, L"feature", L"disable_input_thread", config->disable_input_thread);
	config->disable_attract_thread = ReadIniBool(config_path, L"feature", L"disable_attract_thread", config->disable_attract_thread);
	config->enable_summon_doll = ReadIniBool(config_path, L"feature", L"enable_summon_doll", config->enable_summon_doll);
	config->summon_monster_id = ReadIniUInt32(config_path, L"feature", L"summon_monster_id", config->summon_monster_id);
	config->summon_level = ReadIniUInt32(config_path, L"feature", L"summon_level", config->summon_level);
	config->summon_cooldown_ms = ReadIniUInt32(config_path, L"feature", L"summon_cooldown_ms", config->summon_cooldown_ms);
	config->enable_fullscreen_skill = ReadIniBool(config_path, L"feature", L"enable_fullscreen_skill", config->enable_fullscreen_skill);
	config->fullscreen_skill_code = ReadIniUInt32(config_path, L"fullscreen", L"skill_code", config->fullscreen_skill_code);
	config->fullscreen_skill_damage = ReadIniUInt32(config_path, L"fullscreen", L"skill_damage", config->fullscreen_skill_damage);
	config->fullscreen_skill_interval_ms = ReadIniUInt32(config_path, L"fullscreen", L"skill_interval", config->fullscreen_skill_interval_ms);
	config->fullscreen_skill_hotkey = ReadIniUInt32(config_path, L"fullscreen", L"hotkey_vk", config->fullscreen_skill_hotkey);
	config->hotkey_toggle_transparent = ReadIniUInt32(config_path, L"hotkey", L"toggle_transparent", config->hotkey_toggle_transparent);
	config->hotkey_toggle_fullscreen_attack = ReadIniUInt32(config_path, L"hotkey", L"toggle_fullscreen_attack", config->hotkey_toggle_fullscreen_attack);
	config->hotkey_summon_doll = ReadIniUInt32(config_path, L"hotkey", L"summon_doll", config->hotkey_summon_doll);
	config->hotkey_attract_mode1 = ReadIniUInt32(config_path, L"hotkey", L"attract_mode1", config->hotkey_attract_mode1);
	config->hotkey_attract_mode2 = ReadIniUInt32(config_path, L"hotkey", L"attract_mode2", config->hotkey_attract_mode2);
	config->hotkey_attract_mode3 = ReadIniUInt32(config_path, L"hotkey", L"attract_mode3", config->hotkey_attract_mode3);
	config->hotkey_attract_mode4 = ReadIniUInt32(config_path, L"hotkey", L"attract_mode4", config->hotkey_attract_mode4);
	config->hotkey_toggle_attract_direction = ReadIniUInt32(config_path, L"hotkey", L"toggle_attract_direction", config->hotkey_toggle_attract_direction);
	config->fullscreen_skill_hotkey = ReadIniUInt32(config_path, L"hotkey", L"toggle_fullscreen_skill", config->fullscreen_skill_hotkey);
	wchar_t player_name_encoding[32] = {0};
	if (ReadIniStringValue(config_path, L"feature", L"player_name_encoding", player_name_encoding, sizeof(player_name_encoding) / sizeof(player_name_encoding[0]))) {
		config->player_name_encoding = ParsePlayerNameEncoding(player_name_encoding, config->player_name_encoding);
	}
	config->monster_x_offset_by_mode[1] = ReadIniFloat(config_path, L"attract", L"monster_x_offset_mode1", config->monster_x_offset_by_mode[1]);
	config->monster_x_offset_by_mode[2] = ReadIniFloat(config_path, L"attract", L"monster_x_offset_mode2", config->monster_x_offset_by_mode[2]);
	config->monster_x_offset_by_mode[3] = ReadIniFloat(config_path, L"attract", L"monster_x_offset_mode3", config->monster_x_offset_by_mode[3]);
	config->monster_x_offset_by_mode[4] = ReadIniFloat(config_path, L"attract", L"monster_x_offset_mode4", config->monster_x_offset_by_mode[4]);
	if (ReadIniStringValue(config_path, L"output", L"output_dir", config->output_directory, MAX_PATH)) {
		config->output_directory_set = TRUE;
	}
	return TRUE;
}

static void FormatTimestamp(char* buffer, size_t buffer_capacity) {
	SYSTEMTIME local_time;
	ZeroMemory(&local_time, sizeof(local_time));
	GetLocalTime(&local_time);
	sprintf_s(
		buffer,
		buffer_capacity,
		"%04u-%02u-%02uT%02u:%02u:%02u.%03u",
		local_time.wYear,
		local_time.wMonth,
		local_time.wDay,
		local_time.wHour,
		local_time.wMinute,
		local_time.wSecond,
		local_time.wMilliseconds);
}

static void EscapeJsonString(const char* input, char* output, size_t output_capacity) {
	if (output_capacity == 0) {
		return;
	}
	output[0] = '\0';
	if (input == NULL) {
		return;
	}
	size_t out_index = 0;
	for (const unsigned char* cursor = reinterpret_cast<const unsigned char*>(input); *cursor != '\0'; ++cursor) {
		if (out_index + 2 >= output_capacity) {
			break;
		}
		switch (*cursor) {
			case '\\':
			case '\"':
				output[out_index++] = '\\';
				output[out_index++] = static_cast<char>(*cursor);
				break;
			case '\n':
				output[out_index++] = '\\';
				output[out_index++] = 'n';
				break;
			case '\r':
				output[out_index++] = '\\';
				output[out_index++] = 'r';
				break;
			case '\t':
				output[out_index++] = '\\';
				output[out_index++] = 't';
				break;
			default:
				if (*cursor < 0x20) {
					output[out_index++] = '?';
				} else {
					output[out_index++] = static_cast<char>(*cursor);
				}
				break;
		}
	}
	output[out_index] = '\0';
}

static void WriteLogLine(const char* level, const char* event, const char* message) {
	if (!g_log_ready || g_log_file == INVALID_HANDLE_VALUE) {
		return;
	}
	char timestamp[32] = {0};
	FormatTimestamp(timestamp, sizeof(timestamp));
	char escaped_level[32] = {0};
	char escaped_event[64] = {0};
	char escaped_message[512] = {0};
	EscapeJsonString(level, escaped_level, sizeof(escaped_level));
	EscapeJsonString(event, escaped_event, sizeof(escaped_event));
	EscapeJsonString(message, escaped_message, sizeof(escaped_message));
	char line[1024] = {0};
	int length = sprintf_s(
		line,
		sizeof(line),
		"{\"ts\":\"%s\",\"level\":\"%s\",\"event\":\"%s\",\"message\":\"%s\",\"pid\":%lu,\"tid\":%lu}\r\n",
		timestamp,
		escaped_level,
		escaped_event,
		escaped_message,
		GetCurrentProcessId(),
		GetCurrentThreadId());
	if (length <= 0) {
		return;
	}
	DWORD written = 0;
	WriteFile(g_log_file, line, static_cast<DWORD>(length), &written, NULL);
}

static void LogEvent(const char* level, const char* event, const char* message) {
	if (!g_log_lock_ready) {
		return;
	}
	EnterCriticalSection(&g_log_lock);
	WriteLogLine(level, event, message);
	LeaveCriticalSection(&g_log_lock);
}

static void LogEventWithError(const char* event, const char* message, DWORD error_code) {
	char buffer[256] = {0};
	sprintf_s(buffer, sizeof(buffer), "%s (error=%lu)", message, error_code);
	LogEvent("ERROR", event, buffer);
}

static void LogEventWithPath(const char* event, const wchar_t* path) {
	if (path == NULL) {
		LogEvent("WARN", event, "path is empty");
		return;
	}
	char path_utf8[512] = {0};
	if (WideCharToMultiByte(CP_UTF8, 0, path, -1, path_utf8, sizeof(path_utf8), NULL, NULL) == 0) {
		LogEvent("WARN", event, "path conversion failed");
		return;
	}
	char message[640] = {0};
	sprintf_s(message, sizeof(message), "path=%s", path_utf8);
	LogEvent("INFO", event, message);
}

static BOOL OpenLogFileInDirectory(const wchar_t* directory_path) {
	wchar_t log_path[MAX_PATH] = {0};
	if (!BuildLogPath(directory_path, log_path, MAX_PATH)) {
		return FALSE;
	}
	HANDLE file = CreateFileW(
		log_path,
		FILE_APPEND_DATA,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (file == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	g_log_file = file;
	g_log_ready = TRUE;
	wcscpy_s(g_log_path, MAX_PATH, log_path);
	return TRUE;
}

static void InitializeLogger(const wchar_t* preferred_directory) {
	if (g_log_lock_ready) {
		return;
	}
	InitializeCriticalSection(&g_log_lock);
	g_log_lock_ready = TRUE;
	if (preferred_directory != NULL && preferred_directory[0] != L'\0') {
		if (OpenLogFileInDirectory(preferred_directory)) {
			LogEventWithPath("logger_init", g_log_path);
			return;
		}
	}
	wchar_t temp_path[MAX_PATH] = {0};
	DWORD temp_length = GetTempPathW(MAX_PATH, temp_path);
	if (temp_length > 0 && temp_length < MAX_PATH) {
		if (OpenLogFileInDirectory(temp_path)) {
			LogEventWithPath("logger_init", g_log_path);
			return;
		}
	}
}

// 安全读取 DWORD，避免地址无效时导致进程崩溃。
static DWORD ReadDwordSafely(DWORD address) {
	__try {
		return *(DWORD*)address;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return 0;
	}
}

// 安全读取 float，避免地址无效时导致进程崩溃。
static float ReadFloatSafely(DWORD address) {
	__try {
		return *(float*)address;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return 0.0f;
	}
}

// 安全写入 float，带权限切换。
static BOOL WriteFloatSafely(DWORD address, float value) {
	DWORD old_protect = 0;
	if (!VirtualProtect(reinterpret_cast<void*>(address), sizeof(float), PAGE_EXECUTE_READWRITE, &old_protect)) {
		return FALSE;
	}

	BOOL wrote = FALSE;
	__try {
		*(float*)address = value;
		wrote = TRUE;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		wrote = FALSE;
	}

	DWORD ignored = 0;
	VirtualProtect(reinterpret_cast<void*>(address), sizeof(float), old_protect, &ignored);
	return wrote;
}

// 评分相关暂未提供基址，保留占位实现，避免写入未知地址。
static void ApplyScorePlaceholder() {
	// 评分基址未提供，当前不做任何内存写入，确保稳定性。
}

// 特效占位逻辑，保持接口一致。
static void ApplyEffectPlaceholder() {
}

// 系统公告占位逻辑，保持接口一致。
static void AnnouncePlaceholder(const wchar_t* message) {
	UNREFERENCED_PARAMETER(message);
}

// 城镇/ BOSS 房判断占位逻辑，后续接入实际基址。
static BOOL IsInTownPlaceholder() {
	return FALSE;
}

static BOOL IsInBossRoomPlaceholder() {
	return FALSE;
}

// 安全读取字节序列，避免无效地址导致崩溃。
static BOOL ReadBytesSafely(DWORD address, BYTE* buffer, SIZE_T size) {
	__try {
		memcpy(buffer, reinterpret_cast<const void*>(address), size);
		return TRUE;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
}

// 安全写入字节序列，带权限切换与指令缓存刷新。
static BOOL WriteBytesSafely(DWORD address, const BYTE* buffer, SIZE_T size) {
	DWORD old_protect = 0;
	if (!VirtualProtect(reinterpret_cast<void*>(address), size, PAGE_EXECUTE_READWRITE, &old_protect)) {
		return FALSE;
	}

	BOOL wrote = FALSE;
	__try {
		memcpy(reinterpret_cast<void*>(address), buffer, size);
		wrote = TRUE;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		wrote = FALSE;
	}

	DWORD ignored = 0;
	VirtualProtect(reinterpret_cast<void*>(address), size, old_protect, &ignored);
	if (wrote) {
		FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(address), size);
	}
	return wrote;
}

// 读取全屏攻击目标状态（提前声明，供共享内存写入使用）。
static BOOL IsFullscreenAttackTargetEnabled();
static void TrySummonDoll();
static BYTE NormalizeControlValue(BYTE value);
static void ApplyControlOverrides();

// 判断是否为“关闭全屏攻击”的指令形态。
static BOOL IsFullscreenAttackOffBytes(const BYTE* bytes) {
	return memcmp(bytes, kFullscreenAttackPatchOffA, kFullscreenAttackPatchSize) == 0 ||
		memcmp(bytes, kFullscreenAttackPatchOffB, kFullscreenAttackPatchSize) == 0;
}

// 记录当前版本的关闭指令，便于恢复原始形态。
static void RememberFullscreenAttackOffBytes(const BYTE* bytes) {
	if (!g_fullscreen_attack_off_patch_set && IsFullscreenAttackOffBytes(bytes)) {
		memcpy(g_fullscreen_attack_off_patch, bytes, kFullscreenAttackPatchSize);
		g_fullscreen_attack_off_patch_set = TRUE;
	}
}

// 全屏攻击补丁：仅在识别到预期字节时才切换，避免写错版本。
static BOOL SetFullscreenAttackEnabled(BOOL enabled) {
	BYTE current[2] = {0};
	if (!ReadBytesSafely(kFullScreenAttackPatchAddress, current, sizeof(current))) {
		return FALSE;
	}
	RememberFullscreenAttackOffBytes(current);
	if (enabled == TRUE) {
		if (memcmp(current, kFullscreenAttackPatchOn, kFullscreenAttackPatchSize) == 0) {
			return TRUE;
		}
		if (!IsFullscreenAttackOffBytes(current)) {
			return FALSE;
		}
		return WriteBytesSafely(kFullScreenAttackPatchAddress, kFullscreenAttackPatchOn, kFullscreenAttackPatchSize);
	}
	if (IsFullscreenAttackOffBytes(current)) {
		return TRUE;
	}
	if (memcmp(current, kFullscreenAttackPatchOn, kFullscreenAttackPatchSize) != 0) {
		return FALSE;
	}
	const BYTE* off_patch = g_fullscreen_attack_off_patch_set ? g_fullscreen_attack_off_patch : kFullscreenAttackPatchOffB;
	return WriteBytesSafely(kFullScreenAttackPatchAddress, off_patch, kFullscreenAttackPatchSize);
}

static void BuildSharedMemoryName(const wchar_t* prefix, wchar_t* output, size_t output_capacity, DWORD pid) {
	if (output == NULL || output_capacity == 0) {
		return;
	}
	if (prefix == NULL) {
		output[0] = L'\0';
		return;
	}
	swprintf_s(output, output_capacity, L"%s%lu", prefix, pid);
}

// 初始化共享内存，用于 GUI 状态读取。
static BOOL InitializeSharedMemory() {
	if (g_shared_memory_view != NULL) {
		return TRUE;
	}
	DWORD pid = GetCurrentProcessId();
	wchar_t name_buffer[64] = {0};
	const wchar_t* prefixes[] = {kSharedMemoryNamePrefixGlobal, kSharedMemoryNamePrefixLocal};
	for (int i = 0; i < 2; ++i) {
		BuildSharedMemoryName(prefixes[i], name_buffer, sizeof(name_buffer) / sizeof(name_buffer[0]), pid);
		if (name_buffer[0] == L'\0') {
			continue;
		}
		HANDLE mapping = CreateFileMappingW(
			INVALID_HANDLE_VALUE,
			NULL,
			PAGE_READWRITE,
			0,
			static_cast<DWORD>(sizeof(HelperStatusV2)),
			name_buffer);
		if (mapping == NULL) {
			DWORD error = GetLastError();
			if (error == ERROR_ACCESS_DENIED && i == 0) {
				continue;
			}
			if (InterlockedExchange(&g_shared_memory_failed_logged, 1) == 0) {
				LogEventWithError("shared_memory", "create_failed", error);
			}
			return FALSE;
		}
		void* view = MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, sizeof(HelperStatusV2));
		if (view == NULL) {
			DWORD error = GetLastError();
			CloseHandle(mapping);
			if (InterlockedExchange(&g_shared_memory_failed_logged, 1) == 0) {
				LogEventWithError("shared_memory", "map_failed", error);
			}
			return FALSE;
		}
		g_shared_memory_handle = mapping;
		g_shared_memory_view = view;
		ZeroMemory(view, sizeof(HelperStatusV2));
		InterlockedExchange(&g_shared_memory_failed_logged, 0);
		wcscpy_s(g_shared_memory_name, name_buffer);
		if (InterlockedExchange(&g_shared_memory_ready_logged, 1) == 0) {
			LogEvent("INFO", "shared_memory", "ready");
		}
		return TRUE;
	}
	return FALSE;
}

// 初始化控制共享内存，用于 GUI 写入控制指令。
static BOOL InitializeControlMemory() {
	if (g_control_memory_view != NULL) {
		return TRUE;
	}
	DWORD pid = GetCurrentProcessId();
	wchar_t name_buffer[64] = {0};
	const wchar_t* prefixes[] = {kControlMemoryNamePrefixGlobal, kControlMemoryNamePrefixLocal};
	for (int i = 0; i < 2; ++i) {
		BuildSharedMemoryName(prefixes[i], name_buffer, sizeof(name_buffer) / sizeof(name_buffer[0]), pid);
		if (name_buffer[0] == L'\0') {
			continue;
		}
		HANDLE mapping = CreateFileMappingW(
			INVALID_HANDLE_VALUE,
			NULL,
			PAGE_READWRITE,
			0,
			static_cast<DWORD>(sizeof(HelperControlV1)),
			name_buffer);
		if (mapping == NULL) {
			DWORD error = GetLastError();
			if (error == ERROR_ACCESS_DENIED && i == 0) {
				continue;
			}
			if (InterlockedExchange(&g_control_memory_failed_logged, 1) == 0) {
				LogEventWithError("control_memory", "create_failed", error);
			}
			return FALSE;
		}
		void* view = MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, sizeof(HelperControlV1));
		if (view == NULL) {
			DWORD error = GetLastError();
			CloseHandle(mapping);
			if (InterlockedExchange(&g_control_memory_failed_logged, 1) == 0) {
				LogEventWithError("control_memory", "map_failed", error);
			}
			return FALSE;
		}
		g_control_memory_handle = mapping;
		g_control_memory_view = view;
		ZeroMemory(view, sizeof(HelperControlV1));
		HelperControlV1 init = {0};
		init.version = kControlMemoryVersion;
		init.size = static_cast<DWORD>(sizeof(HelperControlV1));
		init.pid = pid;
		memcpy(view, &init, sizeof(init));
		InterlockedExchange(&g_control_memory_failed_logged, 0);
		wcscpy_s(g_control_memory_name, name_buffer);
		if (InterlockedExchange(&g_control_memory_ready_logged, 1) == 0) {
			LogEvent("INFO", "control_memory", "ready");
		}
		return TRUE;
	}
	return FALSE;
}

// 读取当前角色名（失败则为空）。
static BOOL IsPlayerNameChar(wchar_t ch) {
	if ((ch >= L'0' && ch <= L'9') ||
		(ch >= L'A' && ch <= L'Z') ||
		(ch >= L'a' && ch <= L'z') ||
		(ch >= 0x4E00 && ch <= 0x9FFF) ||
		ch == L'_' || ch == L'-' || ch == 0x00B7 || ch == 0x30FB) {
		return TRUE;
	}
	return FALSE;
}

static int ScorePlayerName(const wchar_t* name) {
	if (name == NULL) {
		return -1000;
	}
	int score = 0;
	int invalid = 0;
	int length = 0;
	for (size_t i = 0; i < kPlayerNameMaxChars; ++i) {
		wchar_t ch = name[i];
		if (ch == L'\0') {
			break;
		}
		++length;
		if ((ch >= L'0' && ch <= L'9') ||
			(ch >= L'A' && ch <= L'Z') ||
			(ch >= L'a' && ch <= L'z')) {
			score += 2;
			continue;
		}
		if (ch >= 0x4E00 && ch <= 0x9FFF) {
			score += 3;
			continue;
		}
		if (ch == L'_' || ch == L'-' || ch == 0x00B7 || ch == 0x30FB) {
			score += 1;
			continue;
		}
		if (ch == 0xFFFD || !iswprint(ch)) {
			score -= 4;
			++invalid;
			continue;
		}
		if (iswprint(ch)) {
			score += 1;
		} else {
			score -= 2;
			++invalid;
		}
	}
	if (length == 0) {
		return -1000;
	}
	if (invalid > 0) {
		score -= invalid * 3;
	}
	if (length == 1) {
		score -= 1;
	}
	return score;
}

static void TrimPlayerName(wchar_t* name) {
	if (name == NULL) {
		return;
	}
	int invalid_run = 0;
	for (size_t i = 0; i < kPlayerNameMaxChars; ++i) {
		wchar_t ch = name[i];
		if (ch == L'\0') {
			break;
		}
		if (IsPlayerNameChar(ch)) {
			invalid_run = 0;
			continue;
		}
		if (iswprint(ch)) {
			++invalid_run;
			if (invalid_run >= 2) {
				name[i - invalid_run + 1] = L'\0';
				break;
			}
			continue;
		}
		++invalid_run;
		if (invalid_run >= 2) {
			name[i - invalid_run + 1] = L'\0';
			break;
		}
	}
}

static BOOL DecodeMultiByteName(UINT code_page, DWORD flags, const BYTE* raw, wchar_t* output, size_t output_capacity) {
	if (output == NULL || output_capacity == 0 || raw == NULL) {
		return FALSE;
	}
	output[0] = L'\0';
	int converted = MultiByteToWideChar(code_page, flags, reinterpret_cast<const char*>(raw), -1,
		output, static_cast<int>(output_capacity));
	if (converted <= 0) {
		output[0] = L'\0';
		return FALSE;
	}
	output[output_capacity - 1] = L'\0';
	TrimPlayerName(output);
	return TRUE;
}

static void FormatHexString(const BYTE* data, size_t length, char* output, size_t output_capacity) {
	if (output == NULL || output_capacity == 0) {
		return;
	}
	output[0] = '\0';
	if (data == NULL || length == 0) {
		return;
	}
	size_t cursor = 0;
	for (size_t i = 0; i < length; ++i) {
		if (cursor + 3 >= output_capacity) {
			break;
		}
		int written = sprintf_s(output + cursor, output_capacity - cursor, "%02X", data[i]);
		if (written <= 0) {
			break;
		}
		cursor += static_cast<size_t>(written);
		if (i + 1 < length) {
			if (cursor + 1 >= output_capacity) {
				break;
			}
			output[cursor++] = ' ';
			output[cursor] = '\0';
		}
	}
}

static void ReadPlayerName(wchar_t* output, size_t output_capacity) {
	if (output == NULL || output_capacity == 0) {
		return;
	}
	output[0] = L'\0';
	DWORD player_ptr = ReadDwordSafely(kPlayerBaseAddress);
	if (player_ptr == 0) {
		return;
	}
	DWORD name_ptr = ReadDwordSafely(player_ptr + kPlayerNameOffset);
	if (name_ptr == 0) {
		return;
	}
	BYTE raw[kPlayerNameMaxChars * sizeof(wchar_t)] = {0};
	if (!ReadBytesSafely(name_ptr + kPlayerNameSecondOffset, raw, sizeof(raw))) {
		output[0] = L'\0';
		return;
	}
	raw[sizeof(raw) - 1] = 0;
	// 诊断用：记录原始字节（变化或间隔触发）。
	{
		static BYTE last_raw[kPlayerNameMaxChars * sizeof(wchar_t)] = {0};
		static DWORD last_log_tick = 0;
		DWORD now = GetTickCount();
		BOOL changed = memcmp(raw, last_raw, sizeof(raw)) != 0;
		if (changed || now - last_log_tick >= 5000) {
			char hex[256] = {0};
			FormatHexString(raw, sizeof(raw), hex, sizeof(hex));
			char message[360] = {0};
			sprintf_s(message, sizeof(message), "ptr=0x%08X raw=%s", name_ptr, hex);
			LogEvent("INFO", "player_name_raw", message);
			memcpy(last_raw, raw, sizeof(raw));
			last_log_tick = now;
		}
	}

	wchar_t utf16_name[kPlayerNameMaxChars] = {0};
	memcpy(utf16_name, raw, sizeof(utf16_name));
	utf16_name[kPlayerNameMaxChars - 1] = L'\0';
	TrimPlayerName(utf16_name);

	wchar_t utf8_name[kPlayerNameMaxChars] = {0};
	BOOL utf8_ok = DecodeMultiByteName(CP_UTF8, MB_ERR_INVALID_CHARS, raw, utf8_name, kPlayerNameMaxChars);

	wchar_t ansi_name[kPlayerNameMaxChars] = {0};
	BOOL ansi_ok = DecodeMultiByteName(CP_ACP, 0, raw, ansi_name, kPlayerNameMaxChars);

	const wchar_t* pick = utf16_name;
	int pick_score = ScorePlayerName(utf16_name);

	if (g_player_name_encoding == kPlayerNameEncodingUtf8) {
		if (utf8_ok) {
			pick = utf8_name;
		} else {
			pick = L"";
		}
	} else if (g_player_name_encoding == kPlayerNameEncodingAnsi) {
		if (ansi_ok) {
			pick = ansi_name;
		} else {
			pick = L"";
		}
	} else if (g_player_name_encoding == kPlayerNameEncodingUtf16) {
		pick = utf16_name;
	} else {
		if (utf8_ok) {
			int utf8_score = ScorePlayerName(utf8_name);
			if (utf8_score > pick_score) {
				pick_score = utf8_score;
				pick = utf8_name;
			}
		}
		if (ansi_ok) {
			int ansi_score = ScorePlayerName(ansi_name);
			if (ansi_score > pick_score) {
				pick_score = ansi_score;
				pick = ansi_name;
			}
		}
	}
	wcsncpy_s(output, output_capacity, pick, _TRUNCATE);
}

static void WriteSharedMemorySnapshot() {
	if (!InitializeSharedMemory()) {
		return;
	}
	HelperStatusV2 snapshot = {0};
	snapshot.version = kSharedMemoryVersion;
	snapshot.size = static_cast<DWORD>(sizeof(HelperStatusV2));
	snapshot.last_tick_ms = GetTickCount64();
	snapshot.pid = GetCurrentProcessId();
	snapshot.process_alive = TRUE;
	snapshot.auto_transparent_enabled = g_auto_transparent_enabled;
	snapshot.fullscreen_attack_target = IsFullscreenAttackTargetEnabled() ? TRUE : FALSE;
	BYTE current[2] = {0};
	if (ReadBytesSafely(kFullScreenAttackPatchAddress, current, sizeof(current))) {
		if (memcmp(current, kFullscreenAttackPatchOn, kFullscreenAttackPatchSize) == 0) {
			snapshot.fullscreen_attack_patch_on = TRUE;
		} else if (IsFullscreenAttackOffBytes(current)) {
			snapshot.fullscreen_attack_patch_on = FALSE;
		} else {
			snapshot.fullscreen_attack_patch_on = FALSE;
		}
	}
	snapshot.attract_mode = g_attract_mode;
	snapshot.attract_positive = g_attract_positive_enabled;
	snapshot.summon_enabled = g_summon_enabled;
	snapshot.summon_last_tick = g_summon_last_tick;
	snapshot.fullscreen_skill_enabled = g_fullscreen_skill_enabled;
	snapshot.fullscreen_skill_active = g_fullscreen_skill_active;
	snapshot.fullscreen_skill_hotkey = g_fullscreen_skill_hotkey;
	snapshot.hotkey_enabled = g_hotkey_enabled;
	ReadPlayerName(snapshot.player_name, kPlayerNameMaxChars);
	memcpy(g_shared_memory_view, &snapshot, sizeof(snapshot));
}

// 共享内存写入线程：持续输出状态。
static DWORD WINAPI SharedMemoryWriterThread(LPVOID param) {
	UNREFERENCED_PARAMETER(param);
	for (;;) {
		WriteSharedMemorySnapshot();
		Sleep(kSharedMemoryWriteIntervalMs);
	}
	return 0;
}

// 控制共享内存读取线程：读取 GUI 控制并应用。
static DWORD WINAPI ControlReaderThread(LPVOID param) {
	UNREFERENCED_PARAMETER(param);
	for (;;) {
		if (!InitializeControlMemory()) {
			Sleep(1000);
			continue;
		}
		HelperControlV1 snapshot = {0};
		memcpy(&snapshot, g_control_memory_view, sizeof(snapshot));
		if (snapshot.version != kControlMemoryVersion || snapshot.size != sizeof(HelperControlV1)) {
			Sleep(1000);
			continue;
		}
		snapshot.fullscreen_attack = NormalizeControlValue(snapshot.fullscreen_attack);
		snapshot.fullscreen_skill = NormalizeControlValue(snapshot.fullscreen_skill);
		snapshot.auto_transparent = NormalizeControlValue(snapshot.auto_transparent);
		snapshot.attract = NormalizeControlValue(snapshot.attract);
		snapshot.hotkey_enabled = NormalizeControlValue(snapshot.hotkey_enabled);

		BOOL control_changed = FALSE;
		if (snapshot.fullscreen_attack != g_control_fullscreen_attack) {
			g_control_fullscreen_attack = snapshot.fullscreen_attack;
			control_changed = TRUE;
		}
		if (snapshot.fullscreen_skill != g_control_fullscreen_skill) {
			g_control_fullscreen_skill = snapshot.fullscreen_skill;
			control_changed = TRUE;
		}
		if (snapshot.auto_transparent != g_control_auto_transparent) {
			g_control_auto_transparent = snapshot.auto_transparent;
			control_changed = TRUE;
		}
		if (snapshot.attract != g_control_attract) {
			g_control_attract = snapshot.attract;
			control_changed = TRUE;
		}
		if (snapshot.hotkey_enabled != g_control_hotkey_enabled) {
			g_control_hotkey_enabled = snapshot.hotkey_enabled;
			control_changed = TRUE;
		}
		if (control_changed) {
			ApplyControlOverrides();
		}
		if (snapshot.summon_sequence != g_control_last_summon_sequence) {
			g_control_last_summon_sequence = snapshot.summon_sequence;
			TrySummonDoll();
		}
		Sleep(kControlMemoryReadIntervalMs);
	}
	return 0;
}

// 读取全屏攻击目标状态，避免多线程竞态。
static BOOL IsFullscreenAttackTargetEnabled() {
	return InterlockedCompareExchange(&g_fullscreen_attack_target_enabled, 0, 0) != 0;
}

// 设置全屏攻击目标状态，供轮询线程纠偏。
static void SetFullscreenAttackTargetEnabled(BOOL enabled) {
	InterlockedExchange(&g_fullscreen_attack_target_enabled, enabled ? 1 : 0);
}

static void ToggleFullscreenAttack() {
	BOOL next_enabled = IsFullscreenAttackTargetEnabled() ? FALSE : TRUE;
	SetFullscreenAttackTargetEnabled(next_enabled);
	if (next_enabled) {
		AnnouncePlaceholder(L"全屏攻击目标 [开启]");
		LogEvent("INFO", "fullscreen_attack", "target_enabled");
	} else {
		AnnouncePlaceholder(L"全屏攻击目标 [关闭]");
		LogEvent("INFO", "fullscreen_attack", "target_disabled");
	}
	if (!SetFullscreenAttackEnabled(next_enabled)) {
		LogEvent("WARN", "fullscreen_attack", "apply_failed");
	}
}

// 全屏攻击状态轮询：与目标状态不一致时纠正。
static DWORD WINAPI FullscreenAttackGuardThread(LPVOID param) {
	UNREFERENCED_PARAMETER(param);
	while (TRUE) {
		BOOL target_enabled = IsFullscreenAttackTargetEnabled();
		SetFullscreenAttackEnabled(target_enabled);
		DWORD interval = g_fullscreen_attack_poll_interval_ms;
		if (interval == 0) {
			interval = 1;
		}
		Sleep(interval);
	}
	return 0;
}

// 吸怪聚物：根据配置把怪物/物品坐标拉到人物坐标或偏移位置。
static void AttractMonstersAndItems(int mode) {
	if (mode <= kAttractModeOff || mode > kAttractModeMax) {
		return;
	}
	DWORD player_ptr = ReadDwordSafely(kPlayerBaseAddress);
	if (player_ptr == 0) {
		return;
	}
	DWORD map_ptr = ReadDwordSafely(player_ptr + kMapOffset);
	if (map_ptr == 0) {
		return;
	}
	DWORD start_ptr = ReadDwordSafely(map_ptr + kMapStartOffset);
	DWORD end_ptr = ReadDwordSafely(map_ptr + kMapEndOffset);
	if (start_ptr == 0 || end_ptr == 0 || end_ptr <= start_ptr) {
		return;
	}
	int count = (int)((end_ptr - start_ptr) / 4);
	if (count <= 0 || count > kMaxObjectCount) {
		return;
	}
	float player_x = ReadFloatSafely(player_ptr + kPositionXOffset);
	float player_y = ReadFloatSafely(player_ptr + kPositionYOffset);
	float offset = g_monster_x_offset_by_mode[mode];
	if (offset < 0.0f) {
		offset = -offset;
	}
	// 方向开关生效：正向为 +，负向为 -。
	float direction = g_attract_positive_enabled ? 1.0f : -1.0f;
	float monster_x = player_x + offset * direction;
	// 以 end 为结束地址，按指针步进遍历对象
	for (DWORD cursor = start_ptr; cursor < end_ptr; cursor += 4) {
		DWORD object_ptr = ReadDwordSafely(cursor);
		if (object_ptr == 0 || object_ptr == player_ptr) {
			continue;
		}
		int type = (int)ReadDwordSafely(object_ptr + kTypeOffset);
		if (type != kTypeMonster && type != kTypeApc && type != kTypeItem) {
			continue;
		}
		int faction = (int)ReadDwordSafely(object_ptr + kFactionOffset);
		if (faction == 0) {
			continue;
		}
		DWORD position_ptr = ReadDwordSafely(object_ptr + kObjectPositionBaseOffset);
		if (position_ptr == 0) {
			continue;
		}
		if (type == kTypeItem) {
			// 物品吸到人物坐标。
			WriteFloatSafely(position_ptr + kObjectPositionXOffset, player_x);
			WriteFloatSafely(position_ptr + kObjectPositionYOffset, player_y);
			continue;
		}
		// 怪物/敌对 APC 的 X 坐标按配置偏移，Y 坐标与人物一致。
		WriteFloatSafely(position_ptr + kObjectPositionXOffset, monster_x);
		WriteFloatSafely(position_ptr + kObjectPositionYOffset, player_y);
	}
}

// 自动吸怪线程：开启时按固定间隔执行吸怪逻辑。
static DWORD WINAPI AutoAttractThread(LPVOID param) {
	UNREFERENCED_PARAMETER(param);
	while (TRUE) {
		int mode = g_attract_mode;
		if (mode != kAttractModeOff) {
			AttractMonstersAndItems(mode);
			Sleep(kAttractLoopIntervalMs);
		} else {
			Sleep(kAttractIdleIntervalMs);
		}
	}
	return 0;
}

// 召唤人偶：内联汇编按 CE 脚本顺序压栈调用。
static BOOL CallSummonDoll(int monster_id, int level) {
	DWORD player_ptr = ReadDwordSafely(kPlayerBaseAddress);
	if (player_ptr == 0) {
		return FALSE;
	}
	DWORD vtable = ReadDwordSafely(player_ptr);
	if (vtable == 0) {
		return FALSE;
	}
	__asm {
		pushad
		push 0
		push 1
		push kSummonCallParam
		push 0
		push 0
		push -1
		push 0
		push 0
		push 0
		push 1
		push 0
		push 0
		push kSummonPositionParam
		push level
		push 0
		push monster_id
		mov esi, player_ptr
		mov ecx, esi
		mov edx, [ecx]
		mov eax, edx
		add eax, kSummonFunctionOffset
		mov ebx, [eax]
		call ebx
		popad
	}
	return TRUE;
}

// 召唤人偶入口：处理开关与冷却。
static void TrySummonDoll() {
	if (!g_summon_enabled) {
		return;
	}
	ULONGLONG now = GetTickCount64();
	if (g_summon_cooldown_ms > 0 && (now - g_summon_last_tick) < g_summon_cooldown_ms) {
		return;
	}
	if (CallSummonDoll(static_cast<int>(g_summon_monster_id), static_cast<int>(g_summon_level))) {
		g_summon_last_tick = now;
		LogEvent("INFO", "summon_doll", "triggered");
	} else {
		LogEvent("WARN", "summon_doll", "player_invalid");
	}
}

// 全屏技能：按 CE 参数顺序执行模拟 CALL。
static void CallFullscreenSkill(DWORD x_raw, DWORD y_raw, int z, int damage, int skill_code) {
	DWORD player_obj = ReadDwordSafely(kPlayerBaseAddress);
	if (player_obj == 0) {
		return;
	}
	DWORD call_address = kFullscreenSkillCallAddress;
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
		push z
		push y_raw
		push x_raw
		push damage
		push skill_code
		push player_obj
		mov ecx, player_obj
		mov eax, call_address
		call eax
		popad
	}
}

// 全屏技能遍历线程：遍历地图单位并执行技能。
static DWORD WINAPI FullscreenSkillThread(LPVOID param) {
	UNREFERENCED_PARAMETER(param);
	while (TRUE) {
		if (!g_fullscreen_skill_enabled) {
			Sleep(1000);
			continue;
		}
		if (!g_fullscreen_skill_active) {
			Sleep(200);
			continue;
		}
		DWORD player_ptr = ReadDwordSafely(kPlayerBaseAddress);
		if (player_ptr == 0) {
			Sleep(1000);
			continue;
		}
		DWORD map_ptr = ReadDwordSafely(player_ptr + kMapOffset);
		if (map_ptr == 0) {
			Sleep(500);
			continue;
		}
		DWORD start_ptr = ReadDwordSafely(map_ptr + kMapStartOffset);
		DWORD end_ptr = ReadDwordSafely(map_ptr + kMapEndOffset);
		if (start_ptr == 0 || end_ptr == 0 || end_ptr <= start_ptr || end_ptr < 4) {
			Sleep(200);
			continue;
		}
		DWORD last_ptr = end_ptr - 4;
		int count = (int)((end_ptr - start_ptr) / 4);
		if (count <= 0 || count > kMaxObjectCount) {
			Sleep(200);
			continue;
		}
		for (DWORD cursor = start_ptr; cursor <= last_ptr; cursor += 4) {
			DWORD object_ptr = ReadDwordSafely(cursor);
			if (object_ptr == 0) {
				continue;
			}
			int faction = (int)ReadDwordSafely(object_ptr + kFactionOffset);
			if (faction == 0) {
				continue;
			}
			int type = (int)ReadDwordSafely(object_ptr + kFullscreenSkillTypeOffset);
			if (type != kTypeMonster && type != kTypeApc) {
				continue;
			}
			DWORD x_raw = ReadDwordSafely(object_ptr + kFullscreenSkillPosXOffset);
			DWORD y_raw = ReadDwordSafely(object_ptr + kFullscreenSkillPosYOffset);
			CallFullscreenSkill(x_raw, y_raw, 0,
				static_cast<int>(g_fullscreen_skill_damage),
				static_cast<int>(g_fullscreen_skill_code));
		}
		DWORD interval = g_fullscreen_skill_interval_ms;
		if (interval == 0) {
			interval = 1;
		}
		Sleep(interval);
	}
	return 0;
}

// 全屏技能开关切换。
static void ToggleFullscreenSkill() {
	if (!g_fullscreen_skill_enabled) {
		AnnouncePlaceholder(L"全屏技能未启用");
		LogEvent("INFO", "fullscreen_skill", "disabled_by_config");
		return;
	}
	g_fullscreen_skill_active = !g_fullscreen_skill_active;
	if (g_fullscreen_skill_active) {
		AnnouncePlaceholder(L"全屏技能 [开启]");
		LogEvent("INFO", "fullscreen_skill", "activated");
	} else {
		AnnouncePlaceholder(L"全屏技能 [关闭]");
		LogEvent("INFO", "fullscreen_skill", "deactivated");
	}
}

// 前台窗口输入轮询：仅当前进程前台时响应按键，避免多开冲突。
static void ToggleAutoTransparent();
static void ToggleAttractMode(int mode, const wchar_t* message);
static void ToggleAttractDirection();

static bool IsHotkeyDown(DWORD vk) {
	if (vk == 0) {
		return false;
	}
	return (GetAsyncKeyState(static_cast<int>(vk)) & 0x8000) != 0;
}

static DWORD WINAPI InputPollThread(LPVOID param) {
	UNREFERENCED_PARAMETER(param);
	DWORD self_pid = GetCurrentProcessId();
	bool f2_last_down = false;
	bool f3_last_down = false;
	bool f12_last_down = false;
	bool key7_last_down = false;
	bool key8_last_down = false;
	bool key9_last_down = false;
	bool key0_last_down = false;
	bool minus_last_down = false;
	bool fullscreen_hotkey_last_down = false;
	while (TRUE) {
		HWND foreground = GetForegroundWindow();
		DWORD foreground_pid = 0;
		if (foreground != NULL) {
			GetWindowThreadProcessId(foreground, &foreground_pid);
		}
		if (foreground_pid == self_pid) {
			if (!g_hotkey_enabled) {
				f2_last_down = false;
				f3_last_down = false;
				f12_last_down = false;
				key7_last_down = false;
				key8_last_down = false;
				key9_last_down = false;
				key0_last_down = false;
				minus_last_down = false;
				fullscreen_hotkey_last_down = false;
				Sleep(kInputPollIntervalMs);
				continue;
			}
			bool f2_down = IsHotkeyDown(g_hotkey_toggle_transparent);
			bool f3_down = IsHotkeyDown(g_hotkey_toggle_fullscreen_attack);
			bool f12_down = IsHotkeyDown(g_hotkey_summon_doll);
			bool key7_down = IsHotkeyDown(g_hotkey_attract_mode1);
			bool key8_down = IsHotkeyDown(g_hotkey_attract_mode2);
			bool key9_down = IsHotkeyDown(g_hotkey_attract_mode3);
			bool key0_down = IsHotkeyDown(g_hotkey_attract_mode4);
			bool minus_down = IsHotkeyDown(g_hotkey_toggle_attract_direction);
			bool fullscreen_down = IsHotkeyDown(g_fullscreen_skill_hotkey);
			if (g_control_auto_transparent == kControlFollow && f2_down && !f2_last_down) {
				ToggleAutoTransparent();
			}
			if (g_control_fullscreen_attack == kControlFollow && f3_down && !f3_last_down) {
				ToggleFullscreenAttack();
			}
			if (f12_down && !f12_last_down) {
				TrySummonDoll();
			}
			if (g_control_attract == kControlFollow && key7_down && !key7_last_down) {
				ToggleAttractMode(kAttractModeAllToPlayer, L"开启吸怪配置1");
			}
			if (g_control_attract == kControlFollow && key8_down && !key8_last_down) {
				ToggleAttractMode(kAttractModeMonsterOffset80, L"开启吸怪配置2");
			}
			if (g_control_attract == kControlFollow && key9_down && !key9_last_down) {
				ToggleAttractMode(kAttractModeMonsterOffset150, L"开启吸怪配置3");
			}
			if (g_control_attract == kControlFollow && key0_down && !key0_last_down) {
				ToggleAttractMode(kAttractModeMonsterOffset300, L"开启吸怪配置4");
			}
			if (g_control_attract == kControlFollow && minus_down && !minus_last_down) {
				ToggleAttractDirection();
			}
			if (g_control_fullscreen_skill == kControlFollow && fullscreen_down && !fullscreen_hotkey_last_down) {
				ToggleFullscreenSkill();
			}
			f2_last_down = f2_down;
			f3_last_down = f3_down;
			f12_last_down = f12_down;
			key7_last_down = key7_down;
			key8_last_down = key8_down;
			key9_last_down = key9_down;
			key0_last_down = key0_down;
			minus_last_down = minus_down;
			fullscreen_hotkey_last_down = fullscreen_down;
		} else {
			f2_last_down = false;
			f3_last_down = false;
			f12_last_down = false;
			key7_last_down = false;
			key8_last_down = false;
			key9_last_down = false;
			key0_last_down = false;
			minus_last_down = false;
			fullscreen_hotkey_last_down = false;
		}
		Sleep(kInputPollIntervalMs);
	}
	return 0;
}

// 透明调用实现：参数/调用约定与旧逻辑保持一致。
static void CallTransparent(DWORD player_ptr) {
	DWORD call_address = kTransparentCallAddress;
	__asm {
		mov ecx, player_ptr
		mov esi, ecx
		push 0xFF
		push 0x01
		push 0x01
		push 0x01
		mov edx, call_address
		call edx
	}
}

// 写入劫持成功标记文件，文件内容为当前时间。
static BOOL WriteSuccessFile(const wchar_t* directory_path) {
	wchar_t dll_base_name[MAX_PATH] = {0};
	if (!GetModuleBaseName(g_self_module, dll_base_name, MAX_PATH)) {
		return FALSE;
	}
	wchar_t file_path[MAX_PATH] = {0};
	if (!BuildSuccessFilePath(directory_path, dll_base_name, GetCurrentProcessId(), file_path, MAX_PATH)) {
		return FALSE;
	}

	SYSTEMTIME local_time;
	ZeroMemory(&local_time, sizeof(local_time));
	GetLocalTime(&local_time);
	char content[64] = {0};
	int content_len = sprintf_s(
		content,
		"%04u-%02u-%02u %02u:%02u:%02u\r\n",
		local_time.wYear,
		local_time.wMonth,
		local_time.wDay,
		local_time.wHour,
		local_time.wMinute,
		local_time.wSecond);
	if (content_len <= 0) {
		return FALSE;
	}

	HANDLE file = CreateFileW(
		file_path,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (file == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	DWORD written = 0;
	WriteFile(file, content, (DWORD)content_len, &written, NULL);
	CloseHandle(file);
	return TRUE;
}

// 自动透明线程：复刻旧逻辑的状态机与节奏。
static DWORD WINAPI TransparentThread(LPVOID param) {
	UNREFERENCED_PARAMETER(param);
	int effect_state = 0;
	while (TRUE) {
		DWORD player_ptr = ReadDwordSafely(kPlayerBaseAddress);
		if (player_ptr == 0) {
			g_character_transparent = FALSE;
			effect_state = 0;
			Sleep(1000);
			continue;
		}

		if (IsInTownPlaceholder()) {
			g_character_transparent = FALSE;
			if (effect_state == 0) {
				effect_state = 1;
				ApplyEffectPlaceholder();
			}
		} else if (IsInBossRoomPlaceholder()) {
			g_character_transparent = FALSE;
		} else if (g_character_transparent == FALSE) {
			g_character_transparent = TRUE;
			CallTransparent(player_ptr);
			Sleep(500);
			ApplyScorePlaceholder();
			Sleep(500);
		}

		Sleep(kTransparentLoopIntervalMs);
	}
	return 0;
}

// 尝试解除透明状态，无法保证一定生效，仅做最佳努力。
static void TryClearTransparentState() {
	DWORD player_ptr = ReadDwordSafely(kPlayerBaseAddress);
	if (player_ptr != 0) {
		CallTransparent(player_ptr);
	}
	g_character_transparent = FALSE;
}

// 自动透明开关：对齐旧逻辑（开启/关闭线程）。
static void ToggleAutoTransparent() {
	if (g_auto_transparent_enabled == TRUE) {
		AnnouncePlaceholder(L"关闭自动透明");
		g_auto_transparent_enabled = FALSE;
		TryClearTransparentState();
		if (g_transparent_thread != NULL) {
			SuspendThread(g_transparent_thread);
			SetThreadPriority(g_transparent_thread, THREAD_PRIORITY_IDLE);
		}
		LogEvent("INFO", "auto_transparent", "disabled");
		return;
	}

	g_character_transparent = FALSE;
	if (g_transparent_thread == NULL) {
		g_transparent_thread = CreateThread(NULL, 0, TransparentThread, NULL, 0, NULL);
		if (g_transparent_thread == NULL) {
			LogEventWithError("transparent_thread", "create_failed", GetLastError());
			return;
		}
	} else {
		ResumeThread(g_transparent_thread);
	}
	g_auto_transparent_enabled = TRUE;
	AnnouncePlaceholder(L"开启自动透明");
	LogEvent("INFO", "auto_transparent", "enabled");
}

// 自动吸怪切换：相同配置再次触发则关闭。
static void ToggleAttractMode(int mode, const wchar_t* message) {
	if (mode <= kAttractModeOff || mode > kAttractModeMax) {
		return;
	}
	if (g_attract_mode == mode) {
		g_attract_mode = kAttractModeOff;
		AnnouncePlaceholder(L"关闭吸怪聚物");
		LogEvent("INFO", "attract_mode", "mode=0");
		return;
	}
	g_attract_mode = mode;
	g_attract_last_mode = g_attract_mode;
	if (message != NULL) {
		AnnouncePlaceholder(message);
	}
	char log_message[64] = {0};
	sprintf_s(log_message, sizeof(log_message), "mode=%d", g_attract_mode);
	LogEvent("INFO", "attract_mode", log_message);
}

// 吸怪方向切换：正向/负向。
static void ToggleAttractDirection() {
	g_attract_positive_enabled = !g_attract_positive_enabled;
	if (g_attract_positive_enabled) {
		AnnouncePlaceholder(L"吸怪方向：正向");
		LogEvent("INFO", "attract_direction", "positive");
		return;
	}
	AnnouncePlaceholder(L"吸怪方向：负向");
	LogEvent("INFO", "attract_direction", "negative");
}

static void SetAutoTransparentEnabled(BOOL enabled) {
	if (enabled) {
		if (!g_auto_transparent_enabled) {
			ToggleAutoTransparent();
		}
		return;
	}
	if (g_auto_transparent_enabled) {
		ToggleAutoTransparent();
	}
}

static void SetAttractEnabled(BOOL enabled) {
	if (enabled) {
		if (g_attract_mode == kAttractModeOff) {
			int mode = g_attract_last_mode;
			if (mode <= kAttractModeOff || mode > kAttractModeMax) {
				mode = kAttractModeAllToPlayer;
			}
			g_attract_mode = mode;
			g_attract_last_mode = g_attract_mode;
			char log_message[64] = {0};
			sprintf_s(log_message, sizeof(log_message), "mode=%d", g_attract_mode);
			LogEvent("INFO", "attract_mode", log_message);
		}
		return;
	}
	if (g_attract_mode != kAttractModeOff) {
		g_attract_last_mode = g_attract_mode;
		g_attract_mode = kAttractModeOff;
		LogEvent("INFO", "attract_mode", "mode=0");
	}
}

static BYTE NormalizeControlValue(BYTE value) {
	if (value == kControlForceOff || value == kControlForceOn) {
		return value;
	}
	return kControlFollow;
}

static void ApplyControlOverrides() {
	BOOL config_fullscreen_skill_enabled = g_config_snapshot_ready ? g_config_snapshot.enable_fullscreen_skill : g_fullscreen_skill_enabled;
	BOOL default_hotkey_enabled = g_config_snapshot_ready ? (g_config_snapshot.disable_input_thread ? FALSE : TRUE) : TRUE;
	if (g_control_hotkey_enabled == kControlForceOff) {
		g_hotkey_enabled = FALSE;
	} else if (g_control_hotkey_enabled == kControlForceOn) {
		g_hotkey_enabled = TRUE;
	} else {
		g_hotkey_enabled = default_hotkey_enabled;
	}

	if (g_control_fullscreen_attack == kControlForceOn) {
		SetFullscreenAttackTargetEnabled(TRUE);
	} else if (g_control_fullscreen_attack == kControlForceOff) {
		SetFullscreenAttackTargetEnabled(FALSE);
	}

	if (g_control_auto_transparent == kControlForceOn) {
		SetAutoTransparentEnabled(TRUE);
	} else if (g_control_auto_transparent == kControlForceOff) {
		SetAutoTransparentEnabled(FALSE);
	}

	if (g_control_attract == kControlForceOn) {
		SetAttractEnabled(TRUE);
	} else if (g_control_attract == kControlForceOff) {
		SetAttractEnabled(FALSE);
	}

	if (g_control_fullscreen_skill == kControlForceOn) {
		g_fullscreen_skill_enabled = TRUE;
		g_fullscreen_skill_active = TRUE;
	} else if (g_control_fullscreen_skill == kControlForceOff) {
		g_fullscreen_skill_enabled = config_fullscreen_skill_enabled;
		g_fullscreen_skill_active = FALSE;
	} else {
		g_fullscreen_skill_enabled = config_fullscreen_skill_enabled;
		if (!g_fullscreen_skill_enabled) {
			g_fullscreen_skill_active = FALSE;
		}
	}
}

// 应用配置到运行时变量，避免线程直接读结构体。
static void ApplyRuntimeConfig(const HelperConfig& config, BOOL reset_state) {
	g_config_snapshot = config;
	g_config_snapshot_ready = TRUE;
	if (reset_state) {
		// 全屏攻击默认关闭，由轮询线程维持目标状态。
		SetFullscreenAttackTargetEnabled(FALSE);
	}
	g_fullscreen_attack_poll_interval_ms = config.fullscreen_attack_poll_interval_ms;
	g_summon_enabled = config.enable_summon_doll;
	g_summon_monster_id = config.summon_monster_id;
	g_summon_level = config.summon_level;
	g_summon_cooldown_ms = config.summon_cooldown_ms;
	if (reset_state) {
		g_summon_last_tick = 0;
	}
	g_fullscreen_skill_enabled = config.enable_fullscreen_skill;
	g_fullscreen_skill_code = config.fullscreen_skill_code;
	g_fullscreen_skill_damage = config.fullscreen_skill_damage;
	g_fullscreen_skill_interval_ms = config.fullscreen_skill_interval_ms;
	g_fullscreen_skill_hotkey = config.fullscreen_skill_hotkey;
	if (reset_state) {
		g_fullscreen_skill_active = FALSE;
	}
	g_hotkey_toggle_transparent = config.hotkey_toggle_transparent;
	g_hotkey_toggle_fullscreen_attack = config.hotkey_toggle_fullscreen_attack;
	g_hotkey_summon_doll = config.hotkey_summon_doll;
	g_hotkey_attract_mode1 = config.hotkey_attract_mode1;
	g_hotkey_attract_mode2 = config.hotkey_attract_mode2;
	g_hotkey_attract_mode3 = config.hotkey_attract_mode3;
	g_hotkey_attract_mode4 = config.hotkey_attract_mode4;
	g_hotkey_toggle_attract_direction = config.hotkey_toggle_attract_direction;
	g_player_name_encoding = config.player_name_encoding;
	for (int i = 0; i <= kAttractModeMax; ++i) {
		g_monster_x_offset_by_mode[i] = config.monster_x_offset_by_mode[i];
	}
	ApplyControlOverrides();
}

// 配置热重载线程：检测 INI 变更并刷新运行时配置。
static DWORD WINAPI ConfigReloadThread(LPVOID param) {
	UNREFERENCED_PARAMETER(param);
	for (;;) {
		if (!g_config_path_ready) {
			Sleep(kConfigReloadIntervalMs);
			continue;
		}
		FILETIME last_write = {0};
		if (!GetFileLastWriteTime(g_config_path, &last_write)) {
			Sleep(kConfigReloadIntervalMs);
			continue;
		}
		if (CompareFileTime(&last_write, &g_config_last_write) != 0) {
			HelperConfig config = g_config_snapshot_ready ? g_config_snapshot : GetDefaultHelperConfig();
			if (LoadHelperConfig(g_config_path, &config)) {
				g_config_last_write = last_write;
				ApplyRuntimeConfig(config, FALSE);
				LogEvent("INFO", "config_reload", "ok");
			} else {
				LogEvent("WARN", "config_reload", "failed");
			}
		}
		Sleep(kConfigReloadIntervalMs);
	}
	return 0;
}

static void InitializeHelper(const wchar_t* output_directory, const HelperConfig& config) {
	if (config.safe_mode) {
		LogEvent("INFO", "safe_mode", "enabled");
		if (config.wipe_pe_header) {
			LogEvent("INFO", "module_header_wipe", "skip_by_safe_mode");
		}
		return;
	}

	ApplyRuntimeConfig(config, TRUE);

	if (config.wipe_pe_header) {
		if (WipeModuleHeader(g_self_module)) {
			LogEvent("INFO", "module_header_wipe", "ok");
		} else {
			LogEvent("WARN", "module_header_wipe", "failed");
		}
	} else {
		LogEvent("INFO", "module_header_wipe", "skip_by_config");
	}

	if (output_directory != NULL && output_directory[0] != L'\0') {
		if (WriteSuccessFile(output_directory)) {
			LogEvent("INFO", "success_file", "written");
		} else {
			LogEvent("WARN", "success_file", "write_failed");
		}
	} else {
		LogEvent("WARN", "success_file", "output_directory_missing");
	}

	if (SetFullscreenAttackEnabled(FALSE)) {
		LogEvent("INFO", "fullscreen_attack", "default_off");
	} else {
		LogEvent("WARN", "fullscreen_attack", "default_off_failed");
	}

	HANDLE fullscreen_attack_thread = CreateThread(NULL, 0, FullscreenAttackGuardThread, NULL, 0, NULL);
	if (fullscreen_attack_thread != NULL) {
		CloseHandle(fullscreen_attack_thread);
		LogEvent("INFO", "fullscreen_attack_thread", "started");
	} else {
		LogEventWithError("fullscreen_attack_thread", "create_failed", GetLastError());
	}

	HANDLE shared_memory_thread = CreateThread(NULL, 0, SharedMemoryWriterThread, NULL, 0, NULL);
	if (shared_memory_thread != NULL) {
		CloseHandle(shared_memory_thread);
		LogEvent("INFO", "shared_memory_thread", "started");
	} else {
		LogEventWithError("shared_memory_thread", "create_failed", GetLastError());
	}

	HANDLE control_thread = CreateThread(NULL, 0, ControlReaderThread, NULL, 0, NULL);
	if (control_thread != NULL) {
		CloseHandle(control_thread);
		LogEvent("INFO", "control_thread", "started");
	} else {
		LogEventWithError("control_thread", "create_failed", GetLastError());
	}

	HANDLE reload_thread = CreateThread(NULL, 0, ConfigReloadThread, NULL, 0, NULL);
	if (reload_thread != NULL) {
		CloseHandle(reload_thread);
		LogEvent("INFO", "config_reload_thread", "started");
	} else {
		LogEventWithError("config_reload_thread", "create_failed", GetLastError());
	}

	if (config.startup_delay_ms > 0) {
		char delay_message[64] = {0};
		sprintf_s(delay_message, sizeof(delay_message), "delay_ms=%lu", config.startup_delay_ms);
		LogEvent("INFO", "startup_delay", delay_message);
		Sleep(config.startup_delay_ms);
	}

	if (config.disable_input_thread) {
		LogEvent("INFO", "input_thread", "disabled_by_config");
	} else {
		HANDLE input_thread = CreateThread(NULL, 0, InputPollThread, NULL, 0, NULL);
		if (input_thread != NULL) {
			CloseHandle(input_thread);
			LogEvent("INFO", "input_thread", "started");
		} else {
			LogEventWithError("input_thread", "create_failed", GetLastError());
		}
	}

	if (config.disable_attract_thread) {
		LogEvent("INFO", "attract_thread", "config_disabled");
	}
	HANDLE attract_thread = CreateThread(NULL, 0, AutoAttractThread, NULL, 0, NULL);
	if (attract_thread != NULL) {
		CloseHandle(attract_thread);
		LogEvent("INFO", "attract_thread", "started");
	} else {
		LogEventWithError("attract_thread", "create_failed", GetLastError());
	}

	if (!config.enable_fullscreen_skill) {
		LogEvent("INFO", "fullscreen_skill_thread", "config_disabled");
	}
	HANDLE fullscreen_thread = CreateThread(NULL, 0, FullscreenSkillThread, NULL, 0, NULL);
	if (fullscreen_thread != NULL) {
		CloseHandle(fullscreen_thread);
		LogEvent("INFO", "fullscreen_skill_thread", "started");
	} else {
		LogEventWithError("fullscreen_skill_thread", "create_failed", GetLastError());
	}
}

// 在独立线程中执行初始化与循环，避免在 DllMain 中做阻塞或复杂操作。
static DWORD WINAPI WorkerThread(LPVOID param) {
	UNREFERENCED_PARAMETER(param);
	wchar_t exe_directory[MAX_PATH] = {0};
	BOOL has_exe_directory = GetExeDirectory(exe_directory, MAX_PATH);
	wchar_t module_directory[MAX_PATH] = {0};
	BOOL has_module_directory = GetModuleDirectory(g_self_module, module_directory, MAX_PATH);
	const wchar_t* default_output_directory = has_module_directory ? module_directory : (has_exe_directory ? exe_directory : NULL);

	HelperConfig config = GetDefaultHelperConfig();
	BOOL config_loaded = FALSE;
	wchar_t config_path[MAX_PATH] = {0};
	if (has_module_directory &&
		BuildConfigPath(module_directory, config_path, MAX_PATH) &&
		LoadHelperConfig(config_path, &config)) {
		config_loaded = TRUE;
	}

	if (!config_loaded && has_exe_directory &&
		BuildConfigPath(exe_directory, config_path, MAX_PATH) &&
		LoadHelperConfig(config_path, &config)) {
		config_loaded = TRUE;
	}

	if (config_loaded) {
		if (wcscpy_s(g_config_path, MAX_PATH, config_path) == 0 && GetFileLastWriteTime(g_config_path, &g_config_last_write)) {
			g_config_path_ready = TRUE;
		} else {
			g_config_path_ready = FALSE;
		}
	}

	const wchar_t* output_directory = default_output_directory;
	if (config.output_directory_set) {
		if (IsDirectoryValid(config.output_directory)) {
			output_directory = config.output_directory;
		} else {
			output_directory = default_output_directory;
		}
	}

	InitializeLogger(output_directory);
	LogEvent("INFO", "worker_thread", "start");
	if (!has_exe_directory) {
		LogEvent("WARN", "worker_thread", "exe_directory_not_found");
	}

	if (config_loaded) {
		LogEventWithPath("config_loaded", config_path);
	} else {
		LogEvent("INFO", "config_loaded", "default");
	}

	if (g_hide_module_result == kHideModuleResultOk) {
		LogEvent("INFO", "hide_module", "ok");
	} else if (g_hide_module_result == kHideModuleResultLdrMissing) {
		LogEvent("WARN", "hide_module", "ldr_missing");
	} else if (g_hide_module_result == kHideModuleResultNotFound) {
		LogEvent("WARN", "hide_module", "not_found");
	} else {
		LogEvent("WARN", "hide_module", "not_attempted");
	}

	if (config.output_directory_set && !IsDirectoryValid(config.output_directory)) {
		LogEventWithPath("output_dir_invalid", config.output_directory);
	}

	char config_message[220] = {0};
	sprintf_s(
		config_message,
		sizeof(config_message),
		"startup_delay_ms=%lu fullscreen_attack_poll_interval_ms=%lu safe_mode=%d wipe_pe_header=%d disable_input_thread=%d disable_attract_thread=%d apply_fullscreen_attack_patch_ignored=%d",
		config.startup_delay_ms,
		config.fullscreen_attack_poll_interval_ms,
		config.safe_mode,
		config.wipe_pe_header,
		config.disable_input_thread,
		config.disable_attract_thread,
		config.apply_fullscreen_attack_patch);
	LogEvent("INFO", "config_effective", config_message);

	char summon_message[160] = {0};
	sprintf_s(
		summon_message,
		sizeof(summon_message),
		"enable_summon_doll=%d summon_monster_id=%lu summon_level=%lu summon_cooldown_ms=%lu",
		config.enable_summon_doll,
		config.summon_monster_id,
		config.summon_level,
		config.summon_cooldown_ms);
	LogEvent("INFO", "config_summon", summon_message);

	char fullscreen_message[200] = {0};
	sprintf_s(
		fullscreen_message,
		sizeof(fullscreen_message),
		"enable_fullscreen_skill=%d skill_code=%lu skill_damage=%lu skill_interval_ms=%lu hotkey_vk=0x%02lX",
		config.enable_fullscreen_skill,
		config.fullscreen_skill_code,
		config.fullscreen_skill_damage,
		config.fullscreen_skill_interval_ms,
		config.fullscreen_skill_hotkey);
	LogEvent("INFO", "config_fullscreen", fullscreen_message);

	char attract_message[200] = {0};
	sprintf_s(
		attract_message,
		sizeof(attract_message),
		"monster_x_offset_mode1=%.1f monster_x_offset_mode2=%.1f monster_x_offset_mode3=%.1f monster_x_offset_mode4=%.1f",
		config.monster_x_offset_by_mode[1],
		config.monster_x_offset_by_mode[2],
		config.monster_x_offset_by_mode[3],
		config.monster_x_offset_by_mode[4]);
	LogEvent("INFO", "config_attract", attract_message);

	char hotkey_message[240] = {0};
	sprintf_s(
		hotkey_message,
		sizeof(hotkey_message),
		"toggle_transparent=0x%02lX toggle_fullscreen_attack=0x%02lX summon_doll=0x%02lX attract1=0x%02lX attract2=0x%02lX attract3=0x%02lX attract4=0x%02lX toggle_attract_dir=0x%02lX fullscreen_skill=0x%02lX",
		config.hotkey_toggle_transparent,
		config.hotkey_toggle_fullscreen_attack,
		config.hotkey_summon_doll,
		config.hotkey_attract_mode1,
		config.hotkey_attract_mode2,
		config.hotkey_attract_mode3,
		config.hotkey_attract_mode4,
		config.hotkey_toggle_attract_direction,
		config.fullscreen_skill_hotkey);
	LogEvent("INFO", "config_hotkey", hotkey_message);

	if (output_directory != NULL) {
		LogEventWithPath("output_directory", output_directory);
	}

	InitializeHelper(output_directory, config);
	return 0;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
	UNREFERENCED_PARAMETER(reserved);

	if (reason == DLL_PROCESS_ATTACH) {
		g_self_module = module;
		// 先断链隐藏模块，降低被模块枚举发现的概率。
		g_hide_module_result = HideModule(module);
		// 避免线程通知开销，并把工作放到新线程，降低加载期风险。
		DisableThreadLibraryCalls(module);
		HANDLE thread = CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
		if (thread != NULL) {
			CloseHandle(thread);
		}
	}

	return TRUE;
}
