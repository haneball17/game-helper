#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>
#include <stdlib.h>

#include "version_exports.h"

// 透明功能的绝对地址配置（x86）。

// 人物基址
static const DWORD kPlayerBaseAddress = 0x01AC790C;

// 全屏攻击补丁地址
static const DWORD kFullScreenAttackPatchAddress = 0x00825282;

// 透明调用地址
static const DWORD kTransparentCallAddress = 0x011499E0;

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

// 输入轮询间隔
static const DWORD kInputPollIntervalMs = 30;

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
// 怪物 X 坐标偏移配置（索引为配置模式）
static const float kMonsterXOffsetByMode[kAttractModeMax + 1] = {0.0f, 0.0f, 80.0f, 150.0f, 250.0f};

static BOOL g_auto_transparent_enabled = FALSE;
// 自动吸怪配置（0 为关闭）
static int g_attract_mode = kAttractModeOff;
// 透明线程
static HANDLE g_transparent_thread = NULL;
static BOOL g_character_transparent = FALSE;
static BYTE g_fullscreen_attack_off_patch[kFullscreenAttackPatchSize] = {0};
static BOOL g_fullscreen_attack_off_patch_set = FALSE;
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

struct HelperConfig {
	DWORD startup_delay_ms;
	BOOL apply_fullscreen_attack_patch;
};

static HelperConfig GetDefaultHelperConfig() {
	HelperConfig config = {0};
	config.startup_delay_ms = 0;
	config.apply_fullscreen_attack_patch = TRUE;
	return config;
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

static BOOL LoadHelperConfig(const wchar_t* config_path, HelperConfig* config) {
	if (config == NULL || config_path == NULL || config_path[0] == L'\0') {
		return FALSE;
	}
	DWORD attrs = GetFileAttributesW(config_path);
	if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
		return FALSE;
	}
	config->startup_delay_ms = ReadIniUInt32(config_path, L"startup", L"startup_delay_ms", config->startup_delay_ms);
	config->apply_fullscreen_attack_patch = ReadIniBool(config_path, L"patch", L"apply_fullscreen_attack_patch", config->apply_fullscreen_attack_patch);
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

static void ToggleFullscreenAttack() {
	BYTE current[2] = {0};
	if (!ReadBytesSafely(kFullScreenAttackPatchAddress, current, sizeof(current))) {
		LogEvent("WARN", "fullscreen_attack", "read_failed");
		return;
	}
	RememberFullscreenAttackOffBytes(current);
	if (IsFullscreenAttackOffBytes(current)) {
		if (SetFullscreenAttackEnabled(TRUE)) {
			AnnouncePlaceholder(L"开启全屏攻击");
			LogEvent("INFO", "fullscreen_attack", "enabled");
		} else {
			LogEvent("WARN", "fullscreen_attack", "enable_failed");
		}
		return;
	}
	if (memcmp(current, kFullscreenAttackPatchOn, kFullscreenAttackPatchSize) == 0) {
		if (SetFullscreenAttackEnabled(FALSE)) {
			AnnouncePlaceholder(L"关闭全屏攻击");
			LogEvent("INFO", "fullscreen_attack", "disabled");
		} else {
			LogEvent("WARN", "fullscreen_attack", "disable_failed");
		}
		return;
	}
	LogEvent("WARN", "fullscreen_attack", "state_unknown");
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
	float monster_x = player_x + kMonsterXOffsetByMode[mode];
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

// 前台窗口输入轮询：仅当前进程前台时响应按键，避免多开冲突。
static void ToggleAutoTransparent();
static void ToggleAttractMode(int mode, const wchar_t* message);

static DWORD WINAPI InputPollThread(LPVOID param) {
	UNREFERENCED_PARAMETER(param);
	DWORD self_pid = GetCurrentProcessId();
	bool f2_last_down = false;
	bool f3_last_down = false;
	bool key7_last_down = false;
	bool key8_last_down = false;
	bool key9_last_down = false;
	bool key0_last_down = false;
	while (TRUE) {
		HWND foreground = GetForegroundWindow();
		DWORD foreground_pid = 0;
		if (foreground != NULL) {
			GetWindowThreadProcessId(foreground, &foreground_pid);
		}
		if (foreground_pid == self_pid) {
			SHORT f2_state = GetAsyncKeyState(VK_F2);
			SHORT f3_state = GetAsyncKeyState(VK_F3);
			SHORT key7_state = GetAsyncKeyState('7');
			SHORT key8_state = GetAsyncKeyState('8');
			SHORT key9_state = GetAsyncKeyState('9');
			SHORT key0_state = GetAsyncKeyState('0');
			bool f2_down = (f2_state & 0x8000) != 0;
			bool f3_down = (f3_state & 0x8000) != 0;
			bool key7_down = (key7_state & 0x8000) != 0;
			bool key8_down = (key8_state & 0x8000) != 0;
			bool key9_down = (key9_state & 0x8000) != 0;
			bool key0_down = (key0_state & 0x8000) != 0;
			if (f2_down && !f2_last_down) {
				ToggleAutoTransparent();
			}
			if (f3_down && !f3_last_down) {
				ToggleFullscreenAttack();
			}
			if (key7_down && !key7_last_down) {
				ToggleAttractMode(kAttractModeAllToPlayer, L"开启吸怪配置1");
			}
			if (key8_down && !key8_last_down) {
				ToggleAttractMode(kAttractModeMonsterOffset80, L"开启吸怪配置2");
			}
			if (key9_down && !key9_last_down) {
				ToggleAttractMode(kAttractModeMonsterOffset150, L"开启吸怪配置3");
			}
			if (key0_down && !key0_last_down) {
				ToggleAttractMode(kAttractModeMonsterOffset300, L"开启吸怪配置4");
			}
			f2_last_down = f2_down;
			f3_last_down = f3_down;
			key7_last_down = key7_down;
			key8_last_down = key8_down;
			key9_last_down = key9_down;
			key0_last_down = key0_down;
		} else {
			f2_last_down = false;
			f3_last_down = false;
			key7_last_down = false;
			key8_last_down = false;
			key9_last_down = false;
			key0_last_down = false;
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
	wchar_t file_path[MAX_PATH] = {0};
	if (wcscpy_s(file_path, MAX_PATH, directory_path) != 0) {
		return FALSE;
	}
	if (wcscat_s(file_path, MAX_PATH, L"test_success.txt") != 0) {
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
	if (message != NULL) {
		AnnouncePlaceholder(message);
	}
	char log_message[64] = {0};
	sprintf_s(log_message, sizeof(log_message), "mode=%d", g_attract_mode);
	LogEvent("INFO", "attract_mode", log_message);
}

static void InitializeHelper(const wchar_t* exe_directory, const HelperConfig& config) {
	if (exe_directory != NULL && exe_directory[0] != L'\0') {
		if (WriteSuccessFile(exe_directory)) {
			LogEvent("INFO", "success_file", "written");
		} else {
			LogEvent("WARN", "success_file", "write_failed");
		}
	} else {
		LogEvent("WARN", "success_file", "exe_directory_missing");
	}

	if (config.startup_delay_ms > 0) {
		char delay_message[64] = {0};
		sprintf_s(delay_message, sizeof(delay_message), "delay_ms=%lu", config.startup_delay_ms);
		LogEvent("INFO", "startup_delay", delay_message);
		Sleep(config.startup_delay_ms);
	}

	if (config.apply_fullscreen_attack_patch) {
		if (SetFullscreenAttackEnabled(FALSE)) {
			LogEvent("INFO", "fullscreen_attack", "reset_ok");
		} else {
			LogEvent("WARN", "fullscreen_attack", "reset_failed");
		}
	} else {
		LogEvent("INFO", "fullscreen_attack", "skip_by_config");
	}

	HANDLE input_thread = CreateThread(NULL, 0, InputPollThread, NULL, 0, NULL);
	if (input_thread != NULL) {
		CloseHandle(input_thread);
		LogEvent("INFO", "input_thread", "started");
	} else {
		LogEventWithError("input_thread", "create_failed", GetLastError());
	}

	HANDLE attract_thread = CreateThread(NULL, 0, AutoAttractThread, NULL, 0, NULL);
	if (attract_thread != NULL) {
		CloseHandle(attract_thread);
		LogEvent("INFO", "attract_thread", "started");
	} else {
		LogEventWithError("attract_thread", "create_failed", GetLastError());
	}
}

// 在独立线程中执行初始化与循环，避免在 DllMain 中做阻塞或复杂操作。
static DWORD WINAPI WorkerThread(LPVOID param) {
	UNREFERENCED_PARAMETER(param);
	wchar_t exe_directory[MAX_PATH] = {0};
	BOOL has_exe_directory = GetExeDirectory(exe_directory, MAX_PATH);
	if (has_exe_directory) {
		InitializeLogger(exe_directory);
	} else {
		InitializeLogger(NULL);
	}

	LogEvent("INFO", "worker_thread", "start");
	if (!has_exe_directory) {
		LogEvent("WARN", "worker_thread", "exe_directory_not_found");
	}

	HelperConfig config = GetDefaultHelperConfig();
	BOOL config_loaded = FALSE;
	wchar_t config_path[MAX_PATH] = {0};
	wchar_t module_directory[MAX_PATH] = {0};
	if (GetModuleDirectory(g_self_module, module_directory, MAX_PATH) &&
		BuildConfigPath(module_directory, config_path, MAX_PATH) &&
		LoadHelperConfig(config_path, &config)) {
		config_loaded = TRUE;
		LogEventWithPath("config_loaded", config_path);
	}

	if (!config_loaded && has_exe_directory &&
		BuildConfigPath(exe_directory, config_path, MAX_PATH) &&
		LoadHelperConfig(config_path, &config)) {
		config_loaded = TRUE;
		LogEventWithPath("config_loaded", config_path);
	}

	if (!config_loaded) {
		LogEvent("INFO", "config_loaded", "default");
	}

	char config_message[128] = {0};
	sprintf_s(
		config_message,
		sizeof(config_message),
		"startup_delay_ms=%lu apply_fullscreen_attack_patch=%d",
		config.startup_delay_ms,
		config.apply_fullscreen_attack_patch);
	LogEvent("INFO", "config_effective", config_message);

	InitializeHelper(has_exe_directory ? exe_directory : NULL, config);
	return 0;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
	UNREFERENCED_PARAMETER(reserved);

	if (reason == DLL_PROCESS_ATTACH) {
		g_self_module = module;
		// 避免线程通知开销，并把工作放到新线程，降低加载期风险。
		DisableThreadLibraryCalls(module);
		HANDLE thread = CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
		if (thread != NULL) {
			CloseHandle(thread);
		}
	}

	return TRUE;
}
