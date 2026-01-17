#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>

#include "version_exports.h"

// 透明功能的绝对地址配置（x86）。

// 人物基址
static const DWORD kPlayerBaseAddress = 0x01AC790C;

// 透明调用地址
static const DWORD kTransparentCallAddress = 0x011499E0;

// 透明循环间隔
static const DWORD kTransparentLoopIntervalMs = 4000;

// 全屏攻击补丁地址
static const DWORD kFullScreenAttackPatchAddress = 0x00825282;

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
static const DWORD kTypeOffset = 0x94;
static const DWORD kPositionXOffset = 0x18C;
static const DWORD kPositionYOffset = 0x190;
static const int kTypeItem = 289;
static const int kTypeMonster = 529;
static const int kTypeMonsterBuilding = 545;
static const int kTypeApc = 273;
static const int kMaxObjectCount = 8192;
static const int kAttractBurstCount = 15;
static const DWORD kAttractBurstIntervalMs = 20;

static BOOL g_auto_transparent_enabled = FALSE;
// 透明线程
static HANDLE g_transparent_thread = NULL;
static BOOL g_character_transparent = FALSE;
static BYTE g_fullscreen_attack_off_patch[kFullscreenAttackPatchSize] = {0};
static BOOL g_fullscreen_attack_off_patch_set = FALSE;

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
		return;
	}
	RememberFullscreenAttackOffBytes(current);
	if (IsFullscreenAttackOffBytes(current)) {
		if (SetFullscreenAttackEnabled(TRUE)) {
			AnnouncePlaceholder(L"开启全屏攻击");
		}
		return;
	}
	if (memcmp(current, kFullscreenAttackPatchOn, kFullscreenAttackPatchSize) == 0) {
		if (SetFullscreenAttackEnabled(FALSE)) {
			AnnouncePlaceholder(L"关闭全屏攻击");
		}
		return;
	}
}

// 吸怪聚物：遍历对象并把怪物/物品坐标拉到人物坐标。
static void AttractMonstersAndItems() {
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
	for (int i = 1; i <= count; i++) {
		DWORD object_ptr = ReadDwordSafely(start_ptr + 4 * i);
		if (object_ptr == 0 || object_ptr == player_ptr) {
			continue;
		}
		int type = (int)ReadDwordSafely(object_ptr + kTypeOffset);
		if (type == kTypeMonster || type == kTypeMonsterBuilding || type == kTypeApc || type == kTypeItem) {
			WriteFloatSafely(object_ptr + kPositionXOffset, player_x);
			WriteFloatSafely(object_ptr + kPositionYOffset, player_y);
		}
	}
}

// 吸怪聚物短时高频写入：抵消游戏对坐标的快速回写。
static void AttractMonstersAndItemsBurst() {
	for (int i = 0; i < kAttractBurstCount; i++) {
		AttractMonstersAndItems();
		if (i + 1 < kAttractBurstCount) {
			Sleep(kAttractBurstIntervalMs);
		}
	}
}

// 前台窗口输入轮询：仅当前进程前台时响应按键，避免多开冲突。
static void ToggleAutoTransparent();

static DWORD WINAPI InputPollThread(LPVOID param) {
	UNREFERENCED_PARAMETER(param);
	DWORD self_pid = GetCurrentProcessId();
	bool f2_last_down = false;
	bool f3_last_down = false;
	bool f4_last_down = false;
	while (TRUE) {
		HWND foreground = GetForegroundWindow();
		DWORD foreground_pid = 0;
		if (foreground != NULL) {
			GetWindowThreadProcessId(foreground, &foreground_pid);
		}
		if (foreground_pid == self_pid) {
			SHORT f2_state = GetAsyncKeyState(VK_F2);
			SHORT f3_state = GetAsyncKeyState(VK_F3);
			SHORT f4_state = GetAsyncKeyState(VK_F4);
			bool f2_down = (f2_state & 0x8000) != 0;
			bool f3_down = (f3_state & 0x8000) != 0;
			bool f4_down = (f4_state & 0x8000) != 0;
			if (f2_down && !f2_last_down) {
				ToggleAutoTransparent();
			}
			if (f3_down && !f3_last_down) {
				ToggleFullscreenAttack();
			}
			if (f4_down && !f4_last_down) {
				AttractMonstersAndItemsBurst();
			}
			f2_last_down = f2_down;
			f3_last_down = f3_down;
			f4_last_down = f4_down;
		} else {
			f2_last_down = false;
			f3_last_down = false;
			f4_last_down = false;
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
static void WriteSuccessFile(const wchar_t* directory_path) {
	wchar_t file_path[MAX_PATH] = {0};
	if (wcscpy_s(file_path, MAX_PATH, directory_path) != 0) {
		return;
	}
	if (wcscat_s(file_path, MAX_PATH, L"test_success.txt") != 0) {
		return;
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
		return;
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
		return;
	}

	DWORD written = 0;
	WriteFile(file, content, (DWORD)content_len, &written, NULL);
	CloseHandle(file);
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
		return;
	}

	g_character_transparent = FALSE;
	if (g_transparent_thread == NULL) {
		g_transparent_thread = CreateThread(NULL, 0, TransparentThread, NULL, 0, NULL);
		if (g_transparent_thread == NULL) {
			return;
		}
	} else {
		ResumeThread(g_transparent_thread);
	}
	g_auto_transparent_enabled = TRUE;
	AnnouncePlaceholder(L"开启自动透明");
}

// 在独立线程中执行初始化与循环，避免在 DllMain 中做阻塞或复杂操作。
static DWORD WINAPI WorkerThread(LPVOID param) {
	UNREFERENCED_PARAMETER(param);
	// 获取 exe 所在目录，后续将标记文件写到该目录。
	wchar_t exe_path[MAX_PATH] = {0};
	DWORD length = GetModuleFileNameW(NULL, exe_path, MAX_PATH);
	if (length > 0 && length < MAX_PATH) {
		// 截断为目录路径，保留末尾反斜杠，便于直接拼接文件名。
		wchar_t* last_slash = wcsrchr(exe_path, L'\\');
		if (last_slash == NULL) {
			last_slash = wcsrchr(exe_path, L'/');
		}
		if (last_slash != NULL) {
			*(last_slash + 1) = L'\0';
			WriteSuccessFile(exe_path);
		}
	}

	SetFullscreenAttackEnabled(FALSE);
	HANDLE input_thread = CreateThread(NULL, 0, InputPollThread, NULL, 0, NULL);
	if (input_thread != NULL) {
		CloseHandle(input_thread);
	}
	return 0;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
	UNREFERENCED_PARAMETER(reserved);

	if (reason == DLL_PROCESS_ATTACH) {
		// 避免线程通知开销，并把工作放到新线程，降低加载期风险。
		DisableThreadLibraryCalls(module);
		HANDLE thread = CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
		if (thread != NULL) {
			CloseHandle(thread);
		}
	}

	return TRUE;
}
