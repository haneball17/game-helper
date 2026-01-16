#include <windows.h>
#include <stdio.h>
#include <wchar.h>

#include "version_exports.h"

// 透明功能的绝对地址配置（x86）。
static const DWORD kPlayerBaseAddress = 0x01AC790C;
static const DWORD kTransparentCallAddress = 0x011499E0;
static const DWORD kTransparentLoopIntervalMs = 4000;

static BOOL g_auto_transparent_enabled = FALSE;
static HANDLE g_transparent_thread = NULL;
static BOOL g_character_transparent = FALSE;

// 安全读取 DWORD，避免地址无效时导致进程崩溃。
static DWORD ReadDwordSafely(DWORD address) {
	__try {
		return *(DWORD*)address;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return 0;
	}
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

// F2 热键消息循环：触发自动透明开关。
static DWORD WINAPI HotkeyThread(LPVOID param) {
	UNREFERENCED_PARAMETER(param);
	if (!RegisterHotKey(NULL, 1, 0, VK_F2)) {
		return 0;
	}

	MSG msg = {0};
	while (GetMessage(&msg, NULL, 0, 0) > 0) {
		if (msg.message == WM_HOTKEY && msg.wParam == 1) {
			if (LOWORD(msg.lParam) == 0 && HIWORD(msg.lParam) == VK_F2) {
				ToggleAutoTransparent();
			}
		}
	}

	UnregisterHotKey(NULL, 1);
	return 0;
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

	HANDLE hotkey_thread = CreateThread(NULL, 0, HotkeyThread, NULL, 0, NULL);
	if (hotkey_thread != NULL) {
		CloseHandle(hotkey_thread);
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
