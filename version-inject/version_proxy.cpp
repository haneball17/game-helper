#include <windows.h>
#include <stdio.h>
#include <wchar.h>

#include "version_exports.h"

// 在独立线程中执行文件写入，避免在 DllMain 中做阻塞或复杂操作。
static DWORD WINAPI WriteSuccessFileThread(LPVOID param) {
	UNREFERENCED_PARAMETER(param);
	// 获取 exe 所在目录，后续将标记文件写到该目录。
	wchar_t exe_path[MAX_PATH] = {0};
	DWORD length = GetModuleFileNameW(NULL, exe_path, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		return 0;
	}

	// 截断为目录路径，保留末尾反斜杠，便于直接拼接文件名。
	wchar_t* last_slash = wcsrchr(exe_path, L'\\');
	if (last_slash == NULL) {
		last_slash = wcsrchr(exe_path, L'/');
	}
	if (last_slash == NULL) {
		return 0;
	}
	*(last_slash + 1) = L'\0';

	// 组合目标文件路径：<exe目录>\test_success.txt
	wchar_t file_path[MAX_PATH] = {0};
	if (wcscpy_s(file_path, MAX_PATH, exe_path) != 0) {
		return 0;
	}
	if (wcscat_s(file_path, MAX_PATH, L"test_success.txt") != 0) {
		return 0;
	}

	// 生成可读时间戳，写入文件作为劫持成功标记。
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
		return 0;
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
		return 0;
	}

	DWORD written = 0;
	WriteFile(file, content, (DWORD)content_len, &written, NULL);
	CloseHandle(file);
	return 0;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
	UNREFERENCED_PARAMETER(reserved);

	if (reason == DLL_PROCESS_ATTACH) {
		// 避免线程通知开销，并把工作放到新线程，降低加载期风险。
		DisableThreadLibraryCalls(module);
		HANDLE thread = CreateThread(NULL, 0, WriteSuccessFileThread, NULL, 0, NULL);
		if (thread != NULL) {
			CloseHandle(thread);
		}
	}

	return TRUE;
}
