#include "stdafx.h"
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <cwctype>

struct InjectorConfig {
	std::wstring process_name;
	std::wstring dll_path;
	std::vector<std::wstring> dll_paths;
	DWORD scan_interval_ms;
	DWORD inject_delay_ms;
	DWORD inject_interval_ms;
	int max_retries;
	DWORD retry_interval_ms;
	DWORD module_check_timeout_ms;
	DWORD module_check_interval_ms;
	DWORD module_check_extend_ms;
	bool success_check_enabled;
	std::wstring success_file_dir;
	std::wstring success_file_name;
	bool watch_mode;
	bool exit_when_no_processes;
	std::wstring log_path;
	std::string log_level;
	bool log_pid_list;
	bool console_output;
	bool file_output;
};

struct LogExtras {
	DWORD pid;
	DWORD tid;
	int attempt;
	int thread_count;
	int queued_count;
	DWORD error_code;
	std::wstring process_name;
	std::wstring dll_path;
	std::string result;

	LogExtras()
		: pid(0),
		  tid(0),
		  attempt(-1),
		  thread_count(-1),
		  queued_count(-1),
		  error_code(0) {}
};

static std::wstring GetExeDirectory() {
	wchar_t buffer[MAX_PATH] = {0};
	DWORD length = GetModuleFileNameW(NULL, buffer, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		return L"";
	}
	wchar_t* last_slash = wcsrchr(buffer, L'\\');
	if (last_slash == NULL) {
		last_slash = wcsrchr(buffer, L'/');
	}
	if (last_slash == NULL) {
		return L"";
	}
	*(last_slash + 1) = L'\0';
	return buffer;
}

static bool IsAbsolutePath(const std::wstring& path) {
	if (path.size() >= 2 && path[1] == L':') {
		return true;
	}
	if (!path.empty() && (path[0] == L'\\' || path[0] == L'/')) {
		return true;
	}
	return false;
}

static std::wstring JoinPathSafe(const std::wstring& left, const std::wstring& right) {
	if (left.empty()) {
		return right;
	}
	if (right.empty()) {
		return left;
	}
	std::wstring result = left;
	wchar_t last = result[result.size() - 1];
	if (last != L'\\' && last != L'/') {
		result.push_back(L'\\');
	}
	result.append(right);
	return result;
}

static std::wstring ReadIniStringValue(const std::wstring& path, const wchar_t* section, const wchar_t* key, const wchar_t* default_value) {
	wchar_t buffer[512] = {0};
	DWORD read = GetPrivateProfileStringW(section, key, default_value, buffer, static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0])), path.c_str());
	return std::wstring(buffer, buffer + read);
}

static DWORD ReadIniUInt32(const std::wstring& path, const wchar_t* section, const wchar_t* key, DWORD default_value) {
	std::wstring value = ReadIniStringValue(path, section, key, L"");
	if (value.empty()) {
		return default_value;
	}
	wchar_t* end = NULL;
	unsigned long parsed = wcstoul(value.c_str(), &end, 10);
	if (end == value.c_str()) {
		return default_value;
	}
	return static_cast<DWORD>(parsed);
}

static std::wstring NormalizePath(const std::wstring& path, const std::wstring& base_dir) {
	if (path.empty()) {
		return path;
	}
	std::wstring candidate = path;
	if (!IsAbsolutePath(candidate)) {
		candidate = JoinPathSafe(base_dir, candidate);
	}
	wchar_t full_path[MAX_PATH] = {0};
	DWORD length = GetFullPathNameW(candidate.c_str(), MAX_PATH, full_path, NULL);
	if (length == 0 || length >= MAX_PATH) {
		return candidate;
	}
	return full_path;
}

static std::wstring GetDirectoryPath(const std::wstring& path) {
	if (path.empty()) {
		return L"";
	}
	size_t pos = path.find_last_of(L"\\/");
	if (pos == std::wstring::npos) {
		return L"";
	}
	return path.substr(0, pos + 1);
}

static std::wstring GetBaseName(const std::wstring& path) {
	if (path.empty()) {
		return L"";
	}
	size_t pos = path.find_last_of(L"\\/");
	if (pos == std::wstring::npos) {
		return path;
	}
	return path.substr(pos + 1);
}

static std::wstring GetBaseNameWithoutExtension(const std::wstring& path) {
	std::wstring base_name = GetBaseName(path);
	if (base_name.empty()) {
		return L"";
	}
	size_t dot = base_name.find_last_of(L'.');
	if (dot == std::wstring::npos) {
		return base_name;
	}
	return base_name.substr(0, dot);
}

static std::wstring TrimWide(const std::wstring& input) {
	size_t start = 0;
	while (start < input.size() && iswspace(input[start])) {
		++start;
	}
	size_t end = input.size();
	while (end > start && iswspace(input[end - 1])) {
		--end;
	}
	return input.substr(start, end - start);
}

static std::wstring StripQuotes(const std::wstring& input) {
	if (input.size() >= 2) {
		wchar_t first = input.front();
		wchar_t last = input.back();
		if ((first == L'"' && last == L'"') || (first == L'\'' && last == L'\'')) {
			return input.substr(1, input.size() - 2);
		}
	}
	return input;
}

static std::wstring ReplaceAll(const std::wstring& input, const std::wstring& token, const std::wstring& value) {
	if (token.empty()) {
		return input;
	}
	std::wstring result = input;
	size_t pos = 0;
	while ((pos = result.find(token, pos)) != std::wstring::npos) {
		result.replace(pos, token.size(), value);
		pos += value.size();
	}
	return result;
}

static bool ContainsPathInsensitive(const std::vector<std::wstring>& items, const std::wstring& value) {
	for (size_t i = 0; i < items.size(); ++i) {
		if (_wcsicmp(items[i].c_str(), value.c_str()) == 0) {
			return true;
		}
	}
	return false;
}

static std::vector<std::wstring> ParseDllPathList(const std::wstring& raw, const std::wstring& base_dir) {
	// 解析 DLL 列表：支持分号分隔、去空白、去重、相对路径归一化
	std::vector<std::wstring> results;
	if (raw.empty()) {
		return results;
	}
	size_t start = 0;
	while (start <= raw.size()) {
		size_t pos = raw.find(L';', start);
		std::wstring item = (pos == std::wstring::npos) ? raw.substr(start) : raw.substr(start, pos - start);
		item = StripQuotes(TrimWide(item));
		if (!item.empty()) {
			std::wstring normalized = NormalizePath(item, base_dir);
			if (!ContainsPathInsensitive(results, normalized)) {
				results.push_back(normalized);
			}
		}
		if (pos == std::wstring::npos) {
			break;
		}
		start = pos + 1;
	}
	return results;
}

static std::vector<std::wstring> BuildDllPathList(const std::wstring& multi_value, const std::wstring& single_value, const std::wstring& base_dir) {
	std::vector<std::wstring> results = ParseDllPathList(multi_value, base_dir);
	if (!results.empty()) {
		return results;
	}
	std::wstring fallback = TrimWide(single_value);
	if (fallback.empty()) {
		fallback = L"GameHelper.dll";
	}
	results = ParseDllPathList(fallback, base_dir);
	if (results.empty()) {
		results.push_back(NormalizePath(L"GameHelper.dll", base_dir));
	}
	return results;
}

static std::wstring BuildSuccessFilePath(const InjectorConfig& settings, DWORD pid, const std::wstring& dll_path) {
	if (!settings.success_check_enabled) {
		return L"";
	}
	std::wstring file_name = settings.success_file_name;
	if (file_name.empty()) {
		file_name = L"successfile_%dll.name%_%pid%.txt";
	}
	std::wstring dll_name = GetBaseNameWithoutExtension(dll_path);
	if (dll_name.empty()) {
		return L"";
	}
	std::wstring pid_text = std::to_wstring(pid);
	file_name = ReplaceAll(file_name, L"%pid%", pid_text);
	file_name = ReplaceAll(file_name, L"%dll.name%", dll_name);
	if (file_name.empty()) {
		return L"";
	}
	if (IsAbsolutePath(file_name)) {
		return file_name;
	}
	std::wstring base_dir = settings.success_file_dir;
	if (base_dir.empty()) {
		base_dir = GetDirectoryPath(dll_path);
	}
	if (base_dir.empty()) {
		return L"";
	}
	return JoinPathSafe(base_dir, file_name);
}

static bool IsSuccessFilePresent(const InjectorConfig& settings, DWORD pid, const std::wstring& dll_path) {
	std::wstring success_file_path = BuildSuccessFilePath(settings, pid, dll_path);
	if (success_file_path.empty()) {
		return false;
	}
	DWORD attrs = GetFileAttributesW(success_file_path.c_str());
	return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

static std::string BuildPidListMessage(const std::vector<DWORD>& pids) {
	std::string message = "count=" + std::to_string(pids.size()) + " pids=";
	for (size_t i = 0; i < pids.size(); ++i) {
		message += std::to_string(pids[i]);
		if (i + 1 < pids.size()) {
			message += ",";
		}
	}
	return message;
}

static std::string BuildPidListHash(const std::vector<DWORD>& pids) {
	std::string hash;
	hash.reserve(pids.size() * 12);
	for (size_t i = 0; i < pids.size(); ++i) {
		hash += std::to_string(pids[i]);
		hash += ",";
	}
	return hash;
}

static bool ParseBool(const std::wstring& value, bool default_value) {
	if (value.empty()) {
		return default_value;
	}
	if (_wcsicmp(value.c_str(), L"1") == 0 ||
		_wcsicmp(value.c_str(), L"true") == 0 ||
		_wcsicmp(value.c_str(), L"yes") == 0 ||
		_wcsicmp(value.c_str(), L"on") == 0) {
		return true;
	}
	if (_wcsicmp(value.c_str(), L"0") == 0 ||
		_wcsicmp(value.c_str(), L"false") == 0 ||
		_wcsicmp(value.c_str(), L"no") == 0 ||
		_wcsicmp(value.c_str(), L"off") == 0) {
		return false;
	}
	return default_value;
}

static std::string WideToUtf8(const std::wstring& input) {
	if (input.empty()) {
		return std::string();
	}
	int length = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, NULL, 0, NULL, NULL);
	if (length <= 0) {
		return std::string();
	}
	std::string output;
	output.resize(static_cast<size_t>(length - 1));
	WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, &output[0], length, NULL, NULL);
	return output;
}

static std::string EscapeJson(const std::string& input) {
	std::string output;
	output.reserve(input.size() + 16);
	for (unsigned char ch : input) {
		switch (ch) {
			case '\\':
			case '"':
				output.push_back('\\');
				output.push_back(static_cast<char>(ch));
				break;
			case '\n':
				output.append("\\n");
				break;
			case '\r':
				output.append("\\r");
				break;
			case '\t':
				output.append("\\t");
				break;
			default:
				if (ch < 0x20) {
					output.push_back('?');
				} else {
					output.push_back(static_cast<char>(ch));
				}
				break;
		}
	}
	return output;
}

static std::string FormatTimestamp() {
	SYSTEMTIME local_time;
	ZeroMemory(&local_time, sizeof(local_time));
	GetLocalTime(&local_time);
	char buffer[32] = {0};
	sprintf_s(
		buffer,
		"%04u-%02u-%02uT%02u:%02u:%02u.%03u",
		local_time.wYear,
		local_time.wMonth,
		local_time.wDay,
		local_time.wHour,
		local_time.wMinute,
		local_time.wSecond,
		local_time.wMilliseconds);
	return std::string(buffer);
}

static int ParseLogLevel(const std::string& level) {
	if (_stricmp(level.c_str(), "ERROR") == 0) {
		return 3;
	}
	if (_stricmp(level.c_str(), "WARN") == 0) {
		return 2;
	}
	return 1;
}

class JsonLogger {
public:
	JsonLogger() : min_level_(1), console_output_(true), file_output_(true), file_(INVALID_HANDLE_VALUE) {}

	bool Initialize(const InjectorConfig& config, const std::wstring& exe_dir) {
		// 初始化 JSON Lines 日志输出（控制台 + 文件）
		console_output_ = config.console_output;
		file_output_ = config.file_output;
		min_level_ = ParseLogLevel(config.log_level);
		if (!file_output_) {
			return true;
		}
		std::wstring path = config.log_path;
		if (!IsAbsolutePath(path)) {
			path = JoinPathSafe(exe_dir, path);
		}
		if (!OpenLogFile(path)) {
			wchar_t temp_path[MAX_PATH] = {0};
			DWORD length = GetTempPathW(MAX_PATH, temp_path);
			if (length == 0 || length >= MAX_PATH) {
				file_output_ = false;
				return false;
			}
			std::wstring fallback = JoinPathSafe(temp_path, L"injector.jsonl");
			if (!OpenLogFile(fallback)) {
				file_output_ = false;
				return false;
			}
		}
		return true;
	}

	void Log(const char* level, const char* event, const std::string& message, const LogExtras& extras) {
		if (!ShouldLog(level)) {
			return;
		}
		std::string line = BuildJsonLine(level, event, message, extras);
		if (console_output_) {
			std::cout << line;
		}
		if (file_output_ && file_ != INVALID_HANDLE_VALUE) {
			DWORD written = 0;
			WriteFile(file_, line.c_str(), static_cast<DWORD>(line.size()), &written, NULL);
		}
	}

private:
	bool ShouldLog(const char* level) const {
		return ParseLogLevel(level) >= min_level_;
	}

	bool OpenLogFile(const std::wstring& path) {
		file_ = CreateFileW(
			path.c_str(),
			FILE_APPEND_DATA,
			FILE_SHARE_READ,
			NULL,
			OPEN_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
		return file_ != INVALID_HANDLE_VALUE;
	}

	static void AppendStringField(std::string& output, const char* key, const std::string& value) {
		output.append(",\"");
		output.append(key);
		output.append("\":\"");
		output.append(EscapeJson(value));
		output.append("\"");
	}

	static void AppendNumberField(std::string& output, const char* key, long long value) {
		char buffer[64] = {0};
		sprintf_s(buffer, "%lld", value);
		output.append(",\"");
		output.append(key);
		output.append("\":");
		output.append(buffer);
	}

	static std::string BuildJsonLine(const char* level, const char* event, const std::string& message, const LogExtras& extras) {
		std::string output;
		output.reserve(512);
		output.append("{\"ts\":\"");
		output.append(FormatTimestamp());
		output.append("\",\"level\":\"");
		output.append(EscapeJson(level));
		output.append("\",\"event\":\"");
		output.append(EscapeJson(event));
		output.append("\",\"message\":\"");
		output.append(EscapeJson(message));
		output.append("\"");
		if (extras.pid != 0) {
			AppendNumberField(output, "pid", extras.pid);
		}
		if (extras.tid != 0) {
			AppendNumberField(output, "tid", extras.tid);
		}
		if (extras.attempt >= 0) {
			AppendNumberField(output, "attempt", extras.attempt);
		}
		if (extras.thread_count >= 0) {
			AppendNumberField(output, "thread_count", extras.thread_count);
		}
		if (extras.queued_count >= 0) {
			AppendNumberField(output, "queued_count", extras.queued_count);
		}
		if (extras.error_code != 0) {
			AppendNumberField(output, "error_code", extras.error_code);
		}
		if (!extras.result.empty()) {
			AppendStringField(output, "result", extras.result);
		}
		if (!extras.process_name.empty()) {
			AppendStringField(output, "target_process", WideToUtf8(extras.process_name));
		}
		if (!extras.dll_path.empty()) {
			AppendStringField(output, "dll_path", WideToUtf8(extras.dll_path));
		}
		output.append("}\r\n");
		return output;
	}

	int min_level_;
	bool console_output_;
	bool file_output_;
	HANDLE file_;
};

static void DeleteSuccessFilesForPid(const InjectorConfig& settings,
	DWORD pid,
	const std::vector<std::wstring>& dll_paths,
	JsonLogger& logger,
	const LogExtras& base_extras) {
	if (!settings.success_check_enabled) {
		return;
	}
	for (size_t i = 0; i < dll_paths.size(); ++i) {
		const std::wstring& dll_path = dll_paths[i];
		std::wstring success_file_path = BuildSuccessFilePath(settings, pid, dll_path);
		if (success_file_path.empty()) {
			continue;
		}
		DWORD attrs = GetFileAttributesW(success_file_path.c_str());
		if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
			continue;
		}
		LogExtras delete_extras = base_extras;
		delete_extras.dll_path = dll_path;
		if (DeleteFileW(success_file_path.c_str()) != 0) {
			logger.Log("INFO", "success_file_cleanup", "deleted", delete_extras);
		} else {
			delete_extras.error_code = GetLastError();
			logger.Log("WARN", "success_file_cleanup", "delete_failed", delete_extras);
		}
	}
}

static InjectorConfig LoadInjectorConfig(const std::wstring& config_path, const std::wstring& exe_dir, bool* loaded) {
	// 读取 INI 配置，缺省值直接生效
	InjectorConfig settings;
	settings.process_name = L"dnf.exe";
	settings.dll_path = L"";
	settings.dll_paths.clear();
	settings.scan_interval_ms = 1000;
	settings.inject_delay_ms = 3000;
	settings.inject_interval_ms = 0;
	settings.max_retries = 5;
	settings.retry_interval_ms = 2000;
	settings.module_check_timeout_ms = 8000;
	settings.module_check_interval_ms = 200;
	settings.module_check_extend_ms = 5000;
	settings.success_check_enabled = true;
	settings.success_file_dir = L"";
	settings.success_file_name = L"successfile_%dll.name%_%pid%.txt";
	settings.watch_mode = true;
	settings.exit_when_no_processes = false;
	settings.log_path = L"injector.jsonl";
	settings.log_level = "INFO";
	settings.log_pid_list = false;
	settings.console_output = true;
	settings.file_output = true;
	*loaded = false;

	DWORD attrs = GetFileAttributesW(config_path.c_str());
	std::wstring dll_path_value;
	std::wstring dll_paths_value;
	std::wstring format = L"json";

	if (attrs != INVALID_FILE_ATTRIBUTES) {
		*loaded = true;
		settings.process_name = ReadIniStringValue(config_path, L"target", L"process_name", settings.process_name.c_str());
		dll_path_value = ReadIniStringValue(config_path, L"target", L"dll_path", L"");
		dll_paths_value = ReadIniStringValue(config_path, L"target", L"dll_paths", L"");
		DWORD detect_interval = ReadIniUInt32(config_path, L"target", L"detect_interval_ms", settings.scan_interval_ms);
		settings.scan_interval_ms = ReadIniUInt32(config_path, L"target", L"scan_interval_ms", detect_interval);
		settings.inject_delay_ms = ReadIniUInt32(config_path, L"target", L"inject_delay_ms", settings.inject_delay_ms);
		settings.inject_interval_ms = ReadIniUInt32(config_path, L"target", L"inject_interval_ms", settings.inject_interval_ms);
		settings.watch_mode = ParseBool(ReadIniStringValue(config_path, L"target", L"watch_mode", settings.watch_mode ? L"true" : L"false"), settings.watch_mode);
		settings.exit_when_no_processes = ParseBool(ReadIniStringValue(config_path, L"target", L"exit_when_no_processes", settings.exit_when_no_processes ? L"true" : L"false"), settings.exit_when_no_processes);
		settings.max_retries = static_cast<int>(ReadIniUInt32(config_path, L"apc", L"max_retries", static_cast<DWORD>(settings.max_retries)));
		settings.retry_interval_ms = ReadIniUInt32(config_path, L"apc", L"retry_interval_ms", settings.retry_interval_ms);
		settings.module_check_timeout_ms = ReadIniUInt32(config_path, L"apc", L"module_check_timeout_ms", settings.module_check_timeout_ms);
		settings.module_check_interval_ms = ReadIniUInt32(config_path, L"apc", L"module_check_interval_ms", settings.module_check_interval_ms);
		settings.module_check_extend_ms = ReadIniUInt32(config_path, L"apc", L"module_check_extend_ms", settings.module_check_extend_ms);
		settings.success_check_enabled = ParseBool(
			ReadIniStringValue(config_path, L"apc", L"success_check_enabled", settings.success_check_enabled ? L"true" : L"false"),
			settings.success_check_enabled);
		std::wstring success_file_dir_value = TrimWide(ReadIniStringValue(config_path, L"apc", L"success_file_dir", L""));
		if (!success_file_dir_value.empty()) {
			settings.success_file_dir = NormalizePath(success_file_dir_value, exe_dir);
		}
		std::wstring success_file_name_value = TrimWide(ReadIniStringValue(config_path, L"apc", L"success_file_name", settings.success_file_name.c_str()));
		if (!success_file_name_value.empty()) {
			settings.success_file_name = success_file_name_value;
		}
		settings.log_path = ReadIniStringValue(config_path, L"log", L"log_path", settings.log_path.c_str());
		settings.log_level = WideToUtf8(ReadIniStringValue(config_path, L"log", L"log_level", L"INFO"));
		format = ReadIniStringValue(config_path, L"log", L"log_format", L"json");
		settings.log_pid_list = ParseBool(ReadIniStringValue(config_path, L"log", L"log_pid_list", L"false"), settings.log_pid_list);
		settings.console_output = ParseBool(ReadIniStringValue(config_path, L"log", L"console_output", L"true"), true);
		settings.file_output = ParseBool(ReadIniStringValue(config_path, L"log", L"file_output", L"true"), true);
	}

	// DLL 列表优先：dll_paths -> dll_path -> 默认 GameHelper.dll
	settings.dll_paths = BuildDllPathList(dll_paths_value, dll_path_value, exe_dir);
	if (!settings.dll_paths.empty()) {
		settings.dll_path = settings.dll_paths.front();
	}
	if (settings.module_check_interval_ms == 0) {
		settings.module_check_interval_ms = 200;
	}

	if (_wcsicmp(format.c_str(), L"json") != 0) {
		format = L"json";
	}
	if (!IsAbsolutePath(settings.log_path)) {
		settings.log_path = JoinPathSafe(exe_dir, settings.log_path);
	}
	return settings;
}

static DWORD FindProcessIdByName(const std::wstring& process_name) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}
	PROCESSENTRY32W entry = {0};
	entry.dwSize = sizeof(entry);
	DWORD result = 0;
	if (Process32FirstW(snapshot, &entry)) {
		do {
			if (_wcsicmp(entry.szExeFile, process_name.c_str()) == 0) {
				result = entry.th32ProcessID;
				break;
			}
		} while (Process32NextW(snapshot, &entry));
	}
	CloseHandle(snapshot);
	return result;
}

static std::vector<DWORD> ListProcessIdsByName(const std::wstring& process_name) {
	std::vector<DWORD> results;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return results;
	}
	PROCESSENTRY32W entry = {0};
	entry.dwSize = sizeof(entry);
	if (Process32FirstW(snapshot, &entry)) {
		do {
			if (_wcsicmp(entry.szExeFile, process_name.c_str()) == 0) {
				results.push_back(entry.th32ProcessID);
			}
		} while (Process32NextW(snapshot, &entry));
	}
	CloseHandle(snapshot);
	return results;
}

static std::vector<DWORD> ListThreadIds(DWORD pid) {
	std::vector<DWORD> threads;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return threads;
	}
	THREADENTRY32 entry = {0};
	entry.dwSize = sizeof(entry);
	if (Thread32First(snapshot, &entry)) {
		do {
			if (entry.th32OwnerProcessID == pid) {
				threads.push_back(entry.th32ThreadID);
			}
		} while (Thread32Next(snapshot, &entry));
	}
	CloseHandle(snapshot);
	return threads;
}

enum ModuleCheckResult {
	kModuleCheckTimeout = 0,
	kModuleCheckModuleLoaded = 1,
	kModuleCheckSuccessFile = 2
};

static bool GetFileWriteTime(const std::wstring& path, FILETIME* write_time) {
	if (write_time == NULL) {
		return false;
	}
	HANDLE file = CreateFileW(
		path.c_str(),
		FILE_READ_ATTRIBUTES,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (file == INVALID_HANDLE_VALUE) {
		return false;
	}
	FILETIME file_write_time = {0};
	BOOL ok = GetFileTime(file, NULL, NULL, &file_write_time);
	CloseHandle(file);
	if (!ok) {
		return false;
	}
	*write_time = file_write_time;
	return true;
}

static bool HasFileUpdated(const std::wstring& path, bool baseline_valid, const FILETIME& baseline_time) {
	FILETIME current_time = {0};
	if (!GetFileWriteTime(path, &current_time)) {
		return false;
	}
	if (!baseline_valid) {
		return true;
	}
	return CompareFileTime(&current_time, &baseline_time) == 1;
}

static bool IsModuleLoaded(DWORD pid, const std::wstring& module_name, const std::wstring& module_path) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return false;
	}
	MODULEENTRY32W entry = {0};
	entry.dwSize = sizeof(entry);
	bool found = false;
	if (Module32FirstW(snapshot, &entry)) {
		do {
			if (_wcsicmp(entry.szModule, module_name.c_str()) == 0 ||
				_wcsicmp(entry.szExePath, module_path.c_str()) == 0) {
				found = true;
				break;
			}
		} while (Module32NextW(snapshot, &entry));
	}
	CloseHandle(snapshot);
	return found;
}

// 同时检测模块加载与成功文件更新，兼容隐藏模块场景。
static ModuleCheckResult WaitForModuleOrSuccess(DWORD pid,
	const std::wstring& module_name,
	const std::wstring& module_path,
	const std::wstring& success_file_path,
	bool success_baseline_valid,
	const FILETIME& success_baseline,
	DWORD timeout_ms,
	DWORD interval_ms) {
	ULONGLONG start = GetTickCount64();
	for (;;) {
		if (IsModuleLoaded(pid, module_name, module_path)) {
			return kModuleCheckModuleLoaded;
		}
		if (!success_file_path.empty() && HasFileUpdated(success_file_path, success_baseline_valid, success_baseline)) {
			return kModuleCheckSuccessFile;
		}
		if (GetTickCount64() - start >= timeout_ms) {
			return kModuleCheckTimeout;
		}
		Sleep(interval_ms);
	}
}

static bool InjectByApc(DWORD pid, const InjectorConfig& settings, const std::wstring& dll_path, const std::wstring& module_name, JsonLogger& logger, int attempt) {
	// APC 注入核心流程：远程写入路径 + QueueUserAPC
	LogExtras extras;
	extras.pid = pid;
	extras.attempt = attempt;
	extras.process_name = settings.process_name;
	extras.dll_path = dll_path;

	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
	if (process == NULL) {
		extras.error_code = GetLastError();
		logger.Log("ERROR", "open_process", "failed", extras);
		return false;
	}

	size_t bytes = (dll_path.size() + 1) * sizeof(wchar_t);
	void* remote_path = VirtualAllocEx(process, NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (remote_path == NULL) {
		extras.error_code = GetLastError();
		logger.Log("ERROR", "alloc_remote", "failed", extras);
		CloseHandle(process);
		return false;
	}

	if (!WriteProcessMemory(process, remote_path, dll_path.c_str(), bytes, NULL)) {
		extras.error_code = GetLastError();
		logger.Log("ERROR", "write_remote", "failed", extras);
		VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
		CloseHandle(process);
		return false;
	}

	HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
	FARPROC load_library = kernel32 ? GetProcAddress(kernel32, "LoadLibraryW") : NULL;
	if (load_library == NULL) {
		extras.error_code = GetLastError();
		logger.Log("ERROR", "resolve_loadlibrary", "failed", extras);
		VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
		CloseHandle(process);
		return false;
	}

	// 记录成功文件基线，模块隐藏时用于判断是否已执行注入逻辑。
	std::wstring success_file_path = BuildSuccessFilePath(settings, pid, dll_path);
	FILETIME success_baseline = {0};
	bool success_baseline_valid = false;
	if (!success_file_path.empty()) {
		success_baseline_valid = GetFileWriteTime(success_file_path, &success_baseline);
	}

	std::vector<DWORD> threads = ListThreadIds(pid);
	extras.thread_count = static_cast<int>(threads.size());
	int queued = 0;
	for (DWORD tid : threads) {
		HANDLE thread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
		if (thread == NULL) {
			continue;
		}
		if (QueueUserAPC(reinterpret_cast<PAPCFUNC>(load_library), thread, reinterpret_cast<ULONG_PTR>(remote_path)) != 0) {
			++queued;
		}
		CloseHandle(thread);
	}
	extras.queued_count = queued;
	logger.Log("INFO", "apc_queued", queued > 0 ? "queued" : "empty", extras);

	if (queued == 0) {
		VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
		CloseHandle(process);
		return false;
	}

	logger.Log("INFO", "module_check", "start", extras);
	ModuleCheckResult check_result = WaitForModuleOrSuccess(
		pid,
		module_name,
		dll_path,
		success_file_path,
		success_baseline_valid,
		success_baseline,
		settings.module_check_timeout_ms,
		settings.module_check_interval_ms);
	if (check_result == kModuleCheckTimeout && settings.module_check_extend_ms > 0) {
		char extend_message[64] = {0};
		sprintf_s(extend_message, "extend_ms=%lu", settings.module_check_extend_ms);
		logger.Log("WARN", "module_check_extend", extend_message, extras);
		check_result = WaitForModuleOrSuccess(
			pid,
			module_name,
			dll_path,
			success_file_path,
			success_baseline_valid,
			success_baseline,
			settings.module_check_extend_ms,
			settings.module_check_interval_ms);
	}
	const char* check_message = "timeout";
	if (check_result == kModuleCheckModuleLoaded) {
		check_message = "loaded";
	} else if (check_result == kModuleCheckSuccessFile) {
		check_message = "success_file";
	}
	logger.Log(check_result == kModuleCheckTimeout ? "WARN" : "INFO", "module_check", check_message, extras);

	CloseHandle(process);
	return check_result != kModuleCheckTimeout;
}

static bool InjectProcessWithRetries(DWORD pid, const InjectorConfig& settings, const std::wstring& dll_path, const std::wstring& module_name, JsonLogger& logger, std::string* last_error) {
	LogExtras extras;
	extras.pid = pid;
	extras.process_name = settings.process_name;
	extras.dll_path = dll_path;

	for (int attempt = 1; attempt <= settings.max_retries; ++attempt) {
		extras.attempt = attempt;
		extras.result = "fail";
		if (InjectByApc(pid, settings, dll_path, module_name, logger, attempt)) {
			extras.result = "ok";
			logger.Log("INFO", "inject_result", "success", extras);
			if (last_error != NULL) {
				*last_error = "ok";
			}
			return true;
		}
		logger.Log("WARN", "inject_result", "retry", extras);
		if (last_error != NULL) {
			*last_error = "retry";
		}
		if (attempt < settings.max_retries) {
			Sleep(settings.retry_interval_ms);
		}
	}

	logger.Log("ERROR", "inject_result", "failed", extras);
	if (last_error != NULL) {
		*last_error = "failed";
	}
	return false;
}

int wmain(int argc, wchar_t* argv[]) {
	// 注入器入口：加载配置 -> 等待进程 -> 执行注入
	std::wstring exe_dir = GetExeDirectory();
	std::wstring config_path = JoinPathSafe(exe_dir, L"injector.ini");
	if (argc >= 3 && _wcsicmp(argv[1], L"--config") == 0) {
		config_path = argv[2];
	}

	bool config_loaded = false;
	InjectorConfig settings = LoadInjectorConfig(config_path, exe_dir, &config_loaded);
	JsonLogger logger;
	logger.Initialize(settings, exe_dir);

	LogExtras extras;
	extras.process_name = settings.process_name;
	extras.dll_path = settings.dll_path;

	logger.Log("INFO", "startup", config_loaded ? "config_loaded" : "config_default", extras);

	if (settings.process_name.empty()) {
		logger.Log("ERROR", "config", "process_name_empty", extras);
		return 1;
	}
	if (settings.dll_paths.empty()) {
		logger.Log("ERROR", "config", "dll_path_empty", extras);
		return 1;
	}
	std::vector<std::wstring> module_names;
	module_names.reserve(settings.dll_paths.size());
	for (size_t i = 0; i < settings.dll_paths.size(); ++i) {
		const std::wstring& dll_path = settings.dll_paths[i];
		LogExtras path_extras = extras;
		path_extras.dll_path = dll_path;
		if (dll_path.empty()) {
			logger.Log("ERROR", "config", "dll_path_empty", path_extras);
			return 1;
		}
		DWORD dll_attrs = GetFileAttributesW(dll_path.c_str());
		if (dll_attrs == INVALID_FILE_ATTRIBUTES || (dll_attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
			logger.Log("ERROR", "config", "dll_path_invalid", path_extras);
			return 1;
		}
		std::wstring module_name = GetBaseName(dll_path);
		if (module_name.empty()) {
			logger.Log("ERROR", "config", "module_name_empty", path_extras);
			return 1;
		}
		module_names.push_back(module_name);
	}

	if (!settings.watch_mode) {
		logger.Log("INFO", "wait_process", "start", extras);
		DWORD pid = 0;
		while (pid == 0) {
			pid = FindProcessIdByName(settings.process_name);
			if (pid == 0) {
				Sleep(settings.scan_interval_ms);
			}
		}
		extras.pid = pid;
		logger.Log("INFO", "process_found", "ok", extras);
		if (settings.inject_delay_ms > 0) {
			Sleep(settings.inject_delay_ms);
		}
		bool all_injected = true;
		for (size_t i = 0; i < settings.dll_paths.size(); ++i) {
			LogExtras start_extras = extras;
			start_extras.pid = pid;
			start_extras.dll_path = settings.dll_paths[i];
			logger.Log("INFO", "inject_start", "single_process", start_extras);
			if (!InjectProcessWithRetries(pid, settings, settings.dll_paths[i], module_names[i], logger, NULL)) {
				all_injected = false;
			}
			if (settings.inject_interval_ms > 0 && i + 1 < settings.dll_paths.size()) {
				// 不同 DLL 注入之间的间隔。
				Sleep(settings.inject_interval_ms);
			}
		}
		return all_injected ? 0 : 1;
	}

	bool ever_found = false;
	std::unordered_set<DWORD> injected_pids;
	std::unordered_map<DWORD, int> pid_attempts;
	std::unordered_map<DWORD, std::string> pid_last_error;
	std::unordered_map<DWORD, std::unordered_set<size_t>> pid_injected_modules;
	std::unordered_map<DWORD, std::unordered_map<size_t, ULONGLONG>> pid_cooldowns;
	std::string last_pid_hash;
	logger.Log("INFO", "watch_mode", "start", extras);
	for (;;) {
		std::vector<DWORD> pids = ListProcessIdsByName(settings.process_name);
		if (settings.log_pid_list) {
			std::string current_hash = BuildPidListHash(pids);
			if (current_hash != last_pid_hash) {
				last_pid_hash = current_hash;
				logger.Log("INFO", "scan_pids", BuildPidListMessage(pids), extras);
			}
		}
		if (!pids.empty()) {
			ever_found = true;
		}

		std::unordered_set<DWORD> current(pids.begin(), pids.end());
		for (std::unordered_set<DWORD>::iterator it = injected_pids.begin(); it != injected_pids.end();) {
			if (current.find(*it) == current.end()) {
				LogExtras exit_extras = extras;
				exit_extras.pid = *it;
				logger.Log("INFO", "process_exit", "removed", exit_extras);
				// 进程退出时清理对应的成功文件。
				DeleteSuccessFilesForPid(settings, *it, settings.dll_paths, logger, exit_extras);
				pid_attempts.erase(*it);
				pid_last_error.erase(*it);
				pid_injected_modules.erase(*it);
				pid_cooldowns.erase(*it);
				it = injected_pids.erase(it);
			} else {
				++it;
			}
		}

		for (size_t index = 0; index < pids.size(); ++index) {
			DWORD pid = pids[index];
			if (injected_pids.find(pid) != injected_pids.end()) {
				continue;
			}
			std::unordered_set<size_t>& injected_modules = pid_injected_modules[pid];
			std::unordered_map<size_t, ULONGLONG>& cooldowns = pid_cooldowns[pid];
			std::vector<size_t> missing_indices;
			std::vector<size_t> pending_indices;
			ULONGLONG now = GetTickCount64();
			for (size_t i = 0; i < settings.dll_paths.size(); ++i) {
				if (injected_modules.find(i) != injected_modules.end()) {
					continue;
				}
				if (IsModuleLoaded(pid, module_names[i], settings.dll_paths[i]) ||
					IsSuccessFilePresent(settings, pid, settings.dll_paths[i])) {
					injected_modules.insert(i);
					continue;
				}
				missing_indices.push_back(i);
				if (settings.retry_interval_ms > 0) {
					std::unordered_map<size_t, ULONGLONG>::iterator cooldown_it = cooldowns.find(i);
					if (cooldown_it != cooldowns.end() && cooldown_it->second > now) {
						continue;
					}
				}
				pending_indices.push_back(i);
			}
			if (missing_indices.empty()) {
				LogExtras loaded_extras = extras;
				loaded_extras.pid = pid;
				logger.Log("INFO", "module_check", "already_loaded", loaded_extras);
				injected_pids.insert(pid);
				continue;
			}
			if (pending_indices.empty()) {
				continue;
			}
			LogExtras start_extras = extras;
			start_extras.pid = pid;
			start_extras.dll_path = L"";
			int total_attempts = 0;
			std::unordered_map<DWORD, int>::iterator attempt_it = pid_attempts.find(pid);
			if (attempt_it != pid_attempts.end()) {
				total_attempts = attempt_it->second;
			}
			start_extras.attempt = total_attempts + 1;
			std::string start_message = "new_process";
			start_message += " dll_count=" + std::to_string(missing_indices.size());
			if (pending_indices.size() != missing_indices.size()) {
				start_message += " pending=" + std::to_string(pending_indices.size());
			}
			std::unordered_map<DWORD, std::string>::iterator error_it = pid_last_error.find(pid);
			if (error_it != pid_last_error.end() && !error_it->second.empty()) {
				start_message += " last_error=" + error_it->second;
			}
			logger.Log("INFO", "inject_start", start_message, start_extras);
			if (settings.inject_delay_ms > 0) {
				Sleep(settings.inject_delay_ms);
			}
			std::string last_error;
			for (size_t i = 0; i < pending_indices.size(); ++i) {
				size_t target_index = pending_indices[i];
				std::string dll_error;
				ULONGLONG attempt_time = GetTickCount64();
				if (settings.retry_interval_ms > 0) {
					cooldowns[target_index] = attempt_time + settings.retry_interval_ms;
				}
				bool injected = InjectProcessWithRetries(pid, settings, settings.dll_paths[target_index], module_names[target_index], logger, &dll_error);
				total_attempts += settings.max_retries;
				if (injected) {
					injected_modules.insert(target_index);
					continue;
				}
				if (!dll_error.empty()) {
					last_error = dll_error;
				}
				if (settings.inject_interval_ms > 0 && i + 1 < pending_indices.size()) {
					// 不同 DLL 注入之间的间隔。
					Sleep(settings.inject_interval_ms);
				}
			}
			pid_attempts[pid] = total_attempts;
			if (!last_error.empty()) {
				pid_last_error[pid] = last_error;
			}
			if (injected_modules.size() == settings.dll_paths.size()) {
				injected_pids.insert(pid);
			}
		}

		if (settings.exit_when_no_processes && ever_found && pids.empty()) {
			logger.Log("INFO", "watch_mode", "exit_no_processes", extras);
			break;
		}
		Sleep(settings.scan_interval_ms);
	}

	return 0;
}
