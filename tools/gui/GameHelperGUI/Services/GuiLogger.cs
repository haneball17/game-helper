using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text.Json;

namespace GameHelperGUI.Services;

public enum GuiLogLevel
{
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3
}

public static class GuiLogger
{
    private static readonly object SyncRoot = new();
    private static StreamWriter? _writer;
    private static GuiLogLevel _level = GuiLogLevel.Info;
    private static bool _consoleOutput;
    private static bool _initialized;

    public static void Initialize(string configPath, string baseDir)
    {
        if (_initialized)
        {
            return;
        }
        var ini = new IniFile(configPath);
        string levelValue = ini.ReadString("gui_log", "log_level", "INFO");
        string logPath = ini.ReadString("gui_log", "log_path", "gui.log.jsonl");
        bool consoleOutput = ini.ReadBool("gui_log", "console_output", false);

        if (!Path.IsPathRooted(logPath))
        {
            logPath = Path.Combine(baseDir, logPath);
        }

        _level = ParseLevel(levelValue);
        _consoleOutput = consoleOutput;
        Directory.CreateDirectory(Path.GetDirectoryName(logPath) ?? baseDir);
        _writer = new StreamWriter(new FileStream(logPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
        {
            AutoFlush = true
        };
        _initialized = true;
        Info("startup", "gui_logger_ready", new Dictionary<string, object?>
        {
            ["log_path"] = logPath,
            ["log_level"] = _level.ToString().ToUpperInvariant()
        });
    }

    public static void Debug(string evt, string message, Dictionary<string, object?>? extras = null)
    {
        Log(GuiLogLevel.Debug, evt, message, extras);
    }

    public static void Info(string evt, string message, Dictionary<string, object?>? extras = null)
    {
        Log(GuiLogLevel.Info, evt, message, extras);
    }

    public static void Warn(string evt, string message, Dictionary<string, object?>? extras = null)
    {
        Log(GuiLogLevel.Warn, evt, message, extras);
    }

    public static void Error(string evt, string message, Dictionary<string, object?>? extras = null)
    {
        Log(GuiLogLevel.Error, evt, message, extras);
    }

    public static void Log(GuiLogLevel level, string evt, string message, Dictionary<string, object?>? extras = null)
    {
        if (!_initialized)
        {
            return;
        }
        if (level < _level)
        {
            return;
        }
        var payload = new Dictionary<string, object?>
        {
            ["ts"] = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fff", CultureInfo.InvariantCulture),
            ["level"] = level.ToString().ToUpperInvariant(),
            ["event"] = evt,
            ["message"] = message,
            ["pid"] = Environment.ProcessId
        };
        if (extras != null)
        {
            foreach (var item in extras)
            {
                payload[item.Key] = item.Value;
            }
        }

        string json = JsonSerializer.Serialize(payload);
        lock (SyncRoot)
        {
            _writer?.WriteLine(json);
        }
        if (_consoleOutput)
        {
            Console.WriteLine(json);
        }
    }

    private static GuiLogLevel ParseLevel(string value)
    {
        if (string.Equals(value, "DEBUG", StringComparison.OrdinalIgnoreCase))
        {
            return GuiLogLevel.Debug;
        }
        if (string.Equals(value, "WARN", StringComparison.OrdinalIgnoreCase))
        {
            return GuiLogLevel.Warn;
        }
        if (string.Equals(value, "ERROR", StringComparison.OrdinalIgnoreCase))
        {
            return GuiLogLevel.Error;
        }
        return GuiLogLevel.Info;
    }
}
