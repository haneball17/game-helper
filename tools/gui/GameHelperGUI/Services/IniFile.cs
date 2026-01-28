using System;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace GameHelperGUI.Services;

public sealed class IniFile
{
    private readonly string _path;

    public IniFile(string path)
    {
        _path = path;
    }

    public string Path => _path;

    public string ReadString(string section, string key, string defaultValue)
    {
        var buffer = new StringBuilder(512);
        GetPrivateProfileString(section, key, defaultValue, buffer, buffer.Capacity, _path);
        return buffer.ToString();
    }

    public int ReadInt(string section, string key, int defaultValue)
    {
        var value = ReadString(section, key, string.Empty);
        if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
        {
            return parsed;
        }
        return defaultValue;
    }

    public double ReadDouble(string section, string key, double defaultValue)
    {
        var value = ReadString(section, key, string.Empty);
        if (double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed))
        {
            return parsed;
        }
        return defaultValue;
    }

    public bool ReadBool(string section, string key, bool defaultValue)
    {
        var value = ReadString(section, key, string.Empty);
        if (string.IsNullOrWhiteSpace(value))
        {
            return defaultValue;
        }
        var normalized = value.Trim();
        if (string.Equals(normalized, "1", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, "true", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, "yes", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, "on", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        if (string.Equals(normalized, "0", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, "false", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, "no", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, "off", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        return defaultValue;
    }

    public void WriteString(string section, string key, string value)
    {
        WritePrivateProfileString(section, key, value, _path);
    }

    public void WriteInt(string section, string key, int value)
    {
        WriteString(section, key, value.ToString(CultureInfo.InvariantCulture));
    }

    public void WriteDouble(string section, string key, double value)
    {
        WriteString(section, key, value.ToString(CultureInfo.InvariantCulture));
    }

    public void WriteBool(string section, string key, bool value)
    {
        WriteString(section, key, value ? "true" : "false");
    }

    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetPrivateProfileString(
        string section,
        string key,
        string defaultValue,
        StringBuilder retVal,
        int size,
        string filePath);

    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WritePrivateProfileString(
        string section,
        string key,
        string? value,
        string filePath);
}
