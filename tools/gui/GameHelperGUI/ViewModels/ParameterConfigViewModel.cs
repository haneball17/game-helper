using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.CompilerServices;
using GameHelperGUI.Models;
using GameHelperGUI.Services;

namespace GameHelperGUI.ViewModels;

public sealed class ParameterConfigViewModel : INotifyPropertyChanged
{
    private readonly IniFile _ini;
    private readonly string _metadataPath;
    private readonly ParameterMetadataLoader _loader = new();

    private string _statusMessage = string.Empty;

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<ParameterSectionViewModel> Sections { get; } = new();

    public RelayCommand SaveCommand { get; }
    public RelayCommand ReloadCommand { get; }
    public RelayCommand ResetCommand { get; }

    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetField(ref _statusMessage, value);
    }

    public ParameterConfigViewModel(string configPath, string metadataPath)
    {
        _ini = new IniFile(configPath);
        _metadataPath = metadataPath;
        SaveCommand = new RelayCommand(_ => Save());
        ReloadCommand = new RelayCommand(_ => Load());
        ResetCommand = new RelayCommand(_ => ResetToDefault());
        Load();
    }

    private void Load()
    {
        Sections.Clear();
        if (!File.Exists(_metadataPath))
        {
            GuiLogger.Error("config", "params_json_missing", new Dictionary<string, object?>
            {
                ["path"] = _metadataPath
            });
            StatusMessage = "参数元数据不存在";
            return;
        }
        GuiLogger.Info("config_read_start", "game_helper_ini", new Dictionary<string, object?>
        {
            ["path"] = _ini.Path
        });
        ParameterMetadataRoot root = _loader.Load(_metadataPath);
        foreach (var section in root.Sections)
        {
            var sectionVm = new ParameterSectionViewModel
            {
                Name = section.Name,
                Title = section.Title
            };
            foreach (var item in section.Items)
            {
                var itemVm = BuildItem(section.Name, item);
                LoadItemValue(itemVm, item);
                sectionVm.Items.Add(itemVm);
            }
            Sections.Add(sectionVm);
        }
        StatusMessage = "已加载";
        GuiLogger.Info("config_read_end", "ok");
    }

    private void ResetToDefault()
    {
        foreach (var section in Sections)
        {
            foreach (var item in section.Items)
            {
                item.SetDefaultValue();
            }
        }
        StatusMessage = "已恢复默认值（未保存）";
    }

    private void Save()
    {
        var errors = new List<string>();
        foreach (var section in Sections)
        {
            foreach (var item in section.Items)
            {
                if (!SaveItem(section.Name, item, errors))
                {
                    continue;
                }
            }
        }
        StatusMessage = errors.Count == 0 ? "保存成功（重启生效）" : "保存失败：" + string.Join(",", errors);
        GuiLogger.Info("config_save", errors.Count == 0 ? "ok" : "failed", new Dictionary<string, object?>
        {
            ["error_keys"] = string.Join(",", errors)
        });
    }

    private ParameterItemViewModel BuildItem(string sectionName, ParameterItemMetadata meta)
    {
        return new ParameterItemViewModel
        {
            Section = sectionName,
            Key = meta.Key,
            Label = meta.Label,
            Type = meta.Type,
            Description = meta.Desc,
            Min = meta.Min,
            Max = meta.Max,
            DefaultValue = meta.Default.ToString()
        };
    }

    private void LoadItemValue(ParameterItemViewModel item, ParameterItemMetadata meta)
    {
        if (item.IsBool)
        {
            bool defaultValue = meta.Default.ValueKind == System.Text.Json.JsonValueKind.True ||
                                (meta.Default.ValueKind == System.Text.Json.JsonValueKind.String &&
                                 meta.Default.ToString().Equals("true", StringComparison.OrdinalIgnoreCase));
            item.BoolValue = _ini.ReadBool(item.Section, item.Key, defaultValue);
            GuiLogger.Info("config_read_item", "ok", new Dictionary<string, object?>
            {
                ["section"] = item.Section,
                ["key"] = item.Key,
                ["value"] = item.BoolValue ? "true" : "false"
            });
            return;
        }
        if (item.Type == "float")
        {
            var defaultValue = meta.Default.ToString();
            double parsed = double.TryParse(defaultValue, NumberStyles.Float, CultureInfo.InvariantCulture, out var value) ? value : 0;
            var current = _ini.ReadDouble(item.Section, item.Key, parsed);
            item.TextValue = current.ToString(CultureInfo.InvariantCulture);
            GuiLogger.Info("config_read_item", "ok", new Dictionary<string, object?>
            {
                ["section"] = item.Section,
                ["key"] = item.Key,
                ["value"] = item.TextValue
            });
            return;
        }
        if (item.Type == "int")
        {
            var defaultValue = meta.Default.ToString();
            int parsed = int.TryParse(defaultValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? value : 0;
            var current = _ini.ReadInt(item.Section, item.Key, parsed);
            item.TextValue = current.ToString(CultureInfo.InvariantCulture);
            GuiLogger.Info("config_read_item", "ok", new Dictionary<string, object?>
            {
                ["section"] = item.Section,
                ["key"] = item.Key,
                ["value"] = item.TextValue
            });
            return;
        }
        item.TextValue = _ini.ReadString(item.Section, item.Key, meta.Default.ToString());
        GuiLogger.Info("config_read_item", "ok", new Dictionary<string, object?>
        {
            ["section"] = item.Section,
            ["key"] = item.Key,
            ["value"] = item.TextValue
        });
    }

    private bool SaveItem(string sectionName, ParameterItemViewModel item, List<string> errors)
    {
        if (item.IsBool)
        {
            _ini.WriteBool(sectionName, item.Key, item.BoolValue);
            GuiLogger.Info("config_write_item", "ok", new Dictionary<string, object?>
            {
                ["section"] = sectionName,
                ["key"] = item.Key,
                ["value"] = item.BoolValue ? "true" : "false"
            });
            return true;
        }
        if (item.Type == "float")
        {
            if (!double.TryParse(item.TextValue, NumberStyles.Float, CultureInfo.InvariantCulture, out var value))
            {
                errors.Add(item.Key);
                GuiLogger.Warn("config_write_item", "invalid_value", new Dictionary<string, object?>
                {
                    ["section"] = sectionName,
                    ["key"] = item.Key,
                    ["value"] = item.TextValue
                });
                return false;
            }
            _ini.WriteDouble(sectionName, item.Key, value);
            GuiLogger.Info("config_write_item", "ok", new Dictionary<string, object?>
            {
                ["section"] = sectionName,
                ["key"] = item.Key,
                ["value"] = item.TextValue
            });
            return true;
        }
        if (item.Type == "int")
        {
            if (!int.TryParse(item.TextValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
            {
                errors.Add(item.Key);
                GuiLogger.Warn("config_write_item", "invalid_value", new Dictionary<string, object?>
                {
                    ["section"] = sectionName,
                    ["key"] = item.Key,
                    ["value"] = item.TextValue
                });
                return false;
            }
            _ini.WriteInt(sectionName, item.Key, value);
            GuiLogger.Info("config_write_item", "ok", new Dictionary<string, object?>
            {
                ["section"] = sectionName,
                ["key"] = item.Key,
                ["value"] = item.TextValue
            });
            return true;
        }
        _ini.WriteString(sectionName, item.Key, item.TextValue);
        GuiLogger.Info("config_write_item", "ok", new Dictionary<string, object?>
        {
            ["section"] = sectionName,
            ["key"] = item.Key,
            ["value"] = item.TextValue
        });
        return true;
    }

    private void SetField<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (Equals(field, value))
        {
            return;
        }
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
