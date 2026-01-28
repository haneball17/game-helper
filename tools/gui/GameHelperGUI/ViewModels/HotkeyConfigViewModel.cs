using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using GameHelperGUI.Services;

namespace GameHelperGUI.ViewModels;

public sealed class HotkeyConfigViewModel : INotifyPropertyChanged
{
    private readonly IniFile _ini;
    private HotkeyItemViewModel? _capturingItem;
    private string _statusMessage = string.Empty;

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<HotkeyItemViewModel> Items { get; } = new();

    public RelayCommand SaveCommand { get; }
    public RelayCommand ReloadCommand { get; }
    public RelayCommand StartCaptureCommand { get; }
    public RelayCommand ClearCommand { get; }

    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetField(ref _statusMessage, value);
    }

    public HotkeyConfigViewModel(string configPath)
    {
        _ini = new IniFile(configPath);
        SaveCommand = new RelayCommand(_ => Save());
        ReloadCommand = new RelayCommand(_ => Load());
        StartCaptureCommand = new RelayCommand(param => StartCapture(param as HotkeyItemViewModel));
        ClearCommand = new RelayCommand(param => Clear(param as HotkeyItemViewModel));
        Load();
    }

    public bool HandleKey(Key key)
    {
        if (_capturingItem == null)
        {
            return false;
        }
        if (key == Key.Escape)
        {
            _capturingItem.IsCapturing = false;
            _capturingItem = null;
            StatusMessage = "已取消绑定";
            GuiLogger.Info("hotkey_capture", "cancel");
            return true;
        }
        if (key == Key.Back)
        {
            _capturingItem.VkCode = 0;
            _capturingItem.IsCapturing = false;
            _capturingItem = null;
            StatusMessage = "已清除绑定（未保存）";
            GuiLogger.Info("hotkey_capture", "clear");
            return true;
        }
        int vk = KeyInterop.VirtualKeyFromKey(key);
        _capturingItem.VkCode = vk;
        _capturingItem.IsCapturing = false;
        _capturingItem = null;
        StatusMessage = BuildConflictMessage(vk);
        GuiLogger.Info("hotkey_capture", "bound", new Dictionary<string, object?>
        {
            ["value"] = $"0x{vk:X2}"
        });
        return true;
    }

    private void Load()
    {
        Items.Clear();
        GuiLogger.Info("hotkey_read_start", "game_helper_ini", new Dictionary<string, object?>
        {
            ["path"] = _ini.Path
        });
        foreach (var definition in BuildDefaults())
        {
            var current = _ini.ReadInt("hotkey", definition.Key, definition.DefaultVk);
            Items.Add(new HotkeyItemViewModel
            {
                Key = definition.Key,
                Label = definition.Label,
                DefaultVk = definition.DefaultVk,
                VkCode = current
            });
            GuiLogger.Info("hotkey_read_item", "ok", new Dictionary<string, object?>
            {
                ["key"] = definition.Key,
                ["value"] = $"0x{current:X2}"
            });
        }
        StatusMessage = "已加载";
        _capturingItem = null;
        GuiLogger.Info("hotkey_read_end", "ok");
    }

    private void Save()
    {
        foreach (var item in Items)
        {
            _ini.WriteInt("hotkey", item.Key, item.VkCode);
            GuiLogger.Info("hotkey_write_item", "ok", new Dictionary<string, object?>
            {
                ["key"] = item.Key,
                ["value"] = $"0x{item.VkCode:X2}"
            });
        }
        StatusMessage = "保存成功（重启生效）";
        GuiLogger.Info("hotkey_save", "ok");
    }

    private void StartCapture(HotkeyItemViewModel? item)
    {
        if (item == null)
        {
            return;
        }
        if (_capturingItem != null && _capturingItem != item)
        {
            _capturingItem.IsCapturing = false;
        }
        item.IsCapturing = true;
        _capturingItem = item;
        StatusMessage = "请按键（Esc 取消，Backspace 清除）";
        GuiLogger.Info("hotkey_capture", "start", new Dictionary<string, object?>
        {
            ["key"] = item.Key
        });
    }

    private void Clear(HotkeyItemViewModel? item)
    {
        if (item == null)
        {
            return;
        }
        item.VkCode = 0;
        StatusMessage = "已清除绑定（未保存）";
        GuiLogger.Info("hotkey_clear", "ok", new Dictionary<string, object?>
        {
            ["key"] = item.Key
        });
    }

    private string BuildConflictMessage(int vk)
    {
        if (vk == 0)
        {
            return "已清除绑定（未保存）";
        }
        var conflicts = new List<string>();
        foreach (var item in Items)
        {
            if (item.VkCode == vk)
            {
                conflicts.Add(item.Label);
            }
        }
        if (conflicts.Count > 1)
        {
            return "按键冲突：" + string.Join(" / ", conflicts);
        }
        return "绑定已更新（未保存）";
    }

    private static IEnumerable<HotkeyItemViewModel> BuildDefaults()
    {
        return new[]
        {
            new HotkeyItemViewModel { Key = "toggle_transparent", Label = "自动透明", DefaultVk = 0x71 },
            new HotkeyItemViewModel { Key = "toggle_fullscreen_attack", Label = "全屏攻击", DefaultVk = 0x72 },
            new HotkeyItemViewModel { Key = "summon_doll", Label = "召唤人偶", DefaultVk = 0x7B },
            new HotkeyItemViewModel { Key = "attract_mode1", Label = "吸怪配置1", DefaultVk = 0x37 },
            new HotkeyItemViewModel { Key = "attract_mode2", Label = "吸怪配置2", DefaultVk = 0x38 },
            new HotkeyItemViewModel { Key = "attract_mode3", Label = "吸怪配置3", DefaultVk = 0x39 },
            new HotkeyItemViewModel { Key = "attract_mode4", Label = "吸怪配置4", DefaultVk = 0x30 },
            new HotkeyItemViewModel { Key = "toggle_attract_direction", Label = "吸怪方向切换", DefaultVk = 0xBD },
            new HotkeyItemViewModel { Key = "toggle_fullscreen_skill", Label = "全屏技能", DefaultVk = 0x24 }
        };
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
