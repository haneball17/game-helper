using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace GameHelperGUI.ViewModels;

public sealed class HotkeyItemViewModel : INotifyPropertyChanged
{
    private int _vkCode;
    private bool _isCapturing;

    public event PropertyChangedEventHandler? PropertyChanged;

    public string Key { get; init; } = string.Empty;
    public string Label { get; init; } = string.Empty;
    public int DefaultVk { get; init; }

    public int VkCode
    {
        get => _vkCode;
        set
        {
            if (SetField(ref _vkCode, value))
            {
                OnPropertyChanged(nameof(DisplayKey));
            }
        }
    }

    public bool IsCapturing
    {
        get => _isCapturing;
        set
        {
            if (SetField(ref _isCapturing, value))
            {
                OnPropertyChanged(nameof(CaptureStatusText));
            }
        }
    }

    public string DisplayKey => HotkeyTextFormatter.Format(VkCode);

    public string CaptureStatusText => IsCapturing ? "请按键" : string.Empty;

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (Equals(field, value))
        {
            return false;
        }
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        return true;
    }

    private void OnPropertyChanged(string name)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
