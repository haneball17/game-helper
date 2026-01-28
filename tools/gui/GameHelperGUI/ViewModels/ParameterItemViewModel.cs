using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace GameHelperGUI.ViewModels;

public sealed class ParameterItemViewModel : INotifyPropertyChanged
{
    private bool _boolValue;
    private string _textValue = string.Empty;

    public event PropertyChangedEventHandler? PropertyChanged;

    public string Section { get; init; } = string.Empty;
    public string Key { get; init; } = string.Empty;
    public string Label { get; init; } = string.Empty;
    public string Type { get; init; } = "string";
    public string Description { get; init; } = string.Empty;
    public double? Min { get; init; }
    public double? Max { get; init; }
    public string DefaultValue { get; init; } = string.Empty;

    public bool IsBool => Type == "bool";

    public bool BoolValue
    {
        get => _boolValue;
        set => SetField(ref _boolValue, value);
    }

    public string TextValue
    {
        get => _textValue;
        set => SetField(ref _textValue, value);
    }

    public void SetDefaultValue()
    {
        if (IsBool)
        {
            BoolValue = DefaultValue == "1" || DefaultValue.Equals("true", System.StringComparison.OrdinalIgnoreCase);
        }
        else
        {
            TextValue = DefaultValue;
        }
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
