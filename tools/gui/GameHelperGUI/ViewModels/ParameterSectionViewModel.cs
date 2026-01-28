using System.Collections.ObjectModel;

namespace GameHelperGUI.ViewModels;

public sealed class ParameterSectionViewModel
{
    public string Name { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public ObservableCollection<ParameterItemViewModel> Items { get; } = new();
}
