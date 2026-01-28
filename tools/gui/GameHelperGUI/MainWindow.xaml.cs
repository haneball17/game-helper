using System.Windows;
using System.Windows.Input;
using GameHelperGUI.ViewModels;

namespace GameHelperGUI;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = new MainViewModel();
    }

    protected override void OnPreviewKeyDown(KeyEventArgs e)
    {
        if (DataContext is MainViewModel viewModel && viewModel.HandleHotkeyInput(e.Key))
        {
            e.Handled = true;
        }
        base.OnPreviewKeyDown(e);
    }
}
