using System;
using System.IO;
using System.Windows;
using System.Windows.Threading;
using GameHelperGUI.Services;

namespace GameHelperGUI;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        string configPath = Path.Combine(baseDir, "game_helper.ini");
        GuiLogger.Initialize(configPath, baseDir);
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
        GuiLogger.Info("startup", "gui_started", new Dictionary<string, object?>
        {
            ["config_path"] = configPath
        });
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        GuiLogger.Error("exception", "dispatcher_unhandled", new Dictionary<string, object?>
        {
            ["error"] = e.Exception.Message,
            ["stack"] = e.Exception.StackTrace ?? string.Empty
        });
        e.Handled = true;
    }

    private void OnUnhandledException(object? sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception ex)
        {
            GuiLogger.Error("exception", "unhandled", new Dictionary<string, object?>
            {
                ["error"] = ex.Message,
                ["stack"] = ex.StackTrace ?? string.Empty
            });
        }
        else
        {
            GuiLogger.Error("exception", "unhandled_unknown");
        }
    }
}
