using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using System.Windows.Threading;
using GameHelperGUI.Models;
using GameHelperGUI.Services;

namespace GameHelperGUI.ViewModels;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private const long ConnectionTimeoutMs = 3000;
    private const string TargetProcessName = "dnf";
    private readonly SharedMemoryStatusReader _reader = new();
    private readonly DispatcherTimer _timer;
    private readonly Dictionary<uint, SharedMemoryReadStatus> _lastStatusByPid = new();
    private int _lastOnlineCount = -1;
    private int _lastOfflineCount = -1;
    private int _lastIncompatibleCount = -1;

    private string _summaryText = "暂无实例";
    private string _windowTitle = "Game Helper GUI";
    private ProcessStatusViewModel? _selectedProcess;

    public event PropertyChangedEventHandler? PropertyChanged;

    public ParameterConfigViewModel ParameterConfig { get; }
    public HotkeyConfigViewModel HotkeyConfig { get; }
    public ProcessControlViewModel ControlPanel { get; }

    public ObservableCollection<ProcessStatusViewModel> Processes { get; } = new();

    public ProcessStatusViewModel? SelectedProcess
    {
        get => _selectedProcess;
        set
        {
            if (SetField(ref _selectedProcess, value))
            {
                UpdateWindowTitle();
                OnPropertyChanged(nameof(SelectedDetailText));
                ControlPanel.UpdateTarget(value);
                if (value != null)
                {
                    GuiLogger.Info("selection", "process_selected", new Dictionary<string, object?>
                    {
                        ["pid"] = value.Pid,
                        ["player_name"] = value.DisplayName
                    });
                }
            }
        }
    }

    public string SummaryText
    {
        get => _summaryText;
        private set => SetField(ref _summaryText, value);
    }

    public string WindowTitle
    {
        get => _windowTitle;
        private set => SetField(ref _windowTitle, value);
    }

    public string SelectedDetailText => SelectedProcess?.DetailSummary ?? "请选择左侧实例";

    public MainViewModel()
    {
        var baseDir = AppDomain.CurrentDomain.BaseDirectory;
        var configPath = Path.Combine(baseDir, "game_helper.ini");
        var metadataPath = Path.Combine(baseDir, "config", "params.json");
        ParameterConfig = new ParameterConfigViewModel(configPath, metadataPath);
        HotkeyConfig = new HotkeyConfigViewModel(configPath);
        ControlPanel = new ProcessControlViewModel();

        _timer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(1000)
        };
        _timer.Tick += (_, _) => RefreshStatus();
        RefreshStatus();
        _timer.Start();
    }

    public bool HandleHotkeyInput(Key key)
    {
        return HotkeyConfig.HandleKey(key);
    }

    private void RefreshStatus()
    {
        var processes = Process.GetProcessesByName(TargetProcessName);
        int online = 0;
        int offline = 0;
        int incompatible = 0;

        Processes.Clear();
        foreach (var process in processes)
        {
            uint pid = (uint)process.Id;
            var status = _reader.TryRead(pid, out var snapshot);
            LogStatusChange(pid, status);
            if (status == SharedMemoryReadStatus.Ok)
            {
                var now = Environment.TickCount64;
                var delta = now - (long)snapshot.LastTickMs;
                bool isStale = delta > ConnectionTimeoutMs;
                string statusText = isStale ? "离线(超时)" : "在线";
                string lastUpdateText = isStale ? $">{ConnectionTimeoutMs}ms" : $"{Math.Max(0, delta)}ms";
                var vm = ProcessStatusViewModel.FromSnapshot(snapshot, statusText, lastUpdateText, !isStale);
                Processes.Add(vm);
                if (isStale)
                {
                    offline++;
                }
                else
                {
                    online++;
                }
                continue;
            }

            string fallbackStatus = status == SharedMemoryReadStatus.VersionMismatch ? "版本不兼容" : "未连接";
            var fallbackVm = new ProcessStatusViewModel
            {
                Pid = pid,
                PlayerName = string.Empty,
                StatusText = fallbackStatus,
                LastUpdateText = "-",
                IsOnline = false,
                IsCompatible = status != SharedMemoryReadStatus.VersionMismatch
            };
            Processes.Add(fallbackVm);
            if (status == SharedMemoryReadStatus.VersionMismatch)
            {
                incompatible++;
            }
            else
            {
                offline++;
            }
        }

        SummaryText = $"实例数：{Processes.Count}，在线：{online}，离线：{offline}，不兼容：{incompatible}";
        LogSummaryChange(online, offline, incompatible);
        RestoreSelection();
    }

    private void RestoreSelection()
    {
        if (Processes.Count == 0)
        {
            SelectedProcess = null;
            return;
        }
        if (SelectedProcess != null)
        {
            foreach (var item in Processes)
            {
                if (item.Pid == SelectedProcess.Pid)
                {
                    SelectedProcess = item;
                    return;
                }
            }
        }
        SelectedProcess = Processes[0];
    }

    private void UpdateWindowTitle()
    {
        if (SelectedProcess == null)
        {
            WindowTitle = "Game Helper GUI";
            return;
        }
        WindowTitle = $"Game Helper GUI - {SelectedProcess.DisplayName} (PID {SelectedProcess.Pid})";
    }

    private void LogStatusChange(uint pid, SharedMemoryReadStatus status)
    {
        if (_lastStatusByPid.TryGetValue(pid, out var lastStatus) && lastStatus == status)
        {
            return;
        }
        _lastStatusByPid[pid] = status;
        string message = status switch
        {
            SharedMemoryReadStatus.Ok => "ok",
            SharedMemoryReadStatus.NotFound => "not_found",
            SharedMemoryReadStatus.VersionMismatch => "version_mismatch",
            _ => "read_failed"
        };
        GuiLogger.Info("shared_memory", message, new Dictionary<string, object?>
        {
            ["pid"] = pid
        });
    }

    private void LogSummaryChange(int online, int offline, int incompatible)
    {
        if (online == _lastOnlineCount && offline == _lastOfflineCount && incompatible == _lastIncompatibleCount)
        {
            return;
        }
        _lastOnlineCount = online;
        _lastOfflineCount = offline;
        _lastIncompatibleCount = incompatible;
        GuiLogger.Info("process_summary", "update", new Dictionary<string, object?>
        {
            ["online"] = online,
            ["offline"] = offline,
            ["incompatible"] = incompatible
        });
    }

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
