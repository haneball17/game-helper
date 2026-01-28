using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using GameHelperGUI.Models;
using GameHelperGUI.Services;

namespace GameHelperGUI.ViewModels;

public sealed class ProcessControlViewModel : INotifyPropertyChanged
{
    private readonly SharedMemoryControlWriter _writer = new();
    private readonly Dictionary<uint, HelperControlSnapshot> _states = new();
    private bool _suspendWrite;
    private uint _pid;
    private ControlOverride _fullscreenAttackOverride = ControlOverride.Follow;
    private ControlOverride _fullscreenSkillOverride = ControlOverride.Follow;
    private ControlOverride _autoTransparentOverride = ControlOverride.Follow;
    private ControlOverride _attractOverride = ControlOverride.Follow;
    private ControlOverride _hotkeyEnabledOverride = ControlOverride.Follow;
    private uint _summonSequence;
    private string _statusMessage = string.Empty;

    public event PropertyChangedEventHandler? PropertyChanged;

    public IReadOnlyList<ControlOptionItem> OverrideOptions { get; } = new[]
    {
        new ControlOptionItem(ControlOverride.Follow, "跟随配置"),
        new ControlOptionItem(ControlOverride.ForceOn, "强制开启"),
        new ControlOptionItem(ControlOverride.ForceOff, "强制关闭")
    };

    public bool HasTarget => _pid != 0;

    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetField(ref _statusMessage, value);
    }

    public ControlOverride FullscreenAttackOverride
    {
        get => _fullscreenAttackOverride;
        set => SetOverride(ref _fullscreenAttackOverride, value);
    }

    public ControlOverride FullscreenSkillOverride
    {
        get => _fullscreenSkillOverride;
        set => SetOverride(ref _fullscreenSkillOverride, value);
    }

    public ControlOverride AutoTransparentOverride
    {
        get => _autoTransparentOverride;
        set => SetOverride(ref _autoTransparentOverride, value);
    }

    public ControlOverride AttractOverride
    {
        get => _attractOverride;
        set => SetOverride(ref _attractOverride, value);
    }

    public ControlOverride HotkeyEnabledOverride
    {
        get => _hotkeyEnabledOverride;
        set => SetOverride(ref _hotkeyEnabledOverride, value);
    }

    public ICommand SummonCommand { get; }

    public ProcessControlViewModel()
    {
        SummonCommand = new RelayCommand(_ => TriggerSummon(), _ => HasTarget);
    }

    public void UpdateTarget(ProcessStatusViewModel? process)
    {
        uint pid = process?.Pid ?? 0;
        _pid = pid;
        _suspendWrite = true;
        if (pid == 0)
        {
            FullscreenAttackOverride = ControlOverride.Follow;
            FullscreenSkillOverride = ControlOverride.Follow;
            AutoTransparentOverride = ControlOverride.Follow;
            AttractOverride = ControlOverride.Follow;
            HotkeyEnabledOverride = ControlOverride.Follow;
            _summonSequence = 0;
            StatusMessage = "未选择实例";
        }
        else
        {
            var state = GetOrCreateState(pid);
            FullscreenAttackOverride = state.FullscreenAttack;
            FullscreenSkillOverride = state.FullscreenSkill;
            AutoTransparentOverride = state.AutoTransparent;
            AttractOverride = state.Attract;
            HotkeyEnabledOverride = state.HotkeyEnabled;
            _summonSequence = state.SummonSequence;
            StatusMessage = string.Empty;
        }
        _suspendWrite = false;
        OnPropertyChanged(nameof(HasTarget));
        CommandManager.InvalidateRequerySuggested();
    }

    private void TriggerSummon()
    {
        if (_pid == 0)
        {
            return;
        }
        _summonSequence = unchecked(_summonSequence + 1);
        PersistState();
    }

    private void SetOverride(ref ControlOverride field, ControlOverride value)
    {
        if (SetField(ref field, value))
        {
            PersistState();
        }
    }

    private HelperControlSnapshot GetOrCreateState(uint pid)
    {
        if (_states.TryGetValue(pid, out var state))
        {
            return state;
        }
        state = new HelperControlSnapshot();
        _states[pid] = state;
        return state;
    }

    private void PersistState()
    {
        if (_suspendWrite || _pid == 0)
        {
            return;
        }
        var snapshot = new HelperControlSnapshot
        {
            FullscreenAttack = _fullscreenAttackOverride,
            FullscreenSkill = _fullscreenSkillOverride,
            AutoTransparent = _autoTransparentOverride,
            Attract = _attractOverride,
            HotkeyEnabled = _hotkeyEnabledOverride,
            SummonSequence = _summonSequence
        };
        _states[_pid] = snapshot;
        var result = _writer.TryWrite(_pid, snapshot);
        switch (result)
        {
            case SharedMemoryWriteStatus.Ok:
                StatusMessage = "已发送";
                GuiLogger.Info("control", "write_ok", new Dictionary<string, object?>
                {
                    ["pid"] = _pid
                });
                break;
            case SharedMemoryWriteStatus.NotFound:
                StatusMessage = "未连接";
                GuiLogger.Info("control", "write_not_found", new Dictionary<string, object?>
                {
                    ["pid"] = _pid
                });
                break;
            default:
                StatusMessage = "写入失败";
                GuiLogger.Info("control", "write_failed", new Dictionary<string, object?>
                {
                    ["pid"] = _pid
                });
                break;
        }
    }

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }
        field = value;
        OnPropertyChanged(name);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public sealed class ControlOptionItem
    {
        public ControlOverride Value { get; }
        public string Label { get; }

        public ControlOptionItem(ControlOverride value, string label)
        {
            Value = value;
            Label = label;
        }
    }
}
