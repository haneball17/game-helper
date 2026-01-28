using System.Text;
using GameHelperGUI.Models;

namespace GameHelperGUI.ViewModels;

public sealed class ProcessStatusViewModel
{
    public uint Pid { get; init; }
    public string PlayerName { get; init; } = string.Empty;
    public string StatusText { get; init; } = "未知";
    public string LastUpdateText { get; init; } = "-";
    public bool IsOnline { get; init; }
    public bool IsCompatible { get; init; }

    public bool AutoTransparentEnabled { get; init; }
    public bool FullscreenAttackTarget { get; init; }
    public bool FullscreenAttackPatchOn { get; init; }
    public int AttractMode { get; init; }
    public bool AttractPositive { get; init; }
    public bool SummonEnabled { get; init; }
    public bool FullscreenSkillEnabled { get; init; }
    public bool FullscreenSkillActive { get; init; }
    public uint FullscreenSkillHotkey { get; init; }
    public bool HotkeyEnabled { get; init; }

    public string DisplayName => string.IsNullOrWhiteSpace(PlayerName) ? "未知角色" : PlayerName;
    public string PidText => Pid.ToString();
    public string FullscreenAttackSummary => $"{(FullscreenAttackTarget ? "开" : "关")}/{(FullscreenAttackPatchOn ? "开" : "关")}";

    public string DetailSummary
    {
        get
        {
            var builder = new StringBuilder();
            builder.AppendLine($"角色：{DisplayName}");
            builder.AppendLine($"PID：{Pid}");
            builder.AppendLine($"状态：{StatusText}");
            builder.AppendLine($"最近更新：{LastUpdateText}");
            builder.AppendLine($"全屏攻击：目标={(FullscreenAttackTarget ? "开" : "关")} / 当前={(FullscreenAttackPatchOn ? "开" : "关")}");
            builder.AppendLine($"自动透明：{(AutoTransparentEnabled ? "开" : "关")}");
            builder.AppendLine($"吸怪模式：{AttractMode}，方向：{(AttractPositive ? "正向" : "负向")}");
            builder.AppendLine($"召唤人偶：{(SummonEnabled ? "启用" : "停用")}");
            builder.AppendLine($"全屏技能：{(FullscreenSkillEnabled ? "启用" : "停用")} / {(FullscreenSkillActive ? "激活" : "关闭")}");
            builder.AppendLine($"技能热键：{HotkeyTextFormatter.Format((int)FullscreenSkillHotkey)}");
            builder.AppendLine($"热键响应：{(HotkeyEnabled ? "启用" : "停用")}");
            return builder.ToString().TrimEnd();
        }
    }

    public static ProcessStatusViewModel FromSnapshot(HelperStatusSnapshot snapshot, string statusText, string lastUpdateText, bool isOnline)
    {
        return new ProcessStatusViewModel
        {
            Pid = snapshot.Pid,
            PlayerName = snapshot.PlayerName,
            StatusText = statusText,
            LastUpdateText = lastUpdateText,
            IsOnline = isOnline,
            IsCompatible = true,
            AutoTransparentEnabled = snapshot.AutoTransparentEnabled,
            FullscreenAttackTarget = snapshot.FullscreenAttackTarget,
            FullscreenAttackPatchOn = snapshot.FullscreenAttackPatchOn,
            AttractMode = snapshot.AttractMode,
            AttractPositive = snapshot.AttractPositive,
            SummonEnabled = snapshot.SummonEnabled,
            FullscreenSkillEnabled = snapshot.FullscreenSkillEnabled,
            FullscreenSkillActive = snapshot.FullscreenSkillActive,
            FullscreenSkillHotkey = snapshot.FullscreenSkillHotkey,
            HotkeyEnabled = snapshot.HotkeyEnabled
        };
    }
}
