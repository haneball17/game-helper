namespace GameHelperGUI.Models;

public sealed class HelperStatusSnapshot
{
    public ulong LastTickMs { get; init; }
    public uint Pid { get; init; }
    public bool ProcessAlive { get; init; }
    public bool AutoTransparentEnabled { get; init; }
    public bool FullscreenAttackTarget { get; init; }
    public bool FullscreenAttackPatchOn { get; init; }
    public int AttractMode { get; init; }
    public bool AttractPositive { get; init; }
    public bool SummonEnabled { get; init; }
    public ulong SummonLastTick { get; init; }
    public bool FullscreenSkillEnabled { get; init; }
    public bool FullscreenSkillActive { get; init; }
    public uint FullscreenSkillHotkey { get; init; }
    public bool HotkeyEnabled { get; init; }
    public string PlayerName { get; init; } = string.Empty;
}
