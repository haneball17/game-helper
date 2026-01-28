namespace GameHelperGUI.Models;

public sealed class HelperControlSnapshot
{
    public ControlOverride FullscreenAttack { get; init; } = ControlOverride.Follow;
    public ControlOverride FullscreenSkill { get; init; } = ControlOverride.Follow;
    public ControlOverride AutoTransparent { get; init; } = ControlOverride.Follow;
    public ControlOverride Attract { get; init; } = ControlOverride.Follow;
    public ControlOverride HotkeyEnabled { get; init; } = ControlOverride.Follow;
    public uint SummonSequence { get; init; }
}
