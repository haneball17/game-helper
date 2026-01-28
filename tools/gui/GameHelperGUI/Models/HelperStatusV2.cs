using System.Runtime.InteropServices;

namespace GameHelperGUI.Models;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe struct HelperStatusV2
{
    public uint Version;
    public uint Size;
    public ulong LastTickMs;
    public uint Pid;
    public int ProcessAlive;
    public int AutoTransparentEnabled;
    public int FullscreenAttackTarget;
    public int FullscreenAttackPatchOn;
    public int AttractMode;
    public int AttractPositive;
    public int SummonEnabled;
    public ulong SummonLastTick;
    public int FullscreenSkillEnabled;
    public int FullscreenSkillActive;
    public uint FullscreenSkillHotkey;
    public int HotkeyEnabled;

    public fixed char PlayerName[32];
}
