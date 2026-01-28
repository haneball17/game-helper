using System.Runtime.InteropServices;

namespace GameHelperGUI.Models;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct HelperControlV1
{
    public uint Version;
    public uint Size;
    public uint Pid;
    public uint LastUpdateTick;
    public byte FullscreenAttack;
    public byte FullscreenSkill;
    public byte AutoTransparent;
    public byte Attract;
    public byte HotkeyEnabled;
    public byte Reserved0;
    public byte Reserved1;
    public byte Reserved2;
    public uint SummonSequence;
}
