using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using GameHelperGUI.Models;

namespace GameHelperGUI.Services;

public enum SharedMemoryWriteStatus
{
    Ok,
    NotFound,
    WriteFailed
}

public sealed class SharedMemoryControlWriter
{
    private static readonly string[] MappingPrefixes =
    {
        "Global\\GameHelperControl_",
        "Local\\GameHelperControl_"
    };

    private const uint ExpectedVersion = 1;

    public SharedMemoryWriteStatus TryWrite(uint pid, HelperControlSnapshot snapshot)
    {
        foreach (string prefix in MappingPrefixes)
        {
            string mappingName = prefix + pid;
            var status = TryWriteInternal(mappingName, pid, snapshot);
            if (status == SharedMemoryWriteStatus.NotFound)
            {
                continue;
            }
            return status;
        }
        return SharedMemoryWriteStatus.NotFound;
    }

    private SharedMemoryWriteStatus TryWriteInternal(string mappingName, uint pid, HelperControlSnapshot snapshot)
    {
        try
        {
            using var mapping = MemoryMappedFile.OpenExisting(mappingName, MemoryMappedFileRights.ReadWrite);
            uint size = (uint)Marshal.SizeOf<HelperControlV1>();
            using var accessor = mapping.CreateViewAccessor(0, size, MemoryMappedFileAccess.Write);
            var raw = new HelperControlV1
            {
                Version = ExpectedVersion,
                Size = size,
                Pid = pid,
                LastUpdateTick = unchecked((uint)Environment.TickCount),
                FullscreenAttack = (byte)snapshot.FullscreenAttack,
                FullscreenSkill = (byte)snapshot.FullscreenSkill,
                AutoTransparent = (byte)snapshot.AutoTransparent,
                Attract = (byte)snapshot.Attract,
                HotkeyEnabled = (byte)snapshot.HotkeyEnabled,
                SummonSequence = snapshot.SummonSequence
            };
            accessor.Write(0, ref raw);
            return SharedMemoryWriteStatus.Ok;
        }
        catch (FileNotFoundException)
        {
            return SharedMemoryWriteStatus.NotFound;
        }
        catch (UnauthorizedAccessException)
        {
            return SharedMemoryWriteStatus.NotFound;
        }
        catch (IOException)
        {
            return SharedMemoryWriteStatus.WriteFailed;
        }
    }
}
