using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using NetworkIsolation.Wfp.Native;

namespace NetworkIsolation.Wfp;

/// <summary>Terminates active IPv4 TCP connections owned by a target executable or PID set via SetTcpEntry.</summary>
public static class TcpConnectionTerminator
{
    private const int MaxTableRetries = 5;

    public static int TerminateConnectionsForExecutable(string executablePath, ulong? onlyIfNotLocalIp = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        if (onlyIfNotLocalIp.HasValue)
            throw new NotSupportedException("Filtering TCP termination by local IP/LUID is not supported.");

        string full = Path.GetFullPath(executablePath);
        var ids = new List<int>();

        foreach (Process proc in Process.GetProcesses())
        {
            try
            {
                string? fileName = proc.MainModule?.FileName;
                if (!string.IsNullOrEmpty(fileName)
                    && string.Equals(Path.GetFullPath(fileName), full, StringComparison.OrdinalIgnoreCase))
                {
                    ids.Add(proc.Id);
                }
            }
            catch (Win32Exception)
            {
                // Protected, elevated, or architecture-mismatched processes cannot be inspected.
            }
            catch (InvalidOperationException)
            {
                // Process exited before MainModule was queried.
            }
            catch (UnauthorizedAccessException)
            {
            }
            catch (NotSupportedException)
            {
            }
            finally
            {
                proc.Dispose();
            }
        }

        return TerminateConnectionsForPids(ids);
    }

    public static int TerminateConnectionsForPids(IEnumerable<int> pids)
    {
        ArgumentNullException.ThrowIfNull(pids);

        var targets = new HashSet<uint>();
        foreach (int pid in pids)
        {
            if (pid > 0)
                targets.Add((uint)pid);
        }

        if (targets.Count == 0)
            return 0;

        uint size = 0;
        uint rc = IpHelperNative.GetExtendedTcpTable(
            0, ref size, false, IpHelperNative.AfInet, IpHelperNative.TcpTableOwnerPidConnections, 0);
        if (rc == IpHelperNative.ErrorSuccess && size == 0)
            return 0;
        if (rc != IpHelperNative.ErrorInsufficientBuffer && rc != IpHelperNative.ErrorSuccess)
            throw new Win32Exception((int)rc);
        if (size < sizeof(uint))
            return 0;

        for (int attempt = 0; attempt < MaxTableRetries; attempt++)
        {
            if (size > int.MaxValue)
                throw new InvalidOperationException($"TCP table buffer size {size} exceeds supported bounds.");

            nint tablePtr = Marshal.AllocHGlobal((int)size);
            try
            {
                rc = IpHelperNative.GetExtendedTcpTable(
                    tablePtr, ref size, false, IpHelperNative.AfInet, IpHelperNative.TcpTableOwnerPidConnections, 0);
                if (rc == IpHelperNative.ErrorInsufficientBuffer)
                    continue;
                if (rc != IpHelperNative.ErrorSuccess)
                    throw new Win32Exception((int)rc);

                return TerminateMatchingRows(tablePtr, size, targets);
            }
            finally
            {
                Marshal.FreeHGlobal(tablePtr);
            }
        }

        throw new Win32Exception((int)IpHelperNative.ErrorInsufficientBuffer);
    }

    private static int TerminateMatchingRows(nint tablePtr, uint bufferSize, HashSet<uint> targetPids)
    {
        if (bufferSize < sizeof(uint))
            return 0;

        int count = Marshal.ReadInt32(tablePtr);
        int rowSize = Marshal.SizeOf<IpHelperNative.TcpRowOwnerPid>();
        if (count < 0 || sizeof(uint) + (long)count * rowSize > bufferSize)
            throw new InvalidDataException($"MIB_TCPTABLE_OWNER_PID entry count {count} exceeds buffer size {bufferSize}.");

        int done = 0;
        for (int i = 0; i < count; i++)
        {
            var entry = Marshal.PtrToStructure<IpHelperNative.TcpRowOwnerPid>(tablePtr + sizeof(uint) + i * rowSize);
            if (!targetPids.Contains(entry.OwningPid))
                continue;
            if (entry.State is IpHelperNative.TcpStateClosed or IpHelperNative.TcpStateListen or IpHelperNative.TcpStateDeleteTcb)
                continue;

            var row = new IpHelperNative.TcpRow
            {
                State = IpHelperNative.TcpStateDeleteTcb,
                LocalAddress = entry.LocalAddress,
                LocalPort = entry.LocalPort,
                RemoteAddress = entry.RemoteAddress,
                RemotePort = entry.RemotePort
            };

            uint setRc = IpHelperNative.SetTcpEntry(ref row);
            if (setRc == IpHelperNative.ErrorSuccess)
            {
                done++;
            }
            else if (setRc is IpHelperNative.ErrorAccessDenied or IpHelperNative.ErrorElevationRequired)
            {
                throw new Win32Exception((int)setRc);
            }
            else if (setRc is IpHelperNative.ErrorNotFound or IpHelperNative.ErrorInvalidParameter or IpHelperNative.ErrorMrMidNotFound)
            {
                // Socket transitioned to CLOSED/TIME_WAIT concurrently between snapshot and SetTcpEntry.
                continue;
            }
            else
            {
                throw new Win32Exception((int)setRc);
            }
        }

        return done;
    }
}
