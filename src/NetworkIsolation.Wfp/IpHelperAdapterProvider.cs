using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using NetworkIsolation.Core;
using NetworkIsolation.Wfp.Native;

namespace NetworkIsolation.Wfp;

/// <summary>Enumerates Windows network adapters via IP Helper and watches for interface/address changes.</summary>
public sealed class IpHelperAdapterProvider : IDisposable
{
    private const int MaxBufferRetries = 5;

    private readonly object _watchLock = new();
    private IpHelperNative.InterfaceChangeCallback? _interfaceCallback;
    private IpHelperNative.InterfaceChangeCallback? _addressCallback;
    private GCHandle _interfaceCallbackHandle;
    private GCHandle _addressCallbackHandle;
    private nint _interfaceHandle;
    private nint _addressHandle;
    private int _disposed;

    /// <summary>Raised asynchronously when IP interface or unicast address state changes.</summary>
    public event Action? AdaptersChanged;

    /// <summary>Raised when a watcher notification or subscriber handler fails inside the callback pipeline.</summary>
    public event Action<Exception>? WatcherError;

    internal bool HasRootedCallbacks
    {
        get
        {
            lock (_watchLock)
            {
                return _interfaceCallbackHandle.IsAllocated && _addressCallbackHandle.IsAllocated;
            }
        }
    }

    public IReadOnlyList<AdapterInfo> GetAdapters()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        uint size = 0;
        uint flags = IpHelperNative.GaafIncludePrefix | IpHelperNative.GaafIncludeGateways;
        uint rc = IpHelperNative.GetAdaptersAddresses(IpHelperNative.AfUnspec, flags, 0, 0, ref size);
        if (rc == IpHelperNative.ErrorNoData)
            return [];
        if (rc != IpHelperNative.ErrorBufferOverflow && rc != IpHelperNative.ErrorSuccess)
            throw new Win32Exception((int)rc);
        if (size == 0)
            return [];

        for (int attempt = 0; attempt < MaxBufferRetries; attempt++)
        {
            if (size > int.MaxValue)
                throw new InvalidOperationException($"Adapter enumeration buffer size {size} exceeds supported bounds.");

            nint mem = Marshal.AllocHGlobal((int)size);
            try
            {
                rc = IpHelperNative.GetAdaptersAddresses(IpHelperNative.AfUnspec, flags, 0, mem, ref size);
                if (rc == IpHelperNative.ErrorBufferOverflow)
                    continue;
                if (rc == IpHelperNative.ErrorNoData)
                    return [];
                if (rc != IpHelperNative.ErrorSuccess)
                    throw new Win32Exception((int)rc);

                return ParseAdapters(mem);
            }
            finally
            {
                Marshal.FreeHGlobal(mem);
            }
        }

        throw new Win32Exception((int)IpHelperNative.ErrorBufferOverflow);
    }

    public bool TryResolveInterfaceIndex(ulong netLuid, out uint ifIndex)
    {
        if (netLuid == 0)
        {
            ifIndex = 0;
            return false;
        }
        return IpHelperNative.ConvertInterfaceLuidToIndex(ref netLuid, out ifIndex) == IpHelperNative.ErrorSuccess;
    }

    public bool TryResolveNetLuid(uint interfaceIndex, out ulong netLuid)
    {
        if (interfaceIndex == 0)
        {
            netLuid = 0;
            return false;
        }
        return IpHelperNative.ConvertInterfaceIndexToLuid(interfaceIndex, out netLuid) == IpHelperNative.ErrorSuccess;
    }

    public void StartWatching()
    {
        lock (_watchLock)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            if (_interfaceHandle != 0 || _addressHandle != 0)
                return;

            IpHelperNative.InterfaceChangeCallback ifaceCb = OnNativeNotification;
            IpHelperNative.InterfaceChangeCallback addrCb = OnNativeNotification;
            GCHandle ifacePin = GCHandle.Alloc(ifaceCb);
            GCHandle addrPin = GCHandle.Alloc(addrCb);
            nint ifaceHandle = 0;
            nint addrHandle = 0;

            try
            {
                uint rc = IpHelperNative.NotifyIpInterfaceChange(
                    IpHelperNative.AfUnspec, ifaceCb, 0, false, out ifaceHandle);
                if (rc != IpHelperNative.ErrorSuccess)
                    throw new Win32Exception((int)rc);

                rc = IpHelperNative.NotifyUnicastIpAddressChange(
                    IpHelperNative.AfUnspec, addrCb, 0, false, out addrHandle);
                if (rc != IpHelperNative.ErrorSuccess)
                    throw new Win32Exception((int)rc);

                _interfaceCallback = ifaceCb;
                _addressCallback = addrCb;
                _interfaceCallbackHandle = ifacePin;
                _addressCallbackHandle = addrPin;
                _interfaceHandle = ifaceHandle;
                _addressHandle = addrHandle;
            }
            catch
            {
                // Cancel native registrations before freeing pinned callback delegates.
                if (addrHandle != 0)
                    _ = IpHelperNative.CancelMibChangeNotify2(addrHandle);
                if (ifaceHandle != 0)
                    _ = IpHelperNative.CancelMibChangeNotify2(ifaceHandle);
                if (addrPin.IsAllocated)
                    addrPin.Free();
                if (ifacePin.IsAllocated)
                    ifacePin.Free();
                throw;
            }
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;

        nint ifaceHandle;
        nint addrHandle;
        GCHandle ifacePin;
        GCHandle addrPin;

        lock (_watchLock)
        {
            ifaceHandle = _interfaceHandle;
            addrHandle = _addressHandle;
            ifacePin = _interfaceCallbackHandle;
            addrPin = _addressCallbackHandle;

            _interfaceHandle = 0;
            _addressHandle = 0;
            _interfaceCallbackHandle = default;
            _addressCallbackHandle = default;
            _interfaceCallback = null;
            _addressCallback = null;
        }

        // CancelMibChangeNotify2 waits for any in-flight native callbacks to finish,
        // so it must run outside _watchLock and before freeing the delegate GCHandles.
        if (ifaceHandle != 0)
        {
            uint rc = IpHelperNative.CancelMibChangeNotify2(ifaceHandle);
            if (rc != IpHelperNative.ErrorSuccess)
                Trace.TraceWarning($"CancelMibChangeNotify2(interface) returned {rc}.");
        }

        if (addrHandle != 0)
        {
            uint rc = IpHelperNative.CancelMibChangeNotify2(addrHandle);
            if (rc != IpHelperNative.ErrorSuccess)
                Trace.TraceWarning($"CancelMibChangeNotify2(address) returned {rc}.");
        }

        if (ifacePin.IsAllocated)
            ifacePin.Free();
        if (addrPin.IsAllocated)
            addrPin.Free();
    }

    internal void InvokeNativeNotificationForTest(nint context = 0, nint row = 0, uint notificationType = 0)
        => OnNativeNotification(context, row, notificationType);

    internal static IReadOnlyList<AdapterInfo> ParseAdapters(nint firstAdapter)
    {
        int minAdapterSize = Marshal.SizeOf<IpHelperNative.AdapterAddresses>();
        var list = new List<AdapterInfo>();
        nint p = firstAdapter;

        while (p != 0)
        {
            uint nodeLength = unchecked((uint)Marshal.ReadInt32(p));
            if (nodeLength < (uint)minAdapterSize)
                throw new InvalidDataException($"IP_ADAPTER_ADDRESSES length {nodeLength} is smaller than expected {minAdapterSize}.");

            var a = Marshal.PtrToStructure<IpHelperNative.AdapterAddresses>(p);
            list.Add(BuildAdapterInfo(in a));
            p = a.Next;
        }

        return list;
    }

    internal static AdapterInfo BuildAdapterInfo(in IpHelperNative.AdapterAddresses a)
    {
        ulong netLuid = a.Luid;
        uint ifIndex = a.IfIndex != 0 ? a.IfIndex : a.Ipv6IfIndex;
        if (ifIndex == 0 && netLuid != 0)
            _ = IpHelperNative.ConvertInterfaceLuidToIndex(ref netLuid, out ifIndex);
        if (netLuid == 0 && ifIndex != 0)
            _ = IpHelperNative.ConvertInterfaceIndexToLuid(ifIndex, out netLuid);

        if (!Guid.TryParse(Marshal.PtrToStringAnsi(a.AdapterName), out Guid interfaceGuid) && netLuid != 0)
        {
            if (IpHelperNative.ConvertInterfaceLuidToGuid(ref netLuid, out Guid resolvedGuid) == IpHelperNative.ErrorSuccess)
                interfaceGuid = resolvedGuid;
        }

        var (v4, v6) = ReadUnicastAddresses(a.FirstUnicastAddress);
        var dns = ReadSocketAddressList(a.FirstDnsServerAddress);
        var gw = ReadSocketAddressList(a.FirstGatewayAddress).FirstOrDefault();

        string status = FormatOperStatus(a.OperStatus);
        bool isLoopback = a.IfType == IpHelperNative.IfTypeSoftwareLoopback;
        bool isUpAndRoutable = ComputeIsUpAndRoutable(a.OperStatus, a.Flags, netLuid, ifIndex, isLoopback, v4, v6);

        return new AdapterInfo(
            netLuid,
            interfaceGuid,
            ifIndex,
            Marshal.PtrToStringUni(a.FriendlyName) ?? "",
            Marshal.PtrToStringUni(a.Description) ?? "",
            a.IfType,
            status,
            v4,
            v6,
            dns,
            a.Ipv4Metric,
            a.Ipv6Metric,
            isLoopback,
            isUpAndRoutable,
            gw,
            a.TransmitLinkSpeed);
    }

    internal static string FormatOperStatus(uint operStatus) => operStatus switch
    {
        IpHelperNative.IfOperStatusUp => "Up",
        IpHelperNative.IfOperStatusDown => "Down",
        IpHelperNative.IfOperStatusTesting => "Testing",
        IpHelperNative.IfOperStatusUnknown => "Unknown",
        IpHelperNative.IfOperStatusDormant => "Dormant",
        IpHelperNative.IfOperStatusNotPresent => "NotPresent",
        IpHelperNative.IfOperStatusLowerLayerDown => "LowerLayerDown",
        _ => operStatus.ToString()
    };

    internal static bool ComputeIsUpAndRoutable(
        uint operStatus,
        uint adapterFlags,
        ulong netLuid,
        uint ifIndex,
        bool isLoopback,
        IReadOnlyList<IPAddress> v4,
        IReadOnlyList<IPAddress> v6)
    {
        if (operStatus != IpHelperNative.IfOperStatusUp)
            return false;
        if ((adapterFlags & IpHelperNative.IpAdapterReceiveOnly) != 0)
            return false;
        if (netLuid == 0 || ifIndex == 0)
            return false;

        return isLoopback
            ? (v4.Count + v6.Count) > 0
            : v4.Any(IsRoutableUnicast) || v6.Any(IsRoutableUnicast);
    }

    internal static bool IsRoutableUnicast(IPAddress ip)
    {
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.Broadcast) || IPAddress.IsLoopback(ip))
                return false;

            Span<byte> bytes = stackalloc byte[4];
            if (!ip.TryWriteBytes(bytes, out int written) || written != 4)
                return false;

            return !(bytes[0] == 169 && bytes[1] == 254);
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return !ip.Equals(IPAddress.IPv6Any)
                && !IPAddress.IsLoopback(ip)
                && !ip.IsIPv6LinkLocal;
        }

        return false;
    }

    internal static (List<IPAddress> V4, List<IPAddress> V6) ReadUnicastAddresses(nint firstNode)
    {
        int minHeaderSize = (int)Marshal.OffsetOf<IpHelperNative.SocketAddressNode>(nameof(IpHelperNative.SocketAddressNode.Address))
            + Marshal.SizeOf<IpHelperNative.NativeSocketAddress>();
        int minDadStateSize = (int)Marshal.OffsetOf<IpHelperNative.UnicastAddressNode>(nameof(IpHelperNative.UnicastAddressNode.DadState))
            + sizeof(int);

        var v4Routable = new List<IPAddress>();
        var v4Other = new List<IPAddress>();
        var v6Routable = new List<IPAddress>();
        var v6Other = new List<IPAddress>();
        var seen = new HashSet<IPAddress>();

        nint p = firstNode;
        while (p != 0)
        {
            uint nodeLength = unchecked((uint)Marshal.ReadInt32(p));
            if (nodeLength < (uint)minHeaderSize)
                throw new InvalidDataException($"IP_ADAPTER_UNICAST_ADDRESS length {nodeLength} is smaller than expected {minHeaderSize}.");

            nint next;
            IpHelperNative.NativeSocketAddress socketAddress;
            bool isPreferred = true;

            if (nodeLength >= (uint)minDadStateSize)
            {
                var node = Marshal.PtrToStructure<IpHelperNative.UnicastAddressNode>(p);
                next = node.Next;
                socketAddress = node.Address;
                isPreferred = node.DadState == IpHelperNative.IpDadStatePreferred;
            }
            else
            {
                var node = Marshal.PtrToStructure<IpHelperNative.SocketAddressNode>(p);
                next = node.Next;
                socketAddress = node.Address;
            }

            if (isPreferred && TryReadIpAddress(socketAddress.Sockaddr, socketAddress.SockaddrLength, out IPAddress? ip) && ip is not null && seen.Add(ip))
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                    (IsRoutableUnicast(ip) ? v4Routable : v4Other).Add(ip);
                else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                    (IsRoutableUnicast(ip) ? v6Routable : v6Other).Add(ip);
            }

            p = next;
        }

        v4Routable.AddRange(v4Other);
        v6Routable.AddRange(v6Other);
        return (v4Routable, v6Routable);
    }

    internal static List<IPAddress> ReadSocketAddressList(nint firstNode)
    {
        int minNodeSize = (int)Marshal.OffsetOf<IpHelperNative.SocketAddressNode>(nameof(IpHelperNative.SocketAddressNode.Address))
            + Marshal.SizeOf<IpHelperNative.NativeSocketAddress>();

        var result = new List<IPAddress>();
        var seen = new HashSet<IPAddress>();
        nint p = firstNode;

        while (p != 0)
        {
            uint nodeLength = unchecked((uint)Marshal.ReadInt32(p));
            if (nodeLength < (uint)minNodeSize)
                throw new InvalidDataException($"IP_ADAPTER address node length {nodeLength} is smaller than expected {minNodeSize}.");

            var node = Marshal.PtrToStructure<IpHelperNative.SocketAddressNode>(p);
            if (TryReadIpAddress(node.Address.Sockaddr, node.Address.SockaddrLength, out IPAddress? ip) && ip is not null && seen.Add(ip))
                result.Add(ip);

            p = node.Next;
        }

        return result;
    }

    internal static bool TryReadIpAddress(nint sockaddr, int sockaddrLength, out IPAddress? address)
    {
        address = null;
        if (sockaddr == 0 || sockaddrLength < sizeof(ushort))
            return false;

        ushort af = unchecked((ushort)Marshal.ReadInt16(sockaddr));
        if (af == IpHelperNative.AfInet)
        {
            if (sockaddrLength < IpHelperNative.SockaddrInSize)
                return false;

            byte[] bytes = new byte[4];
            Marshal.Copy(sockaddr + IpHelperNative.SockaddrInAddrOffset, bytes, 0, bytes.Length);
            address = new IPAddress(bytes);
            return true;
        }

        if (af == IpHelperNative.AfInet6)
        {
            if (sockaddrLength < IpHelperNative.SockaddrIn6Size)
                return false;

            byte[] bytes = new byte[16];
            Marshal.Copy(sockaddr + IpHelperNative.SockaddrIn6AddrOffset, bytes, 0, bytes.Length);
            uint scopeId = unchecked((uint)Marshal.ReadInt32(sockaddr + IpHelperNative.SockaddrIn6ScopeIdOffset));

            var ip = new IPAddress(bytes);
            if (ip.IsIPv6LinkLocal && scopeId != 0)
                ip = new IPAddress(bytes, scopeId);

            address = ip;
            return true;
        }

        return false;
    }

    private void OnNativeNotification(nint context, nint row, uint notificationType)
    {
        try
        {
            if (Volatile.Read(ref _disposed) != 0)
                return;

            // Dispatch asynchronously so subscribers calling GetAdapters() or Dispose() cannot
            // re-enter NSI or deadlock CancelMibChangeNotify2 from the native callback thread.
            ThreadPool.QueueUserWorkItem(static state =>
            {
                var self = (IpHelperAdapterProvider)state!;
                self.DispatchAdaptersChanged();
            }, this);
        }
        catch (Exception ex)
        {
            ReportWatcherError(ex);
        }
    }

    private void DispatchAdaptersChanged()
    {
        if (Volatile.Read(ref _disposed) != 0)
            return;

        try
        {
            AdaptersChanged?.Invoke();
        }
        catch (Exception ex)
        {
            ReportWatcherError(ex);
        }
    }

    private void ReportWatcherError(Exception ex)
    {
        Trace.TraceError($"IpHelperAdapterProvider watcher callback failed: {ex}");
        try
        {
            WatcherError?.Invoke(ex);
        }
        catch (Exception handlerEx)
        {
            Trace.TraceError($"IpHelperAdapterProvider WatcherError handler threw: {handlerEx}");
        }
    }
}
