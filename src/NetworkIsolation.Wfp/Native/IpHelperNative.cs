using System.Runtime.InteropServices;

namespace NetworkIsolation.Wfp.Native;

internal static class IpHelperNative
{
    internal const uint ErrorSuccess = 0;
    internal const uint ErrorAccessDenied = 5;
    internal const uint ErrorInvalidParameter = 87;
    internal const uint ErrorBufferOverflow = 111;
    internal const uint ErrorInsufficientBuffer = 122;
    internal const uint ErrorNoData = 232;
    internal const uint ErrorMrMidNotFound = 317;
    internal const uint ErrorElevationRequired = 740;
    internal const uint ErrorNotFound = 1168;

    internal const ushort AfUnspec = 0;
    internal const ushort AfInet = 2;
    internal const ushort AfInet6 = 23;

    internal const uint GaafIncludePrefix = 0x10;
    internal const uint GaafIncludeGateways = 0x80;

    internal const uint IfTypeSoftwareLoopback = 24;

    internal const uint IfOperStatusUp = 1;
    internal const uint IfOperStatusDown = 2;
    internal const uint IfOperStatusTesting = 3;
    internal const uint IfOperStatusUnknown = 4;
    internal const uint IfOperStatusDormant = 5;
    internal const uint IfOperStatusNotPresent = 6;
    internal const uint IfOperStatusLowerLayerDown = 7;

    internal const uint IpAdapterReceiveOnly = 0x0008;

    internal const int IpDadStateInvalid = 0;
    internal const int IpDadStateTentative = 1;
    internal const int IpDadStateDuplicate = 2;
    internal const int IpDadStateDeprecated = 3;
    internal const int IpDadStatePreferred = 4;

    internal const int SockaddrInSize = 16;
    internal const int SockaddrInAddrOffset = 4;
    internal const int SockaddrIn6Size = 28;
    internal const int SockaddrIn6AddrOffset = 8;
    internal const int SockaddrIn6ScopeIdOffset = 24;

    internal const uint TcpTableOwnerPidConnections = 4;
    internal const uint TcpStateClosed = 1;
    internal const uint TcpStateListen = 2;
    internal const uint TcpStateDeleteTcb = 12;

    /// <summary>
    /// Prefix of Windows SDK IP_ADAPTER_ADDRESSES_LH through Luid (232 bytes on x64).
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct AdapterAddresses
    {
        internal uint Length;
        internal uint IfIndex;
        internal nint Next;
        internal nint AdapterName;
        internal nint FirstUnicastAddress;
        internal nint FirstAnycastAddress;
        internal nint FirstMulticastAddress;
        internal nint FirstDnsServerAddress;
        internal nint DnsSuffix;
        internal nint FriendlyName;
        internal nint Description;
        internal fixed byte PhysicalAddress[8];
        internal uint PhysicalAddressLength;
        internal uint Flags;
        internal uint Mtu;
        internal uint IfType;
        internal uint OperStatus;
        internal uint Ipv6IfIndex;
        internal fixed uint ZoneIndices[16];
        internal nint FirstPrefix;
        internal ulong TransmitLinkSpeed;
        internal ulong ReceiveLinkSpeed;
        internal nint FirstWinsServerAddress;
        internal nint FirstGatewayAddress;
        internal uint Ipv4Metric;
        internal uint Ipv6Metric;
        internal ulong Luid;
    }

    /// <summary>
    /// Windows SDK SOCKET_ADDRESS (16 bytes on x64 including trailing alignment padding).
    /// Must remain a nested struct so subsequent fields align at offset 32 in IP_ADAPTER_UNICAST_ADDRESS_LH.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct NativeSocketAddress
    {
        internal nint Sockaddr;
        internal int SockaddrLength;
    }

    /// <summary>
    /// Windows SDK IP_ADAPTER_DNS_SERVER_ADDRESS_XP / IP_ADAPTER_GATEWAY_ADDRESS_LH (32 bytes on x64).
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct SocketAddressNode
    {
        internal uint Length;
        internal uint Flags;
        internal nint Next;
        internal NativeSocketAddress Address;
    }

    /// <summary>
    /// Windows SDK IP_ADAPTER_UNICAST_ADDRESS_LH (64 bytes on x64).
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct UnicastAddressNode
    {
        internal uint Length;
        internal uint Flags;
        internal nint Next;
        internal NativeSocketAddress Address;
        internal int PrefixOrigin;
        internal int SuffixOrigin;
        internal int DadState;
        internal uint ValidLifetime;
        internal uint PreferredLifetime;
        internal uint LeaseLifetime;
        internal byte OnLinkPrefixLength;
    }

    /// <summary>
    /// Windows SDK MIB_TCPROW_LH (20 bytes) passed to SetTcpEntry.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct TcpRow
    {
        internal uint State;
        internal uint LocalAddress;
        internal uint LocalPort;
        internal uint RemoteAddress;
        internal uint RemotePort;
    }

    /// <summary>
    /// Windows SDK MIB_TCPROW_OWNER_PID (24 bytes) returned in MIB_TCPTABLE_OWNER_PID.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct TcpRowOwnerPid
    {
        internal uint State;
        internal uint LocalAddress;
        internal uint LocalPort;
        internal uint RemoteAddress;
        internal uint RemotePort;
        internal uint OwningPid;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    internal delegate void InterfaceChangeCallback(nint context, nint row, uint notificationType);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    internal static extern uint GetAdaptersAddresses(
        uint family,
        uint flags,
        nint reserved,
        nint adapterAddresses,
        ref uint sizePointer);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    internal static extern uint ConvertInterfaceLuidToIndex(ref ulong luid, out uint ifIndex);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    internal static extern uint ConvertInterfaceIndexToLuid(uint ifIndex, out ulong luid);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    internal static extern uint ConvertInterfaceLuidToGuid(ref ulong luid, out Guid interfaceGuid);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    internal static extern uint NotifyIpInterfaceChange(
        ushort family,
        InterfaceChangeCallback callback,
        nint context,
        [MarshalAs(UnmanagedType.U1)] bool initialNotification,
        out nint notificationHandle);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    internal static extern uint NotifyUnicastIpAddressChange(
        ushort family,
        InterfaceChangeCallback callback,
        nint context,
        [MarshalAs(UnmanagedType.U1)] bool initialNotification,
        out nint notificationHandle);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    internal static extern uint CancelMibChangeNotify2(nint notificationHandle);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    internal static extern uint GetExtendedTcpTable(
        nint table,
        ref uint size,
        [MarshalAs(UnmanagedType.Bool)] bool order,
        uint family,
        uint tableClass,
        uint reserved);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    internal static extern uint SetTcpEntry(ref TcpRow row);
}
