using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using NetworkIsolation.Wfp;
using NetworkIsolation.Wfp.Native;
using Xunit;

namespace NetworkIsolation.Tests;

public class IpHelperLiveTests
{
    [Fact]
    public void EnumeratesLiveAdaptersAndStableLuids()
    {
        using var provider = new IpHelperAdapterProvider();
        var adapters = provider.GetAdapters();
        Assert.NotEmpty(adapters);
        Assert.Contains(adapters, a => a.IsLoopback);

        foreach (var a in adapters)
        {
            Assert.NotEqual(0UL, a.NetLuid);
            Assert.NotEqual(Guid.Empty, a.InterfaceGuid);
            Assert.True(provider.TryResolveInterfaceIndex(a.NetLuid, out var index));
            Assert.Equal(a.InterfaceIndex, index);
            Assert.True(provider.TryResolveNetLuid(a.InterfaceIndex, out var roundTrippedLuid));
            Assert.Equal(a.NetLuid, roundTrippedLuid);
            if (!a.IsLoopback)
                Assert.NotEqual((ulong)a.InterfaceIndex, a.NetLuid);
        }
    }

    [Fact]
    public void WatcherStartsAndDisposesIdempotentlyAndRootsCallbacks()
    {
        var p = new IpHelperAdapterProvider();
        Assert.False(p.HasRootedCallbacks);

        p.StartWatching();
        Assert.True(p.HasRootedCallbacks);

        p.StartWatching();
        Assert.True(p.HasRootedCallbacks);

        p.Dispose();
        Assert.False(p.HasRootedCallbacks);

        p.Dispose();
        Assert.Throws<ObjectDisposedException>(() => p.StartWatching());
        Assert.Throws<ObjectDisposedException>(() => p.GetAdapters());
    }

    [Fact]
    public void WatcherSwallowsAndReportsSubscriberExceptions()
    {
        using var provider = new IpHelperAdapterProvider();
        using var errorSeen = new ManualResetEventSlim(false);
        Exception? captured = null;

        provider.AdaptersChanged += () => throw new InvalidOperationException("boom");
        provider.WatcherError += ex =>
        {
            captured = ex;
            errorSeen.Set();
        };

        // Must not throw across the native callback boundary.
        provider.InvokeNativeNotificationForTest();

        Assert.True(errorSeen.Wait(TimeSpan.FromSeconds(5)));
        Assert.IsType<InvalidOperationException>(captured);
    }

    [Fact]
    public void X64NativeStructLayoutsMatchWindowsSdk()
    {
        if (!Environment.Is64BitProcess)
            return;

        Assert.Equal(232, Marshal.SizeOf<IpHelperNative.AdapterAddresses>());
        Assert.Equal(0, (int)Marshal.OffsetOf<IpHelperNative.AdapterAddresses>(nameof(IpHelperNative.AdapterAddresses.Length)));
        Assert.Equal(4, (int)Marshal.OffsetOf<IpHelperNative.AdapterAddresses>(nameof(IpHelperNative.AdapterAddresses.IfIndex)));
        Assert.Equal(8, (int)Marshal.OffsetOf<IpHelperNative.AdapterAddresses>(nameof(IpHelperNative.AdapterAddresses.Next)));
        Assert.Equal(16, (int)Marshal.OffsetOf<IpHelperNative.AdapterAddresses>(nameof(IpHelperNative.AdapterAddresses.AdapterName)));
        Assert.Equal(24, (int)Marshal.OffsetOf<IpHelperNative.AdapterAddresses>(nameof(IpHelperNative.AdapterAddresses.FirstUnicastAddress)));
        Assert.Equal(48, (int)Marshal.OffsetOf<IpHelperNative.AdapterAddresses>(nameof(IpHelperNative.AdapterAddresses.FirstDnsServerAddress)));
        Assert.Equal(64, (int)Marshal.OffsetOf<IpHelperNative.AdapterAddresses>(nameof(IpHelperNative.AdapterAddresses.FriendlyName)));
        Assert.Equal(72, (int)Marshal.OffsetOf<IpHelperNative.AdapterAddresses>(nameof(IpHelperNative.AdapterAddresses.Description)));
        Assert.Equal(80, (int)Marshal.OffsetOf<IpHelperNative.AdapterAddresses>(nameof(IpHelperNative.AdapterAddresses.PhysicalAddress)));
        Assert.Equal(88, (int)Marshal.OffsetOf<IpHelperNative.AdapterAddresses>(nameof(IpHelperNative.AdapterAddresses.PhysicalAddressLength)));
        Assert.Equal(92, (int)Marshal.OffsetOf<IpHelperNative.AdapterAddresses>(nameof(IpHelperNative.AdapterAddresses.Flags)));
        Assert.Equal(100, (int)Marshal.OffsetOf<IpHelperNative.AdapterAddresses>(nameof(IpHelperNative.AdapterAddresses.IfType)));
        Assert.Equal(104, (int)Marshal.OffsetOf<IpHelperNative.AdapterAddresses>(nameof(IpHelperNative.AdapterAddresses.OperStatus)));
        Assert.Equal(108, (int)Marshal.OffsetOf<IpHelperNative.AdapterAddresses>(nameof(IpHelperNative.AdapterAddresses.Ipv6IfIndex)));
        Assert.Equal(112, (int)Marshal.OffsetOf<IpHelperNative.AdapterAddresses>(nameof(IpHelperNative.AdapterAddresses.ZoneIndices)));
        Assert.Equal(176, (int)Marshal.OffsetOf<IpHelperNative.AdapterAddresses>(nameof(IpHelperNative.AdapterAddresses.FirstPrefix)));
        Assert.Equal(184, (int)Marshal.OffsetOf<IpHelperNative.AdapterAddresses>(nameof(IpHelperNative.AdapterAddresses.TransmitLinkSpeed)));
        Assert.Equal(208, (int)Marshal.OffsetOf<IpHelperNative.AdapterAddresses>(nameof(IpHelperNative.AdapterAddresses.FirstGatewayAddress)));
        Assert.Equal(216, (int)Marshal.OffsetOf<IpHelperNative.AdapterAddresses>(nameof(IpHelperNative.AdapterAddresses.Ipv4Metric)));
        Assert.Equal(220, (int)Marshal.OffsetOf<IpHelperNative.AdapterAddresses>(nameof(IpHelperNative.AdapterAddresses.Ipv6Metric)));
        Assert.Equal(224, (int)Marshal.OffsetOf<IpHelperNative.AdapterAddresses>(nameof(IpHelperNative.AdapterAddresses.Luid)));

        Assert.Equal(16, Marshal.SizeOf<IpHelperNative.NativeSocketAddress>());
        Assert.Equal(0, (int)Marshal.OffsetOf<IpHelperNative.NativeSocketAddress>(nameof(IpHelperNative.NativeSocketAddress.Sockaddr)));
        Assert.Equal(8, (int)Marshal.OffsetOf<IpHelperNative.NativeSocketAddress>(nameof(IpHelperNative.NativeSocketAddress.SockaddrLength)));

        Assert.Equal(32, Marshal.SizeOf<IpHelperNative.SocketAddressNode>());
        Assert.Equal(16, (int)Marshal.OffsetOf<IpHelperNative.SocketAddressNode>(nameof(IpHelperNative.SocketAddressNode.Address)));

        Assert.Equal(64, Marshal.SizeOf<IpHelperNative.UnicastAddressNode>());
        Assert.Equal(16, (int)Marshal.OffsetOf<IpHelperNative.UnicastAddressNode>(nameof(IpHelperNative.UnicastAddressNode.Address)));
        Assert.Equal(32, (int)Marshal.OffsetOf<IpHelperNative.UnicastAddressNode>(nameof(IpHelperNative.UnicastAddressNode.PrefixOrigin)));
        Assert.Equal(40, (int)Marshal.OffsetOf<IpHelperNative.UnicastAddressNode>(nameof(IpHelperNative.UnicastAddressNode.DadState)));
        Assert.Equal(56, (int)Marshal.OffsetOf<IpHelperNative.UnicastAddressNode>(nameof(IpHelperNative.UnicastAddressNode.OnLinkPrefixLength)));

        Assert.Equal(20, Marshal.SizeOf<IpHelperNative.TcpRow>());
        Assert.Equal(24, Marshal.SizeOf<IpHelperNative.TcpRowOwnerPid>());
        Assert.Equal(20, (int)Marshal.OffsetOf<IpHelperNative.TcpRowOwnerPid>(nameof(IpHelperNative.TcpRowOwnerPid.OwningPid)));
    }

    [Fact]
    public void TryReadIpAddress_ValidatesFamilyAndSockaddrLength()
    {
        nint v4Mem = Marshal.AllocHGlobal(IpHelperNative.SockaddrInSize);
        nint v6Mem = Marshal.AllocHGlobal(IpHelperNative.SockaddrIn6Size);
        try
        {
            for (int i = 0; i < IpHelperNative.SockaddrInSize; i++) Marshal.WriteByte(v4Mem + i, 0);
            Marshal.WriteInt16(v4Mem, unchecked((short)IpHelperNative.AfInet));
            Marshal.Copy(new byte[] { 192, 0, 2, 44 }, 0, v4Mem + IpHelperNative.SockaddrInAddrOffset, 4);

            Assert.True(IpHelperAdapterProvider.TryReadIpAddress(v4Mem, IpHelperNative.SockaddrInSize, out var v4));
            Assert.Equal(IPAddress.Parse("192.0.2.44"), v4);
            Assert.False(IpHelperAdapterProvider.TryReadIpAddress(v4Mem, IpHelperNative.SockaddrInSize - 1, out _));

            for (int i = 0; i < IpHelperNative.SockaddrIn6Size; i++) Marshal.WriteByte(v6Mem + i, 0);
            Marshal.WriteInt16(v6Mem, unchecked((short)IpHelperNative.AfInet6));
            var linkLocal = IPAddress.Parse("fe80::42");
            Marshal.Copy(linkLocal.GetAddressBytes(), 0, v6Mem + IpHelperNative.SockaddrIn6AddrOffset, 16);
            Marshal.WriteInt32(v6Mem + IpHelperNative.SockaddrIn6ScopeIdOffset, 17);

            Assert.True(IpHelperAdapterProvider.TryReadIpAddress(v6Mem, IpHelperNative.SockaddrIn6Size, out var v6));
            Assert.Equal(AddressFamily.InterNetworkV6, v6!.AddressFamily);
            Assert.Equal(17L, v6.ScopeId);
            Assert.False(IpHelperAdapterProvider.TryReadIpAddress(v6Mem, IpHelperNative.SockaddrIn6Size - 1, out _));

            // Non-IP family (e.g., AF_UNSPEC or AF_LINK) must be rejected even with large buffer.
            Marshal.WriteInt16(v6Mem, 17);
            Assert.False(IpHelperAdapterProvider.TryReadIpAddress(v6Mem, IpHelperNative.SockaddrIn6Size, out _));
        }
        finally
        {
            Marshal.FreeHGlobal(v4Mem);
            Marshal.FreeHGlobal(v6Mem);
        }
    }

    [Fact]
    public void ReadUnicastAddresses_FiltersDadStateAndOrdersRoutableFirst()
    {
        int nodeSize = Marshal.SizeOf<IpHelperNative.UnicastAddressNode>();
        nint n1 = Marshal.AllocHGlobal(nodeSize);
        nint n2 = Marshal.AllocHGlobal(nodeSize);
        nint n3 = Marshal.AllocHGlobal(nodeSize);
        nint sa1 = Marshal.AllocHGlobal(IpHelperNative.SockaddrInSize);
        nint sa2 = Marshal.AllocHGlobal(IpHelperNative.SockaddrInSize);
        nint sa3 = Marshal.AllocHGlobal(IpHelperNative.SockaddrInSize);

        try
        {
            WriteSockaddrIn(sa1, new byte[] { 169, 254, 10, 20 });
            WriteSockaddrIn(sa2, new byte[] { 10, 0, 0, 5 }); // Tentative -> excluded
            WriteSockaddrIn(sa3, new byte[] { 198, 51, 100, 7 }); // Preferred routable -> ordered first

            Marshal.StructureToPtr(new IpHelperNative.UnicastAddressNode
            {
                Length = (uint)nodeSize,
                Next = n2,
                Address = new IpHelperNative.NativeSocketAddress { Sockaddr = sa1, SockaddrLength = IpHelperNative.SockaddrInSize },
                DadState = IpHelperNative.IpDadStatePreferred
            }, n1, false);

            Marshal.StructureToPtr(new IpHelperNative.UnicastAddressNode
            {
                Length = (uint)nodeSize,
                Next = n3,
                Address = new IpHelperNative.NativeSocketAddress { Sockaddr = sa2, SockaddrLength = IpHelperNative.SockaddrInSize },
                DadState = IpHelperNative.IpDadStateTentative
            }, n2, false);

            Marshal.StructureToPtr(new IpHelperNative.UnicastAddressNode
            {
                Length = (uint)nodeSize,
                Next = 0,
                Address = new IpHelperNative.NativeSocketAddress { Sockaddr = sa3, SockaddrLength = IpHelperNative.SockaddrInSize },
                DadState = IpHelperNative.IpDadStatePreferred
            }, n3, false);

            var (v4, v6) = IpHelperAdapterProvider.ReadUnicastAddresses(n1);
            Assert.Empty(v6);
            Assert.Equal(new[] { IPAddress.Parse("198.51.100.7"), IPAddress.Parse("169.254.10.20") }, v4);
        }
        finally
        {
            Marshal.FreeHGlobal(n1);
            Marshal.FreeHGlobal(n2);
            Marshal.FreeHGlobal(n3);
            Marshal.FreeHGlobal(sa1);
            Marshal.FreeHGlobal(sa2);
            Marshal.FreeHGlobal(sa3);
        }
    }

    [Fact]
    public void ComputeIsUpAndRoutable_RequiresUpNonReceiveOnlyAndRoutableAddress()
    {
        var apipaOnly = new[] { IPAddress.Parse("169.254.1.2") };
        var linkLocalV6Only = new[] { IPAddress.Parse("fe80::1") };
        var routableV4 = new[] { IPAddress.Parse("192.0.2.10") };

        Assert.False(IpHelperAdapterProvider.ComputeIsUpAndRoutable(
            IpHelperNative.IfOperStatusUp, 0, 100, 2, false, apipaOnly, linkLocalV6Only));
        Assert.False(IpHelperAdapterProvider.ComputeIsUpAndRoutable(
            IpHelperNative.IfOperStatusDown, 0, 100, 2, false, routableV4, []));
        Assert.False(IpHelperAdapterProvider.ComputeIsUpAndRoutable(
            IpHelperNative.IfOperStatusUp, IpHelperNative.IpAdapterReceiveOnly, 100, 2, false, routableV4, []));
        Assert.True(IpHelperAdapterProvider.ComputeIsUpAndRoutable(
            IpHelperNative.IfOperStatusUp, 0, 100, 2, false, routableV4, linkLocalV6Only));
        Assert.True(IpHelperAdapterProvider.ComputeIsUpAndRoutable(
            IpHelperNative.IfOperStatusUp, 0, 100, 1, true, [IPAddress.Loopback], []));
    }

    [Fact]
    public void TcpConnectionTerminator_ValidatesArgumentsExplicitly()
    {
        Assert.Throws<ArgumentNullException>(() => TcpConnectionTerminator.TerminateConnectionsForPids(null!));
        Assert.Equal(0, TcpConnectionTerminator.TerminateConnectionsForPids([]));
        Assert.Throws<ArgumentException>(() => TcpConnectionTerminator.TerminateConnectionsForExecutable("   "));
        Assert.Throws<NotSupportedException>(() => TcpConnectionTerminator.TerminateConnectionsForExecutable("sample.exe", 123UL));
    }

    private static void WriteSockaddrIn(nint mem, byte[] ipv4Bytes)
    {
        for (int i = 0; i < IpHelperNative.SockaddrInSize; i++) Marshal.WriteByte(mem + i, 0);
        Marshal.WriteInt16(mem, unchecked((short)IpHelperNative.AfInet));
        Marshal.Copy(ipv4Bytes, 0, mem + IpHelperNative.SockaddrInAddrOffset, 4);
    }
}
