using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using NetworkIsolation.Core;
using NetworkIsolation.Wfp;
using NetworkIsolation.Wfp.Native;

namespace NetworkIsolation.Tests;

public class AdapterBoundProxyTests
{
    private static AdapterInfo Loopback(bool up = true, IReadOnlyList<IPAddress>? dnsServers = null) => new(
        1,
        Guid.Empty,
        1,
        "Loopback",
        "Loopback",
        24,
        up ? "Up" : "Down",
        [IPAddress.Loopback],
        [IPAddress.IPv6Loopback],
        dnsServers ?? [],
        0,
        0,
        true,
        up);

    private static async Task<(TcpListener Listener, Task Task)> Echo(IPAddress? bindAddress = null)
    {
        var listener = new TcpListener(bindAddress ?? IPAddress.Loopback, 0);
        listener.Start();
        var task = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            var stream = client.GetStream();
            var buffer = new byte[1024];
            int read;
            while ((read = await stream.ReadAsync(buffer)) > 0)
            {
                await stream.WriteAsync(buffer.AsMemory(0, read));
            }
        });
        return (listener, task);
    }

    private static async Task RoundTrip(AdapterBoundProxy proxy, bool socks, int target, string host = "127.0.0.1")
    {
        using var c = new TcpClient();
        await c.ConnectAsync(IPAddress.Loopback, proxy.Port);
        var s = c.GetStream();
        if (!socks)
        {
            string authority = host.Contains(':') ? $"[{host}]:{target}" : $"{host}:{target}";
            await s.WriteAsync(Encoding.ASCII.GetBytes($"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"));
            var line = await ReadLine(s);
            Assert.Contains("200", line);
            while ((await ReadLine(s)).Length > 0) { }
        }
        else
        {
            await s.WriteAsync(new byte[] { 5, 1, 0 });
            var m = new byte[2];
            await s.ReadExactlyAsync(m);
            Assert.Equal(new byte[] { 5, 0 }, m);

            byte[] req;
            var ip = IPAddress.Parse(host);
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                req = new byte[10];
                req[0] = 5; req[1] = 1; req[2] = 0; req[3] = 1;
                ip.TryWriteBytes(req.AsSpan(4, 4), out _);
                BinaryPrimitives.WriteUInt16BigEndian(req.AsSpan(8, 2), (ushort)target);
            }
            else
            {
                req = new byte[22];
                req[0] = 5; req[1] = 1; req[2] = 0; req[3] = 4;
                ip.TryWriteBytes(req.AsSpan(4, 16), out _);
                BinaryPrimitives.WriteUInt16BigEndian(req.AsSpan(20, 2), (ushort)target);
            }

            await s.WriteAsync(req);
            var rep = new byte[10];
            await s.ReadExactlyAsync(rep);
            Assert.Equal((byte)0, rep[1]);
        }

        var data = Encoding.UTF8.GetBytes("echo payload");
        await s.WriteAsync(data);
        var received = new byte[data.Length];
        await s.ReadExactlyAsync(received);
        Assert.Equal(data, received);
    }

    private static async Task<string> ReadLine(Stream s)
    {
        var b = new List<byte>();
        var one = new byte[1];
        while (true)
        {
            int n = await s.ReadAsync(one.AsMemory(0, 1));
            if (n == 0 || one[0] == 10)
            {
                break;
            }
            if (one[0] != 13)
            {
                b.Add(one[0]);
            }
        }
        return Encoding.ASCII.GetString(b.ToArray());
    }

    [Fact]
    public async Task HttpConnect_TunnelsEcho()
    {
        var (l, _) = await Echo();
        try
        {
            await using var p = new AdapterBoundProxy(Loopback());
            await RoundTrip(p, false, ((IPEndPoint)l.LocalEndpoint).Port);
        }
        finally
        {
            l.Stop();
        }
    }

    [Fact]
    public async Task Socks5_TunnelsEcho()
    {
        var (l, _) = await Echo();
        try
        {
            await using var p = new AdapterBoundProxy(Loopback());
            await RoundTrip(p, true, ((IPEndPoint)l.LocalEndpoint).Port);
        }
        finally
        {
            l.Stop();
        }
    }

    [Fact]
    public async Task HttpConnect_And_Socks5_Ipv6Loopback_TunnelsEcho()
    {
        if (!Socket.OSSupportsIPv6)
        {
            return;
        }

        var (httpListener, _) = await Echo(IPAddress.IPv6Loopback);
        var (socksListener, _) = await Echo(IPAddress.IPv6Loopback);
        try
        {
            await using var p = new AdapterBoundProxy(Loopback());
            await RoundTrip(p, false, ((IPEndPoint)httpListener.LocalEndpoint).Port, "::1");
            await RoundTrip(p, true, ((IPEndPoint)socksListener.LocalEndpoint).Port, "::1");
        }
        finally
        {
            httpListener.Stop();
            socksListener.Stop();
        }
    }

    [Fact]
    public async Task HttpConnect_HalfCloseClientWrite_PreservesUpstreamResponse()
    {
        var (l, echoTask) = await Echo();
        try
        {
            await using var p = new AdapterBoundProxy(Loopback());
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, p.Port);
            var stream = client.GetStream();

            int targetPort = ((IPEndPoint)l.LocalEndpoint).Port;
            await stream.WriteAsync(Encoding.ASCII.GetBytes($"CONNECT 127.0.0.1:{targetPort} HTTP/1.1\r\nHost: 127.0.0.1:{targetPort}\r\n\r\n"));
            string status = await ReadLine(stream);
            Assert.Contains("200", status);
            while ((await ReadLine(stream)).Length > 0) { }

            byte[] payload = Encoding.UTF8.GetBytes("half-close-payload");
            await stream.WriteAsync(payload);
            client.Client.Shutdown(SocketShutdown.Send);

            using var ms = new MemoryStream();
            await stream.CopyToAsync(ms);
            Assert.Equal(payload, ms.ToArray());
            await echoTask;
        }
        finally
        {
            l.Stop();
        }
    }

    [Fact]
    public void BindSocket_DisconnectedAdapterFailsClosed()
    {
        using var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        Assert.Throws<InvalidOperationException>(() => SocketNative.BindSocketToAdapter(s, Loopback(false), AddressFamily.InterNetwork));
    }

    [Fact]
    public async Task Proxy_DisconnectedAdapterCannotConnect()
    {
        await Assert.ThrowsAsync<IOException>(() => AdapterBoundProxy.ConnectViaAdapterAsync("127.0.0.1", 9, Loopback(false), CancellationToken.None));
    }

    [Fact]
    public void BuildUnicastInterfaceOption_UsesNetworkOrderForIpv4AndHostOrderForIpv6()
    {
        const uint index = 0x01020304u;
        var v4 = SocketNative.BuildUnicastInterfaceOption(index, AddressFamily.InterNetwork);
        var v6 = SocketNative.BuildUnicastInterfaceOption(index, AddressFamily.InterNetworkV6);

        Assert.Equal(SocketNative.IPPROTO_IP, v4.Level);
        Assert.Equal(SocketNative.IP_UNICAST_IF, v4.OptionName);
        byte[] v4Bytes = BitConverter.GetBytes(v4.OptionValue);
        Assert.Equal(new byte[] { 0x01, 0x02, 0x03, 0x04 }, v4Bytes);

        Assert.Equal(SocketNative.IPPROTO_IPV6, v6.Level);
        Assert.Equal(SocketNative.IPV6_UNICAST_IF, v6.OptionName);
        byte[] v6Bytes = BitConverter.GetBytes(v6.OptionValue);
        Assert.Equal(BitConverter.GetBytes((int)index), v6Bytes);
    }

    [Fact]
    public void SetUnicastInterface_ValidatesArgumentsAndDisposedSocket()
    {
        using var v4Socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        Assert.Throws<ArgumentOutOfRangeException>(() => SocketNative.SetUnicastInterface(v4Socket, 0, AddressFamily.InterNetwork));
        Assert.Throws<ArgumentOutOfRangeException>(() => SocketNative.SetUnicastInterface(v4Socket, (uint)int.MaxValue + 1, AddressFamily.InterNetwork));
        Assert.Throws<ArgumentException>(() => SocketNative.SetUnicastInterface(v4Socket, 1, AddressFamily.Unix));
        Assert.Throws<ArgumentException>(() => SocketNative.SetUnicastInterface(v4Socket, 1, AddressFamily.InterNetworkV6));

        var disposed = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        disposed.Dispose();
        Assert.Throws<ObjectDisposedException>(() => SocketNative.SetUnicastInterface(disposed, 1, AddressFamily.InterNetwork));
    }

    [Fact]
    public void SelectBindAddress_SkipsUnspecifiedAndPrefersNonLinkLocal()
    {
        var adapter = new AdapterInfo(
            2,
            Guid.Empty,
            7,
            "Ethernet",
            "Ethernet",
            6,
            "Up",
            [IPAddress.Any, IPAddress.Loopback, IPAddress.Parse("169.254.10.20"), IPAddress.Parse("192.0.2.50")],
            [IPAddress.IPv6Any, IPAddress.IPv6Loopback, IPAddress.Parse("fe80::1"), IPAddress.Parse("2001:db8::5")],
            [],
            10,
            10,
            false,
            true);

        Assert.Equal(IPAddress.Parse("192.0.2.50"), SocketNative.SelectBindAddress(adapter, AddressFamily.InterNetwork));
        Assert.Equal(IPAddress.Parse("2001:db8::5"), SocketNative.SelectBindAddress(adapter, AddressFamily.InterNetworkV6));

        var linkLocalOnlyV6 = new AdapterInfo(
            3,
            Guid.Empty,
            9,
            "Ethernet-LL",
            "Ethernet-LL",
            6,
            "Up",
            [],
            [IPAddress.Parse("fe80::42")],
            [],
            10,
            10,
            false,
            true);

        IPAddress? selectedV6 = SocketNative.SelectBindAddress(linkLocalOnlyV6, AddressFamily.InterNetworkV6);
        Assert.NotNull(selectedV6);
        Assert.Equal(9, selectedV6!.ScopeId);
    }

    [Fact]
    public async Task ConnectViaAdapterAsync_StrictDnsWithNoServers_RefusesSystemFallback()
    {
        // "localhost" resolves in system DNS, so throwing InvalidOperationException proves zero fallback occurred.
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            AdapterBoundProxy.ConnectViaAdapterAsync("localhost", 80, Loopback(true, []), CancellationToken.None));
    }

    [Fact]
    public async Task ConnectViaAdapterAsync_StrictDnsFailure_DoesNotFallbackToSystemDns()
    {
        var adapterWithDeadDns = Loopback(true, [IPAddress.Parse("127.0.0.254")]);
        await Assert.ThrowsAsync<IOException>(() =>
            AdapterBoundProxy.ConnectViaAdapterAsync(
                "nonexistent-no-fallback.invalid",
                80,
                adapterWithDeadDns,
                CancellationToken.None,
                strictAdapterDns: true,
                dnsTimeout: TimeSpan.FromMilliseconds(100)));
    }

    [Fact]
    public async Task ConnectViaAdapterAsync_CallerCancellation_PropagatesOperationCanceled()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var adapterWithDns = Loopback(true, [IPAddress.Parse("127.0.0.254")]);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            AdapterBoundProxy.ConnectViaAdapterAsync("example.test", 80, adapterWithDns, cts.Token));
    }

    [Theory]
    [InlineData("example.test", 1)]
    [InlineData("v6.example.test", 28)]
    public void DnsQueryAndResponse_AAndAaaa(string name, ushort type)
    {
        var q = DnsWire.BuildQuery(name, type);
        Assert.Equal((byte)type, q[^3]);
        var addr = type == 1 ? IPAddress.Parse("192.0.2.1") : IPAddress.Parse("2001:db8::1");
        var packet = Response(type, addr.GetAddressBytes());
        Assert.Equal(addr, DnsWire.ParseResponse(packet).Single());
    }

    [Fact]
    public void DnsWire_ValidatesQueriesAndRejectsMalformedOrMismatchedResponses()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => DnsWire.BuildQuery("example.test", 15));
        Assert.Throws<ArgumentException>(() => DnsWire.BuildQuery("", 1));
        Assert.Throws<ArgumentException>(() => DnsWire.BuildQuery(".", 1));
        Assert.Throws<ArgumentException>(() => DnsWire.BuildQuery("a..b", 1));
        Assert.Throws<ArgumentException>(() => DnsWire.BuildQuery(new string('a', 64) + ".test", 1));

        byte[] validV4 = Response(1, IPAddress.Parse("192.0.2.5").GetAddressBytes(), txId: 0x1234);
        Assert.True(DnsWire.TryParseResponse(validV4, 0x1234, 1, out var ips, out int rcode));
        Assert.Equal(0, rcode);
        Assert.Equal(IPAddress.Parse("192.0.2.5"), ips.Single());

        // Mismatched transaction ID and mismatched QTYPE must be rejected.
        Assert.False(DnsWire.TryParseResponse(validV4, 0x9999, 1, out _, out _));
        Assert.Empty(DnsWire.ParseResponse(validV4, 0x1234, 28));

        // Non-zero RCODE (NXDOMAIN = 3) returns empty address list and exposes rcode.
        byte[] nxdomain = (byte[])validV4.Clone();
        nxdomain[3] = (byte)((nxdomain[3] & 0xF0) | 3);
        Assert.True(DnsWire.TryParseResponse(nxdomain, 0x1234, 1, out var nxIps, out int nxRcode));
        Assert.Equal(3, nxRcode);
        Assert.Empty(nxIps);

        // Truncated compression pointer (0xC0 with no second byte) must fail safely without throwing.
        byte[] truncatedPointer = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0];
        Assert.False(DnsWire.TryParseResponse(truncatedPointer, 0x1234, 1, out _, out _));

        // Reserved label type 0x40 must be rejected.
        byte[] reservedLabel = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0x40, 0x00];
        Assert.False(DnsWire.TryParseResponse(reservedLabel, 0x1234, 1, out _, out _));
    }

    [Theory]
    [InlineData("CONNECT 127.0.0.1:0 HTTP/1.1\r\n\r\n", "400")]
    [InlineData("CONNECT 127.0.0.1:70000 HTTP/1.1\r\n\r\n", "400")]
    [InlineData("CONNECT ::1:80 HTTP/1.1\r\n\r\n", "400")]
    [InlineData("CONNECT 127.0.0.1:80\r\n\r\n", "400")]
    [InlineData("GET http://127.0.0.1/ HTTP/1.1\r\n\r\n", "405")]
    public async Task HttpConnect_InvalidRequests_SendHttpErrorAndRaiseErrorOccurred(string rawRequest, string expectedCode)
    {
        var errors = new ConcurrentQueue<ProxyErrorEventArgs>();
        await using var proxy = new AdapterBoundProxy(Loopback(), onError: errors.Enqueue);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, proxy.Port);
        var stream = client.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes(rawRequest));

        string statusLine = await ReadLine(stream);
        Assert.Contains(expectedCode, statusLine);
        Assert.NotEmpty(errors);
    }

    [Fact]
    public async Task HttpConnect_HeaderLimits_RejectOversizedLineAndExcessHeaders()
    {
        var errors = new ConcurrentQueue<ProxyErrorEventArgs>();
        await using var proxy = new AdapterBoundProxy(Loopback(), onError: errors.Enqueue);

        // Oversized single header line (> 8192 bytes)
        using (var c1 = new TcpClient())
        {
            await c1.ConnectAsync(IPAddress.Loopback, proxy.Port);
            var s1 = c1.GetStream();
            string huge = $"CONNECT 127.0.0.1:80 HTTP/1.1\r\nX-Huge: {new string('a', AdapterBoundProxy.MaxHttpLineBytes + 10)}\r\n\r\n";
            await s1.WriteAsync(Encoding.ASCII.GetBytes(huge));
            Assert.Contains("431", await ReadLine(s1));
        }

        // Too many header lines (> 64)
        using (var c2 = new TcpClient())
        {
            await c2.ConnectAsync(IPAddress.Loopback, proxy.Port);
            var s2 = c2.GetStream();
            var sb = new StringBuilder("CONNECT 127.0.0.1:80 HTTP/1.1\r\n");
            for (int i = 0; i <= AdapterBoundProxy.MaxHttpHeaderCount; i++)
            {
                sb.Append($"X-H{i}: v\r\n");
            }
            sb.Append("\r\n");
            await s2.WriteAsync(Encoding.ASCII.GetBytes(sb.ToString()));
            Assert.Contains("431", await ReadLine(s2));
        }

        Assert.True(errors.Count >= 2);
    }

    [Fact]
    public async Task Socks5_InvalidHandshakeAndRequests_SendRfcRepliesAndRaiseErrorOccurred()
    {
        var errors = new ConcurrentQueue<ProxyErrorEventArgs>();
        await using var proxy = new AdapterBoundProxy(Loopback(), onError: errors.Enqueue);

        // 1. Missing no-auth method -> [5, 0xFF]
        using (var c1 = new TcpClient())
        {
            await c1.ConnectAsync(IPAddress.Loopback, proxy.Port);
            var s1 = c1.GetStream();
            await s1.WriteAsync(new byte[] { 5, 1, 2 });
            var rep1 = new byte[2];
            await s1.ReadExactlyAsync(rep1);
            Assert.Equal(new byte[] { 5, 0xFF }, rep1);
        }

        // 2. Unsupported command (BIND = 2) -> rep[1] == 0x07
        using (var c2 = new TcpClient())
        {
            await c2.ConnectAsync(IPAddress.Loopback, proxy.Port);
            var s2 = c2.GetStream();
            await s2.WriteAsync(new byte[] { 5, 1, 0 });
            await s2.ReadExactlyAsync(new byte[2]);
            await s2.WriteAsync(new byte[] { 5, 2, 0, 1, 127, 0, 0, 1, 0, 80 });
            var rep2 = new byte[10];
            await s2.ReadExactlyAsync(rep2);
            Assert.Equal((byte)0x07, rep2[1]);
        }

        // 3. Unsupported ATYP (0x09) -> rep[1] == 0x08
        using (var c3 = new TcpClient())
        {
            await c3.ConnectAsync(IPAddress.Loopback, proxy.Port);
            var s3 = c3.GetStream();
            await s3.WriteAsync(new byte[] { 5, 1, 0 });
            await s3.ReadExactlyAsync(new byte[2]);
            await s3.WriteAsync(new byte[] { 5, 1, 0, 0x09, 1, 2, 3, 4, 0, 80 });
            var rep3 = new byte[10];
            await s3.ReadExactlyAsync(rep3);
            Assert.Equal((byte)0x08, rep3[1]);
        }

        // 4. Empty domain (ATYP=3, len=0) -> rep[1] == 0x01
        using (var c4 = new TcpClient())
        {
            await c4.ConnectAsync(IPAddress.Loopback, proxy.Port);
            var s4 = c4.GetStream();
            await s4.WriteAsync(new byte[] { 5, 1, 0 });
            await s4.ReadExactlyAsync(new byte[2]);
            await s4.WriteAsync(new byte[] { 5, 1, 0, 3, 0, 0, 80 });
            var rep4 = new byte[10];
            await s4.ReadExactlyAsync(rep4);
            Assert.Equal((byte)0x01, rep4[1]);
        }

        // 5. Port 0 -> rep[1] == 0x01
        using (var c5 = new TcpClient())
        {
            await c5.ConnectAsync(IPAddress.Loopback, proxy.Port);
            var s5 = c5.GetStream();
            await s5.WriteAsync(new byte[] { 5, 1, 0 });
            await s5.ReadExactlyAsync(new byte[2]);
            await s5.WriteAsync(new byte[] { 5, 1, 0, 1, 127, 0, 0, 1, 0, 0 });
            var rep5 = new byte[10];
            await s5.ReadExactlyAsync(rep5);
            Assert.Equal((byte)0x01, rep5[1]);
        }

        Assert.True(errors.Count >= 5);
    }

    [Fact]
    public async Task Proxy_UpstreamFailure_ReturnsProtocolFailureAndRaisesErrorOccurred()
    {
        var errors = new ConcurrentQueue<ProxyErrorEventArgs>();
        await using var proxy = new AdapterBoundProxy(Loopback(up: false), onError: errors.Enqueue);

        // HTTP CONNECT failure -> 502 Bad Gateway
        using (var c1 = new TcpClient())
        {
            await c1.ConnectAsync(IPAddress.Loopback, proxy.Port);
            var s1 = c1.GetStream();
            await s1.WriteAsync("CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n"u8.ToArray());
            Assert.Contains("502", await ReadLine(s1));
        }

        // SOCKS5 failure -> non-zero reply code
        using (var c2 = new TcpClient())
        {
            await c2.ConnectAsync(IPAddress.Loopback, proxy.Port);
            var s2 = c2.GetStream();
            await s2.WriteAsync(new byte[] { 5, 1, 0 });
            await s2.ReadExactlyAsync(new byte[2]);
            await s2.WriteAsync(new byte[] { 5, 1, 0, 1, 127, 0, 0, 1, 0x01, 0xBB });
            var rep = new byte[10];
            await s2.ReadExactlyAsync(rep);
            Assert.NotEqual((byte)0, rep[1]);
        }

        Assert.Contains(errors, e => e.Stage == "UpstreamConnect" && e.TargetHost == "127.0.0.1" && e.TargetPort == 443);
    }

    [Fact]
    public async Task Proxy_DisposeAsync_IsIdempotentAndAbortsStalledClients()
    {
        var proxy = new AdapterBoundProxy(Loopback(), handshakeTimeout: TimeSpan.FromSeconds(30));
        using var stalledClient = new TcpClient();
        await stalledClient.ConnectAsync(IPAddress.Loopback, proxy.Port);

        await proxy.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(3));
        await proxy.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(3));

        var buf = new byte[1];
        int read = await stalledClient.GetStream().ReadAsync(buf).AsTask().WaitAsync(TimeSpan.FromSeconds(3));
        Assert.Equal(0, read);
    }

    private static byte[] Response(ushort type, byte[] address, ushort txId = 0x4a31)
    {
        var q = DnsWire.BuildQuery("example.test", type, txId);
        using var m = new MemoryStream();
        m.Write(new byte[] { (byte)(txId >> 8), (byte)txId, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0 });
        m.Write(q.AsSpan(12));
        m.Write(new byte[] { 0xc0, 0x0c, (byte)(type >> 8), (byte)type, 0, 1, 0, 0, 0, 30, (byte)(address.Length >> 8), (byte)address.Length });
        m.Write(address);
        return m.ToArray();
    }
}
