using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using NetworkIsolation.Core;
using NetworkIsolation.Wfp.Native;

namespace NetworkIsolation.Wfp;

/// <summary>Error details raised by <see cref="AdapterBoundProxy"/> so failures are observable rather than silently swallowed.</summary>
public sealed class ProxyErrorEventArgs : EventArgs
{
    public ProxyErrorEventArgs(string stage, Exception exception, string? targetHost = null, int? targetPort = null)
    {
        Stage = stage;
        Exception = exception;
        TargetHost = targetHost;
        TargetPort = targetPort;
        TimestampUtc = DateTimeOffset.UtcNow;
    }

    public string Stage { get; }
    public Exception Exception { get; }
    public string? TargetHost { get; }
    public int? TargetPort { get; }
    public DateTimeOffset TimestampUtc { get; }
}

/// <summary>
/// A local loopback HTTP CONNECT and SOCKS5 proxy for cooperating applications whose upstream sockets
/// are explicitly steered onto a single <see cref="AdapterInfo"/> via <c>IP_UNICAST_IF</c>/<c>IPV6_UNICAST_IF</c>
/// and local source-address binding.
/// </summary>
/// <remarks>
/// This component provides explicit cooperating-app steering only. It does NOT intercept arbitrary unmodified
/// third-party sockets or act as a system-wide enforcement boundary; fail-closed isolation for arbitrary
/// applications requires WFP filters (and an optional kernel callout driver for transparent redirection).
/// </remarks>
public sealed class AdapterBoundProxy : IAsyncDisposable
{
    internal const int MaxHttpLineBytes = 8192;
    internal const int MaxHttpHeaderCount = 64;
    internal const int MaxHttpTotalHeaderBytes = 32 * 1024;
    private static readonly TimeSpan DefaultHandshakeTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan DefaultConnectTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan DefaultDnsTimeout = TimeSpan.FromSeconds(3);

    private readonly AdapterInfo _adapter;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _stop = new();
    private readonly SemaphoreSlim _concurrencyGate;
    private readonly ConcurrentDictionary<long, Task> _activeConnections = new();
    private readonly Action<ProxyErrorEventArgs>? _onError;
    private readonly TimeSpan _handshakeTimeout;
    private readonly TimeSpan _connectTimeout;
    private readonly TimeSpan _dnsTimeout;
    private readonly Task _acceptLoop;
    private long _nextConnectionId;
    private int _disposed;

    public bool StrictAdapterDns { get; }
    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
    public IPEndPoint EndPoint => (IPEndPoint)_listener.LocalEndpoint;

    /// <summary>Raised whenever a listener, protocol handshake, DNS, upstream connect, or relay error occurs.</summary>
    public event EventHandler<ProxyErrorEventArgs>? ErrorOccurred;

    public AdapterBoundProxy(
        AdapterInfo adapter,
        int port = 0,
        bool strictAdapterDns = true,
        Action<ProxyErrorEventArgs>? onError = null,
        int maxConcurrentConnections = 256,
        TimeSpan? handshakeTimeout = null,
        TimeSpan? connectTimeout = null,
        TimeSpan? dnsTimeout = null)
    {
        _adapter = adapter ?? throw new ArgumentNullException(nameof(adapter));
        if (port is < 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port), port, "Port must be between 0 and 65535.");
        }
        if (maxConcurrentConnections <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxConcurrentConnections), maxConcurrentConnections, "Max concurrent connections must be positive.");
        }
        if (handshakeTimeout.HasValue && handshakeTimeout.Value <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(handshakeTimeout), handshakeTimeout, "Handshake timeout must be positive.");
        }
        if (connectTimeout.HasValue && connectTimeout.Value <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(connectTimeout), connectTimeout, "Connect timeout must be positive.");
        }
        if (dnsTimeout.HasValue && dnsTimeout.Value <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(dnsTimeout), dnsTimeout, "DNS timeout must be positive.");
        }

        StrictAdapterDns = strictAdapterDns;
        _onError = onError;
        _handshakeTimeout = handshakeTimeout ?? DefaultHandshakeTimeout;
        _connectTimeout = connectTimeout ?? DefaultConnectTimeout;
        _dnsTimeout = dnsTimeout ?? DefaultDnsTimeout;
        _concurrencyGate = new SemaphoreSlim(maxConcurrentConnections, maxConcurrentConnections);

        _listener = new TcpListener(IPAddress.Loopback, port);
        try
        {
            _listener.Start();
        }
        catch
        {
            _stop.Dispose();
            _concurrencyGate.Dispose();
            throw;
        }

        _acceptLoop = AcceptLoopAsync();
    }

    private async Task AcceptLoopAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            TcpClient? client = null;
            bool gateAcquired = false;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_stop.Token).ConfigureAwait(false);
                await _concurrencyGate.WaitAsync(_stop.Token).ConfigureAwait(false);
                gateAcquired = true;

                long id = Interlocked.Increment(ref _nextConnectionId);
                var startGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                Task connectionTask = HandleClientAsync(client, id, startGate.Task);
                _activeConnections[id] = connectionTask;
                startGate.SetResult();
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested)
            {
                client?.Dispose();
                if (gateAcquired) _concurrencyGate.Release();
                break;
            }
            catch (ObjectDisposedException) when (_stop.IsCancellationRequested)
            {
                client?.Dispose();
                if (gateAcquired) _concurrencyGate.Release();
                break;
            }
            catch (Exception ex)
            {
                client?.Dispose();
                if (gateAcquired) _concurrencyGate.Release();
                ReportError("AcceptLoop", ex);
                if (_stop.IsCancellationRequested)
                {
                    break;
                }
            }
        }
    }

    private async Task HandleClientAsync(TcpClient client, long connectionId, Task startGate)
    {
        string? targetHost = null;
        int? targetPort = null;
        try
        {
            await startGate.ConfigureAwait(false);
            using (client)
            using (var closeReg = _stop.Token.Register(static s => ((TcpClient)s!).Dispose(), client))
            {
                NetworkStream stream = client.GetStream();

                using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
                handshakeCts.CancelAfter(_handshakeTimeout);

                int first = await ReadByteOrEofAsync(stream, handshakeCts.Token).ConfigureAwait(false);
                if (first < 0)
                {
                    return;
                }

                bool isSocks;
                string host;
                int port;
                if (first == 5)
                {
                    isSocks = true;
                    try
                    {
                        (host, port) = await SocksRequestAsync(stream, handshakeCts.Token).ConfigureAwait(false);
                    }
                    catch (SocksProtocolException ex)
                    {
                        ReportError(ex.GreetingFailed ? "Socks5Greeting" : "Socks5Request", ex);
                        if (!ex.GreetingFailed)
                        {
                            await TrySendSocksReplyAsync(stream, ex.ReplyCode, null, _stop.Token).ConfigureAwait(false);
                        }
                        return;
                    }
                }
                else if (char.IsAsciiLetter((char)first))
                {
                    isSocks = false;
                    try
                    {
                        (host, port) = await HttpConnectRequestAsync(stream, first, handshakeCts.Token).ConfigureAwait(false);
                    }
                    catch (HttpProtocolException ex)
                    {
                        ReportError("HttpConnectRequest", ex);
                        await TrySendHttpErrorAsync(stream, ex.StatusLine, _stop.Token).ConfigureAwait(false);
                        return;
                    }
                }
                else
                {
                    var ex = new InvalidDataException($"Unsupported proxy protocol lead byte 0x{first:X2}; only SOCKS5 (0x05) and HTTP CONNECT are supported.");
                    ReportError("Handshake", ex);
                    return;
                }

                targetHost = host;
                targetPort = port;

                TcpClient upstream;
                try
                {
                    using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
                    connectCts.CancelAfter(_connectTimeout);
                    upstream = await ConnectViaAdapterAsync(host, port, _adapter, connectCts.Token, StrictAdapterDns, _dnsTimeout).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (_stop.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    ReportError("UpstreamConnect", ex, host, port);
                    if (isSocks)
                    {
                        await TrySendSocksReplyAsync(stream, MapSocksReplyCode(ex), null, _stop.Token).ConfigureAwait(false);
                    }
                    else
                    {
                        string status = ex is OperationCanceledException or TimeoutException
                            ? "504 Gateway Timeout"
                            : "502 Bad Gateway";
                        await TrySendHttpErrorAsync(stream, status, _stop.Token).ConfigureAwait(false);
                    }
                    return;
                }

                using (upstream)
                using (var upstreamCloseReg = _stop.Token.Register(static s => ((TcpClient)s!).Dispose(), upstream))
                {
                    if (isSocks)
                    {
                        await SendSocksSuccessReplyAsync(stream, upstream.Client.LocalEndPoint as IPEndPoint, _stop.Token).ConfigureAwait(false);
                    }
                    else
                    {
                        await stream.WriteAsync("HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray(), _stop.Token).ConfigureAwait(false);
                    }

                    await CopyBothAsync(stream, upstream.GetStream(), client.Client, upstream.Client, _stop.Token).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested)
        {
        }
        catch (ObjectDisposedException) when (_stop.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            ReportError("Connection", ex, targetHost, targetPort);
        }
        finally
        {
            _activeConnections.TryRemove(connectionId, out _);
            _concurrencyGate.Release();
        }
    }

    private void ReportError(string stage, Exception exception, string? targetHost = null, int? targetPort = null)
    {
        var args = new ProxyErrorEventArgs(stage, exception, targetHost, targetPort);
        Trace.TraceWarning($"[AdapterBoundProxy:{stage}] {targetHost}:{targetPort} -> {exception.GetType().Name}: {exception.Message}");
        try
        {
            _onError?.Invoke(args);
        }
        catch (Exception callbackEx)
        {
            Trace.TraceError($"[AdapterBoundProxy] onError callback failed: {callbackEx}");
        }

        try
        {
            ErrorOccurred?.Invoke(this, args);
        }
        catch (Exception eventEx)
        {
            Trace.TraceError($"[AdapterBoundProxy] ErrorOccurred handler failed: {eventEx}");
        }
    }

    internal static (string Host, int Port) ParseConnectTarget(string target)
    {
        if (string.IsNullOrWhiteSpace(target))
        {
            throw new HttpProtocolException("400 Bad Request", "CONNECT target cannot be empty.");
        }

        string hostPart;
        string portPart;
        if (target[0] == '[')
        {
            int closeBracket = target.IndexOf(']');
            if (closeBracket <= 1 || closeBracket + 2 >= target.Length || target[closeBracket + 1] != ':')
            {
                throw new HttpProtocolException("400 Bad Request", "Invalid bracketed IPv6 CONNECT target.");
            }

            hostPart = target[1..closeBracket];
            portPart = target[(closeBracket + 2)..];
            if (hostPart.Contains('%')
                || !IPAddress.TryParse(hostPart, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetworkV6)
            {
                throw new HttpProtocolException("400 Bad Request", "Invalid IPv6 address in CONNECT target.");
            }
        }
        else
        {
            if (target.Contains('[') || target.Contains(']'))
            {
                throw new HttpProtocolException("400 Bad Request", "Invalid brackets in CONNECT target.");
            }

            int colon = target.IndexOf(':');
            if (colon <= 0 || colon != target.LastIndexOf(':'))
            {
                throw new HttpProtocolException("400 Bad Request", "Invalid host:port in CONNECT target.");
            }

            hostPart = target[..colon];
            portPart = target[(colon + 1)..];
            if (!IsValidHostToken(hostPart))
            {
                throw new HttpProtocolException("400 Bad Request", "Invalid host in CONNECT target.");
            }
        }

        if (!int.TryParse(portPart, NumberStyles.None, CultureInfo.InvariantCulture, out int port) || port is < 1 or > 65535)
        {
            throw new HttpProtocolException("400 Bad Request", "Invalid port in CONNECT target.");
        }

        return (hostPart, port);
    }

    private static async Task<(string Host, int Port)> HttpConnectRequestAsync(NetworkStream stream, int firstByte, CancellationToken ct)
    {
        HttpLineReadResult requestLineRead = await ReadHttpLineAsync(stream, MaxHttpLineBytes - 1, ct).ConfigureAwait(false);
        string requestLine = ((char)firstByte) + requestLineRead.Text;

        HttpProtocolException? requestError = requestLineRead.TooLong
            ? new HttpProtocolException("431 Request Header Fields Too Large", "HTTP request line exceeds the allowed limit.")
            : null;
        string host = string.Empty;
        int port = 0;
        if (requestError is null)
        {
            string[] parts = requestLine.Split(' ');
            if (parts.Length != 3
                || parts[2].Length != 8
                || !parts[2].StartsWith("HTTP/1.", StringComparison.Ordinal)
                || !char.IsAsciiDigit(parts[2][7]))
            {
                requestError = new HttpProtocolException("400 Bad Request", "Expected HTTP/1.x CONNECT request line.");
            }
            else if (!string.Equals(parts[0], "CONNECT", StringComparison.Ordinal))
            {
                requestError = new HttpProtocolException("405 Method Not Allowed", "Only HTTP CONNECT is supported.");
            }
            else
            {
                try
                {
                    (host, port) = ParseConnectTarget(parts[1]);
                }
                catch (HttpProtocolException ex)
                {
                    requestError = ex;
                }
            }
        }

        int headerCount = 0;
        int totalHeaderBytes = requestLineRead.ByteCount + 1;
        bool headersTooLarge = false;
        while (true)
        {
            HttpLineReadResult headerRead = await ReadHttpLineAsync(stream, MaxHttpLineBytes, ct).ConfigureAwait(false);
            totalHeaderBytes += headerRead.ByteCount + 2;
            if (headerRead.TooLong)
                headersTooLarge = true;
            if (!headerRead.TooLong && headerRead.Text.Length == 0)
            {
                break;
            }

            headerCount++;
            headersTooLarge |= headerCount > MaxHttpHeaderCount || totalHeaderBytes > MaxHttpTotalHeaderBytes;
        }

        if (headersTooLarge)
            throw new HttpProtocolException("431 Request Header Fields Too Large", "HTTP CONNECT headers exceed allowed limits.");
        if (requestError is not null)
            throw requestError;

        return (host, port);
    }

    private static async Task<HttpLineReadResult> ReadHttpLineAsync(NetworkStream stream, int maxBytes, CancellationToken ct)
    {
        var bytes = new List<byte>(128);
        byte[] one = new byte[1];
        int byteCount = 0;
        bool tooLong = false;
        while (true)
        {
            int n = await stream.ReadAsync(one.AsMemory(0, 1), ct).ConfigureAwait(false);
            if (n == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading HTTP CONNECT request.");
            }

            byte b = one[0];
            if (b == (byte)'\n')
            {
                return new HttpLineReadResult(Encoding.ASCII.GetString(bytes.ToArray()), byteCount, tooLong);
            }

            if (b == (byte)'\r')
            {
                continue;
            }

            if (b == 0)
            {
                throw new HttpProtocolException("400 Bad Request", "NUL byte is not allowed in HTTP request headers.");
            }

            byteCount++;
            if (byteCount > MaxHttpTotalHeaderBytes)
            {
                throw new HttpProtocolException("431 Request Header Fields Too Large", "HTTP line exceeds the total request header limit.");
            }

            if (bytes.Count < maxBytes)
                bytes.Add(b);
            else
                tooLong = true;
        }
    }

    private static async Task<(string Host, int Port)> SocksRequestAsync(NetworkStream stream, CancellationToken ct)
    {
        int nmethods = await ReadByteRequiredAsync(stream, ct).ConfigureAwait(false);
        if (nmethods < 1)
        {
            await TrySendSocksMethodReplyAsync(stream, 0xFF, ct).ConfigureAwait(false);
            throw new SocksProtocolException(0xFF, "SOCKS5 client offered zero authentication methods.", greetingFailed: true);
        }

        byte[] methods = await ReadExactBytesAsync(stream, nmethods, ct).ConfigureAwait(false);
        if (!methods.Contains((byte)0))
        {
            await TrySendSocksMethodReplyAsync(stream, 0xFF, ct).ConfigureAwait(false);
            throw new SocksProtocolException(0xFF, "SOCKS5 no-auth method (0x00) is required.", greetingFailed: true);
        }

        await stream.WriteAsync(new byte[] { 5, 0 }, ct).ConfigureAwait(false);

        byte[] header = await ReadExactBytesAsync(stream, 4, ct).ConfigureAwait(false);
        if (header[0] != 5)
        {
            throw new SocksProtocolException(0x01, $"Invalid SOCKS version {header[0]}.");
        }
        if (header[2] != 0)
        {
            throw new SocksProtocolException(0x01, $"Invalid SOCKS5 reserved byte 0x{header[2]:X2}.");
        }
        if (header[1] != 1)
        {
            throw new SocksProtocolException(0x07, $"Unsupported SOCKS5 command 0x{header[1]:X2}; only CONNECT (0x01) is supported.");
        }

        string host;
        switch (header[3])
        {
            case 1:
                host = new IPAddress(await ReadExactBytesAsync(stream, 4, ct).ConfigureAwait(false)).ToString();
                break;
            case 4:
                host = new IPAddress(await ReadExactBytesAsync(stream, 16, ct).ConfigureAwait(false)).ToString();
                break;
            case 3:
                int domainLength = await ReadByteRequiredAsync(stream, ct).ConfigureAwait(false);
                if (domainLength == 0)
                {
                    throw new SocksProtocolException(0x01, "SOCKS5 domain name length cannot be 0.");
                }
                byte[] domainBytes = await ReadExactBytesAsync(stream, domainLength, ct).ConfigureAwait(false);
                string domain = Encoding.ASCII.GetString(domainBytes);
                if (!IsValidHostToken(domain))
                {
                    throw new SocksProtocolException(0x01, "SOCKS5 domain name contains invalid characters.");
                }
                host = domain;
                break;
            default:
                throw new SocksProtocolException(0x08, $"Unsupported SOCKS5 address type 0x{header[3]:X2}.");
        }

        byte[] portBytes = await ReadExactBytesAsync(stream, 2, ct).ConfigureAwait(false);
        int port = BinaryPrimitives.ReadUInt16BigEndian(portBytes);
        if (port == 0)
        {
            throw new SocksProtocolException(0x01, "SOCKS5 target port cannot be 0.");
        }

        return (host, port);
    }

    private static bool IsValidHostToken(string host)
    {
        if (string.IsNullOrEmpty(host) || host.Length > 255)
        {
            return false;
        }

        foreach (char c in host)
        {
            if (c <= 0x20 || c >= 0x7F || c is '%' or '/' or '\\' or '@' or '?')
            {
                return false;
            }
        }

        return true;
    }

    private static async Task<int> ReadByteOrEofAsync(NetworkStream stream, CancellationToken ct)
    {
        byte[] one = new byte[1];
        int read = await stream.ReadAsync(one.AsMemory(0, 1), ct).ConfigureAwait(false);
        return read == 0 ? -1 : one[0];
    }

    private static async Task<int> ReadByteRequiredAsync(NetworkStream stream, CancellationToken ct)
    {
        int value = await ReadByteOrEofAsync(stream, ct).ConfigureAwait(false);
        if (value < 0)
        {
            throw new EndOfStreamException("Unexpected EOF while reading SOCKS5 frame.");
        }
        return value;
    }

    private static async Task<byte[]> ReadExactBytesAsync(NetworkStream stream, int count, CancellationToken ct)
    {
        byte[] buffer = new byte[count];
        await stream.ReadExactlyAsync(buffer, ct).ConfigureAwait(false);
        return buffer;
    }

    private static async Task TrySendHttpErrorAsync(NetworkStream stream, string statusLine, CancellationToken ct)
    {
        try
        {
            byte[] payload = Encoding.ASCII.GetBytes($"HTTP/1.1 {statusLine}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
            await stream.WriteAsync(payload, ct).ConfigureAwait(false);
        }
        catch
        {
        }
    }

    private static async Task TrySendSocksMethodReplyAsync(NetworkStream stream, byte method, CancellationToken ct)
    {
        try
        {
            await stream.WriteAsync(new byte[] { 5, method }, ct).ConfigureAwait(false);
        }
        catch
        {
        }
    }

    private static Task SendSocksSuccessReplyAsync(NetworkStream stream, IPEndPoint? boundEndpoint, CancellationToken ct)
    {
        byte[] reply = new byte[10];
        reply[0] = 5;
        reply[1] = 0;
        reply[2] = 0;
        reply[3] = 1;
        if (boundEndpoint is not null && boundEndpoint.AddressFamily == AddressFamily.InterNetwork)
        {
            boundEndpoint.Address.TryWriteBytes(reply.AsSpan(4, 4), out _);
            BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(8, 2), checked((ushort)boundEndpoint.Port));
        }
        return stream.WriteAsync(reply, ct).AsTask();
    }

    private static async Task TrySendSocksReplyAsync(NetworkStream stream, byte replyCode, IPEndPoint? boundEndpoint, CancellationToken ct)
    {
        try
        {
            byte[] reply = new byte[10];
            reply[0] = 5;
            reply[1] = replyCode;
            reply[2] = 0;
            reply[3] = 1;
            if (boundEndpoint is not null && boundEndpoint.AddressFamily == AddressFamily.InterNetwork)
            {
                boundEndpoint.Address.TryWriteBytes(reply.AsSpan(4, 4), out _);
                BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(8, 2), checked((ushort)boundEndpoint.Port));
            }
            await stream.WriteAsync(reply, ct).ConfigureAwait(false);
        }
        catch
        {
        }
    }

    private static byte MapSocksReplyCode(Exception ex)
    {
        SocketException? sockEx = ex as SocketException ?? ex.InnerException as SocketException;
        if (sockEx is null && ex.InnerException is AggregateException agg)
        {
            sockEx = agg.InnerExceptions.OfType<SocketException>().FirstOrDefault();
        }

        return sockEx?.SocketErrorCode switch
        {
            SocketError.ConnectionRefused => 0x05,
            SocketError.NetworkUnreachable => 0x03,
            SocketError.HostUnreachable or SocketError.HostNotFound or SocketError.TryAgain => 0x04,
            _ => 0x01
        };
    }

    private static async Task CopyBothAsync(
        NetworkStream clientStream,
        NetworkStream upstreamStream,
        Socket clientSocket,
        Socket upstreamSocket,
        CancellationToken ct)
    {
        using var relayCts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        Task c2u = PumpDirectionAsync(clientStream, upstreamStream, upstreamSocket, relayCts, ct);
        Task u2c = PumpDirectionAsync(upstreamStream, clientStream, clientSocket, relayCts, ct);

        await Task.WhenAll(c2u, u2c).ConfigureAwait(false);
    }

    private static async Task PumpDirectionAsync(
        NetworkStream source,
        NetworkStream destination,
        Socket destinationSocket,
        CancellationTokenSource relayCts,
        CancellationToken outerCt)
    {
        try
        {
            await source.CopyToAsync(destination, relayCts.Token).ConfigureAwait(false);
            try
            {
                destinationSocket.Shutdown(SocketShutdown.Send);
            }
            catch (SocketException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
        }
        catch (OperationCanceledException) when (relayCts.IsCancellationRequested && !outerCt.IsCancellationRequested)
        {
            // Peer direction faulted and cancelled the relay; the peer task surfaces the exception.
        }
        catch (Exception) when (!outerCt.IsCancellationRequested)
        {
            relayCts.Cancel();
            throw;
        }
    }

    /// <summary>Opens an adapter-bound TCP connection using strict no-fallback adapter DNS by default.</summary>
    public static Task<TcpClient> ConnectViaAdapterAsync(string host, int port, AdapterInfo adapter, CancellationToken ct)
        => ConnectViaAdapterAsync(host, port, adapter, ct, strictAdapterDns: true, dnsTimeout: null);

    /// <summary>Opens an adapter-bound TCP connection, optionally controlling strict no-fallback DNS and DNS timeout.</summary>
    public static async Task<TcpClient> ConnectViaAdapterAsync(
        string host,
        int port,
        AdapterInfo adapter,
        CancellationToken ct,
        bool strictAdapterDns,
        TimeSpan? dnsTimeout = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentNullException.ThrowIfNull(adapter);
        if (port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port), port, "Port must be between 1 and 65535.");
        }
        ct.ThrowIfCancellationRequested();

        if (!adapter.IsUpAndRoutable)
        {
            throw new IOException(
                $"Adapter '{adapter.FriendlyName}' is disconnected or not routable.",
                new InvalidOperationException($"Adapter '{adapter.FriendlyName}' is disconnected or not routable."));
        }

        IPAddress[] ips;
        if (IPAddress.TryParse(host, out var ip))
        {
            if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any))
            {
                throw new IOException($"Refusing connection to unspecified target address '{host}'.");
            }

            if (ip.AddressFamily == AddressFamily.InterNetworkV6 && ip.ScopeId != 0 && ip.ScopeId != adapter.InterfaceIndex)
            {
                throw new IOException($"Target IPv6 scope ID {ip.ScopeId} does not match adapter '{adapter.FriendlyName}' interface index {adapter.InterfaceIndex}.");
            }

            if (ip.AddressFamily == AddressFamily.InterNetworkV6 && ip.IsIPv6LinkLocal && ip.ScopeId == 0)
            {
                ip = new IPAddress(ip.GetAddressBytes(), adapter.InterfaceIndex);
            }

            ips = [ip];
        }
        else
        {
            ips = await ResolveAsync(host, adapter, strictAdapterDns, dnsTimeout ?? DefaultDnsTimeout, ct).ConfigureAwait(false);
        }

        var failures = new List<Exception>();
        foreach (var addr in ips)
        {
            ct.ThrowIfCancellationRequested();
            var client = new TcpClient(addr.AddressFamily);
            try
            {
                SocketNative.BindSocketToAdapter(client.Client, adapter, addr.AddressFamily);
                await client.ConnectAsync(addr, port, ct).ConfigureAwait(false);
                return client;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                client.Dispose();
                throw;
            }
            catch (Exception ex)
            {
                failures.Add(ex);
                client.Dispose();
            }
        }

        Exception? inner = failures.Count switch
        {
            0 => null,
            1 => failures[0],
            _ => new AggregateException(failures)
        };
        throw new IOException($"Could not connect to {host}:{port} through adapter '{adapter.FriendlyName}'.", inner);
    }

    private static async Task<IPAddress[]> ResolveAsync(
        string host,
        AdapterInfo adapter,
        bool strict,
        TimeSpan dnsTimeout,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (adapter.DnsServers.Count == 0)
        {
            if (strict)
            {
                throw new InvalidOperationException($"Adapter '{adapter.FriendlyName}' has no DNS servers; strict adapter DNS will not use the system resolver.");
            }

            return await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
        }

        bool hasV4 = SocketNative.SelectBindAddress(adapter, AddressFamily.InterNetwork) is not null;
        bool hasV6 = SocketNative.SelectBindAddress(adapter, AddressFamily.InterNetworkV6) is not null;
        if (!hasV4 && !hasV6)
        {
            throw new InvalidOperationException($"Adapter '{adapter.FriendlyName}' has no usable IPv4 or IPv6 address for adapter-bound DNS.");
        }

        var queryTypes = new List<ushort>(2);
        if (hasV4) queryTypes.Add(1);
        if (hasV6) queryTypes.Add(28);

        var errors = new List<Exception>();
        foreach (var server in adapter.DnsServers)
        {
            ct.ThrowIfCancellationRequested();

            if (server.Equals(IPAddress.Any) || server.Equals(IPAddress.IPv6Any) || (!adapter.IsLoopback && IPAddress.IsLoopback(server)))
            {
                errors.Add(new InvalidOperationException($"Skipping unusable DNS server '{server}' for adapter '{adapter.FriendlyName}'."));
                continue;
            }

            var resolved = new List<IPAddress>();
            foreach (ushort qtype in queryTypes)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    ushort txId = DnsWire.CreateTransactionId();
                    byte[] query = DnsWire.BuildQuery(host, qtype, txId);

                    using var udp = new UdpClient(server.AddressFamily);
                    SocketNative.BindSocketToAdapter(udp.Client, adapter, server.AddressFamily);

                    using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeoutCts.CancelAfter(dnsTimeout);

                    await udp.SendAsync(query, new IPEndPoint(server, 53), timeoutCts.Token).ConfigureAwait(false);

                    while (true)
                    {
                        var response = await udp.ReceiveAsync(timeoutCts.Token).ConfigureAwait(false);
                        if (!response.RemoteEndPoint.Address.Equals(server) || response.RemoteEndPoint.Port != 53)
                        {
                            continue;
                        }

                        if (!DnsWire.TryParseResponse(response.Buffer, txId, qtype, out var parsed, out int rcode))
                        {
                            continue;
                        }

                        if (rcode != 0)
                        {
                            errors.Add(new IOException($"DNS server {server} returned RCODE {rcode} for '{host}' (type {qtype})."));
                            break;
                        }

                        foreach (var ip in parsed)
                        {
                            if (!resolved.Contains(ip))
                            {
                                resolved.Add(ip);
                            }
                        }
                        break;
                    }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (OperationCanceledException)
                {
                    errors.Add(new TimeoutException($"Adapter-bound DNS query to {server} for '{host}' (type {qtype}) timed out after {dnsTimeout.TotalMilliseconds:F0} ms."));
                }
                catch (Exception ex)
                {
                    errors.Add(ex);
                }
            }

            if (resolved.Count > 0)
            {
                return resolved.ToArray();
            }
        }

        if (strict)
        {
            Exception? inner = errors.Count switch
            {
                0 => null,
                1 => errors[0],
                _ => new AggregateException(errors)
            };
            throw new IOException($"Adapter-bound DNS resolution for '{host}' failed on adapter '{adapter.FriendlyName}'; system DNS fallback is disabled.", inner);
        }

        return await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            _stop.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }

        _listener.Stop();

        try
        {
            await _acceptLoop.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
        catch (Exception ex)
        {
            ReportError("DisposeAcceptLoop", ex);
        }

        Task[] remaining = _activeConnections.Values.ToArray();
        if (remaining.Length > 0)
        {
            try
            {
                await Task.WhenAll(remaining).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            catch (TimeoutException ex)
            {
                ReportError("DisposeDrain", ex);
            }
        }

        _stop.Dispose();
        _concurrencyGate.Dispose();
    }

    private sealed class HttpProtocolException : IOException
    {
        public HttpProtocolException(string statusLine, string message) : base(message)
        {
            StatusLine = statusLine;
        }

        public string StatusLine { get; }
    }

    private readonly record struct HttpLineReadResult(string Text, int ByteCount, bool TooLong);

    private sealed class SocksProtocolException : IOException
    {
        public SocksProtocolException(byte replyCode, string message, bool greetingFailed = false) : base(message)
        {
            ReplyCode = replyCode;
            GreetingFailed = greetingFailed;
        }

        public byte ReplyCode { get; }
        public bool GreetingFailed { get; }
    }
}

/// <summary>Small RFC 1035 A/AAAA query encoder and response parser.</summary>
public static class DnsWire
{
    internal static ushort CreateTransactionId()
    {
        Span<byte> bytes = stackalloc byte[2];
        RandomNumberGenerator.Fill(bytes);
        return BinaryPrimitives.ReadUInt16BigEndian(bytes);
    }

    public static byte[] BuildQuery(string name, ushort type)
        => BuildQuery(name, type, CreateTransactionId());

    public static byte[] BuildQuery(string name, ushort type, ushort transactionId)
    {
        if (type is not (1 or 28))
        {
            throw new ArgumentOutOfRangeException(nameof(type), type, "Only DNS query types A (1) and AAAA (28) are supported.");
        }
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("DNS name cannot be empty.", nameof(name));
        }

        string trimmed = name.TrimEnd('.');
        if (trimmed.Length == 0)
        {
            throw new ArgumentException("DNS name cannot be root-only.", nameof(name));
        }

        string[] labels = trimmed.Split('.');
        using var m = new MemoryStream(64);
        Span<byte> header = stackalloc byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(header[..2], transactionId);
        header[2] = 0x01; // RD=1
        header[5] = 0x01; // QDCOUNT=1
        m.Write(header);

        int qnameLength = 1; // trailing zero label
        foreach (string label in labels)
        {
            byte[] labelBytes = Encoding.ASCII.GetBytes(label);
            if (labelBytes.Length is 0 or > 63)
            {
                throw new ArgumentException("Invalid DNS label.", nameof(name));
            }
            foreach (byte b in labelBytes)
            {
                if (b <= 0x20 || b >= 0x7F)
                {
                    throw new ArgumentException("DNS label contains invalid characters.", nameof(name));
                }
            }

            qnameLength += 1 + labelBytes.Length;
            if (qnameLength > 255)
            {
                throw new ArgumentException("DNS name exceeds RFC 1035 255-byte wire limit.", nameof(name));
            }

            m.WriteByte((byte)labelBytes.Length);
            m.Write(labelBytes);
        }

        m.WriteByte(0);
        Span<byte> questionTail = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(questionTail[..2], type);
        BinaryPrimitives.WriteUInt16BigEndian(questionTail[2..], 1); // IN
        m.Write(questionTail);
        return m.ToArray();
    }

    public static IPAddress[] ParseResponse(byte[] packet)
        => TryParseResponse(packet, expectedTransactionId: null, expectedType: null, out var addresses, out _)
            ? addresses
            : [];

    public static IPAddress[] ParseResponse(byte[] packet, ushort expectedTransactionId, ushort? expectedType = null)
        => TryParseResponse(packet, expectedTransactionId, expectedType, out var addresses, out _)
            ? addresses
            : [];

    /// <summary>
    /// Parses a DNS response packet, returning <c>false</c> when malformed or when <paramref name="expectedTransactionId"/> does not match.
    /// </summary>
    public static bool TryParseResponse(
        ReadOnlySpan<byte> packet,
        ushort? expectedTransactionId,
        ushort? expectedType,
        out IPAddress[] addresses,
        out int rcode)
    {
        addresses = [];
        rcode = 0;

        if (packet.Length < 12)
        {
            return false;
        }

        ushort txId = BinaryPrimitives.ReadUInt16BigEndian(packet[..2]);
        if (expectedTransactionId.HasValue && txId != expectedTransactionId.Value)
        {
            return false;
        }

        if ((packet[2] & 0x80) == 0)
        {
            return false;
        }

        rcode = packet[3] & 0x0F;
        if (rcode != 0)
        {
            return true;
        }

        int qd = BinaryPrimitives.ReadUInt16BigEndian(packet[4..6]);
        int an = BinaryPrimitives.ReadUInt16BigEndian(packet[6..8]);
        if (qd > 64 || an > 256)
        {
            return false;
        }

        int p = 12;
        for (int i = 0; i < qd; i++)
        {
            if (!TrySkipName(packet, ref p) || p + 4 > packet.Length)
            {
                return false;
            }
            p += 4;
        }

        var result = new List<IPAddress>();
        for (int i = 0; i < an; i++)
        {
            if (!TrySkipName(packet, ref p) || p + 10 > packet.Length)
            {
                return false;
            }

            ushort rrType = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(p, 2));
            ushort rrClass = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(p + 2, 2));
            ushort rdLength = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(p + 8, 2));
            p += 10;

            if (p + rdLength > packet.Length)
            {
                return false;
            }

            if (rrClass == 1
                && ((rrType == 1 && rdLength == 4) || (rrType == 28 && rdLength == 16))
                && (!expectedType.HasValue || rrType == expectedType.Value))
            {
                result.Add(new IPAddress(packet.Slice(p, rdLength)));
            }

            p += rdLength;
        }

        addresses = result.ToArray();
        return true;
    }

    private static bool TrySkipName(ReadOnlySpan<byte> packet, ref int offset)
    {
        int totalLength = 0;
        while (offset < packet.Length)
        {
            byte len = packet[offset++];
            if (len == 0)
            {
                return true;
            }

            int tag = len & 0xC0;
            if (tag == 0xC0)
            {
                if (offset >= packet.Length)
                {
                    return false;
                }
                offset++;
                return true;
            }

            if (tag != 0)
            {
                return false;
            }

            totalLength += 1 + len;
            if (totalLength > 255 || offset + len > packet.Length)
            {
                return false;
            }

            offset += len;
        }

        return false;
    }
}
