using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using NetworkIsolation.Core;

namespace NetworkIsolation.Wfp.Native;

/// <summary>
/// Windows socket options for cooperating-socket interface steering (<c>IP_UNICAST_IF</c> / <c>IPV6_UNICAST_IF</c> + local IP bind).
/// </summary>
/// <remarks>
/// These helpers steer sockets owned by a cooperating process (such as <see cref="AdapterBoundProxy"/>).
/// They do not enforce isolation on arbitrary unmodified third-party applications; system-wide fail-closed
/// enforcement requires WFP filters (and an optional kernel callout for transparent redirection).
/// </remarks>
public static class SocketNative
{
    public const int IPPROTO_IP = 0;
    public const int IP_UNICAST_IF = 31;
    public const int IPPROTO_IPV6 = 41;
    public const int IPV6_UNICAST_IF = 31;

    [DllImport("ws2_32.dll", SetLastError = true, ExactSpelling = true, EntryPoint = "setsockopt")]
    private static extern int SetSocketOption(SafeSocketHandle socket, int level, int optionName, ref int optionValue, int optionLength);

    /// <summary>
    /// Computes the Winsock level, option name, and byte-ordered option value for <c>IP_UNICAST_IF</c> or <c>IPV6_UNICAST_IF</c>.
    /// </summary>
    /// <remarks>
    /// Windows requires <c>IP_UNICAST_IF</c> in network byte order (big-endian) and <c>IPV6_UNICAST_IF</c> in host byte order.
    /// </remarks>
    internal static (int Level, int OptionName, int OptionValue) BuildUnicastInterfaceOption(uint interfaceIndex, AddressFamily family)
    {
        if (interfaceIndex == 0 || interfaceIndex > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(interfaceIndex), interfaceIndex, "Interface index must be between 1 and Int32.MaxValue.");
        }

        return family switch
        {
            AddressFamily.InterNetwork => (IPPROTO_IP, IP_UNICAST_IF, IPAddress.HostToNetworkOrder(unchecked((int)interfaceIndex))),
            AddressFamily.InterNetworkV6 => (IPPROTO_IPV6, IPV6_UNICAST_IF, unchecked((int)interfaceIndex)),
            _ => throw new ArgumentException("Only IPv4 and IPv6 sockets can be interface-bound.", nameof(family))
        };
    }

    /// <summary>Sets <c>IP_UNICAST_IF</c> or <c>IPV6_UNICAST_IF</c> on a cooperating socket.</summary>
    public static void SetUnicastInterface(Socket socket, uint interfaceIndex, AddressFamily family)
    {
        ArgumentNullException.ThrowIfNull(socket);

        SafeSocketHandle handle = socket.SafeHandle;
        if (handle.IsInvalid || handle.IsClosed)
        {
            throw new ObjectDisposedException(nameof(Socket));
        }

        bool compatible = socket.AddressFamily == family
            || (family == AddressFamily.InterNetwork && socket.AddressFamily == AddressFamily.InterNetworkV6 && socket.DualMode);
        if (!compatible)
        {
            throw new ArgumentException($"Socket address family {socket.AddressFamily} is incompatible with {family}.", nameof(family));
        }

        var (level, option, value) = BuildUnicastInterfaceOption(interfaceIndex, family);

        bool added = false;
        try
        {
            handle.DangerousAddRef(ref added);
            if (SetSocketOption(handle, level, option, ref value, sizeof(int)) != 0)
            {
                throw new SocketException(Marshal.GetLastPInvokeError());
            }
        }
        finally
        {
            if (added)
            {
                handle.DangerousRelease();
            }
        }
    }

    /// <summary>Selects a usable local bind address on <paramref name="adapter"/> for <paramref name="targetFamily"/>.</summary>
    internal static IPAddress? SelectBindAddress(AdapterInfo adapter, AddressFamily targetFamily)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        var addresses = targetFamily switch
        {
            AddressFamily.InterNetwork => adapter.IPv4Addresses,
            AddressFamily.InterNetworkV6 => adapter.IPv6Addresses,
            _ => throw new ArgumentException("Only IPv4 and IPv6 are supported.", nameof(targetFamily))
        };

        IPAddress? linkLocalFallback = null;
        foreach (var addr in addresses)
        {
            if (addr is null || addr.AddressFamily != targetFamily)
            {
                continue;
            }

            if (addr.Equals(IPAddress.Any) || addr.Equals(IPAddress.IPv6Any) || addr.Equals(IPAddress.None))
            {
                continue;
            }

            if (targetFamily == AddressFamily.InterNetworkV6 && addr.IsIPv6Multicast)
            {
                continue;
            }

            if (!adapter.IsLoopback && IPAddress.IsLoopback(addr))
            {
                continue;
            }

            if (IsLinkLocal(addr))
            {
                linkLocalFallback ??= NormalizeBindAddress(addr, adapter.InterfaceIndex);
                continue;
            }

            return NormalizeBindAddress(addr, adapter.InterfaceIndex);
        }

        return linkLocalFallback;
    }

    /// <summary>Binds a cooperating socket to the adapter's interface index and local source IP.</summary>
    public static void BindSocketToAdapter(Socket socket, AdapterInfo adapter, AddressFamily targetFamily)
    {
        ArgumentNullException.ThrowIfNull(socket);
        ArgumentNullException.ThrowIfNull(adapter);

        if (!adapter.IsUpAndRoutable)
        {
            throw new InvalidOperationException($"Adapter '{adapter.FriendlyName}' is disconnected or not routable.");
        }

        var local = SelectBindAddress(adapter, targetFamily)
            ?? throw new InvalidOperationException($"Adapter '{adapter.FriendlyName}' has no usable {targetFamily} address; refusing an unbound connection.");

        SetUnicastInterface(socket, adapter.InterfaceIndex, targetFamily);
        socket.Bind(new IPEndPoint(local, 0));
    }

    private static bool IsLinkLocal(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return address.IsIPv6LinkLocal;
        }

        Span<byte> bytes = stackalloc byte[4];
        return address.TryWriteBytes(bytes, out int written) && written == 4 && bytes[0] == 169 && bytes[1] == 254;
    }

    private static IPAddress NormalizeBindAddress(IPAddress address, uint interfaceIndex)
    {
        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.IsIPv6LinkLocal && address.ScopeId == 0)
        {
            Span<byte> bytes = stackalloc byte[16];
            if (address.TryWriteBytes(bytes, out int written) && written == 16)
            {
                return new IPAddress(bytes, interfaceIndex);
            }
        }

        return address;
    }
}
