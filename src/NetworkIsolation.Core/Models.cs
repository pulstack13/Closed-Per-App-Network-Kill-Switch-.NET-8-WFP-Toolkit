using System.Net;

namespace NetworkIsolation.Core;

/// <summary>How an application is assigned to network interfaces.</summary>
public enum PolicyMode { Unassigned, Bind, AllowMultiple, BlockAll }
/// <summary>Application identity supported by the policy engine.</summary>
public enum AppIdentityKind { Executable, UwpPackage }
/// <summary>WFP filter action.</summary>
public enum FilterAction { Permit, Block }
/// <summary>WFP enforcement layers used by the engine.</summary>
public enum WfpLayer { AleAuthConnectV4, AleAuthConnectV6, AleAuthRecvAcceptV4, AleAuthRecvAcceptV6, OutboundTransportV4, OutboundTransportV6 }

/// <summary>Runtime details for a network adapter, keyed by its stable NET_LUID.</summary>
public sealed record AdapterInfo(
    ulong NetLuid, Guid InterfaceGuid, uint InterfaceIndex, string FriendlyName, string Description,
    uint InterfaceType, string OperStatus, IReadOnlyList<IPAddress> IPv4Addresses,
    IReadOnlyList<IPAddress> IPv6Addresses, IReadOnlyList<IPAddress> DnsServers,
    uint IPv4Metric, uint IPv6Metric, bool IsLoopback, bool IsUpAndRoutable,
    IPAddress? AdapterGateway = null, ulong LinkSpeedBps = 0);

/// <summary>A canonical executable path or package family name.</summary>
public sealed record AppIdentity(AppIdentityKind Kind, string Value)
{
    /// <summary>Creates an identity for an executable file.</summary>
    public static AppIdentity Executable(string path) => new(AppIdentityKind.Executable, Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar).ToUpperInvariant());
    /// <summary>Creates an identity for a packaged application.</summary>
    public static AppIdentity UwpPackage(string familyName) => new(AppIdentityKind.UwpPackage, familyName.Trim());
}

/// <summary>Optional behavior for an application policy.</summary>
public sealed record PolicyOptions(bool AllowLoopback = true, bool TerminateOnDisconnect = false, bool NotifyOnBlock = true, bool InheritChildProcesses = false);
/// <summary>Desired application network policy.</summary>
public sealed record NetworkPolicy(AppIdentity App, PolicyMode Mode, IReadOnlyList<ulong> AllowedLuid, PolicyOptions Options);
/// <summary>One compiled WFP filter request.</summary>
public sealed record FilterSpec(WfpLayer Layer, FilterAction Action, ulong Weight, string Purpose, ulong? InterfaceLuid = null, string? RemoteAddress = null);

/// <summary>Stable identifiers owned by this product's WFP provider.</summary>
public static class NetworkIsolationConstants
{
    /// <summary>Private provider GUID.</summary>
    public static readonly Guid ProviderGuid = new("4D2F7221-356C-4B50-AB5E-843E97F56D38");
    /// <summary>Private sublayer GUID.</summary>
    public static readonly Guid SubLayerGuid = new("A0140AE1-BB89-42BD-A8FC-70FF7B6A4E02");
}

/// <summary>Prevents policies from disabling critical Windows processes accidentally.</summary>
public static class ProtectedProcessGuard
{
    private static readonly HashSet<string> Protected = new(StringComparer.OrdinalIgnoreCase) { "csrss.exe", "wininit.exe", "lsass.exe", "services.exe", "smss.exe", "TrustedInstaller.exe", "MsMpEng.exe" };
    /// <summary>Returns true for a protected system executable.</summary>
    public static bool IsProtected(string executable) => Protected.Contains(Path.GetFileName(executable));
    /// <summary>Returns true when binding shared svchost.exe needs an explicit warning.</summary>
    public static bool RequiresSharedHostWarning(string executable) => string.Equals(Path.GetFileName(executable), "svchost.exe", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Compiles desired policies into fail-closed filter plans.</summary>
public static class WfpPlanCompiler
{
    private static readonly (WfpLayer Layer, bool V4)[] Layers =
    [
        (WfpLayer.AleAuthConnectV4, true), (WfpLayer.AleAuthConnectV6, false),
        (WfpLayer.AleAuthRecvAcceptV4, true), (WfpLayer.AleAuthRecvAcceptV6, false),
        (WfpLayer.OutboundTransportV4, true), (WfpLayer.OutboundTransportV6, false)
    ];

    /// <summary>Creates loopback, allowed-interface, and base-block filters.</summary>
    public static IReadOnlyList<FilterSpec> Compile(NetworkPolicy policy, IReadOnlyCollection<AdapterInfo> adapters)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (policy.Mode == PolicyMode.Unassigned) return [];
        var filters = new List<FilterSpec>();
        foreach (var (layer, v4) in Layers)
        {
            if (policy.Options.AllowLoopback)
                filters.Add(new(layer, FilterAction.Permit, 15, "Loopback exemption", RemoteAddress: v4 ? "127.0.0.0/8" : "::1/128"));
            if (policy.Mode is PolicyMode.Bind or PolicyMode.AllowMultiple)
            {
                foreach (var luid in policy.AllowedLuid.Distinct())
                {
                    var adapter = adapters.FirstOrDefault(a => a.NetLuid == luid);
                    if (adapter is null || !adapter.IsUpAndRoutable || (v4 ? adapter.IPv4Addresses.Count == 0 : adapter.IPv6Addresses.Count == 0)) continue;
                    filters.Add(new(layer, FilterAction.Permit, 10, $"Allow {policy.App.Value}", luid));
                }
            }
            filters.Add(new(layer, FilterAction.Block, 1, $"Base block {policy.App.Value}"));
        }
        return filters;
    }

    /// <summary>Returns a warning for protected or shared Windows processes.</summary>
    public static string? BuildProtectedWarning(AppIdentity app)
    {
        if (app.Kind != AppIdentityKind.Executable) return null;
        if (ProtectedProcessGuard.IsProtected(app.Value)) return $"{Path.GetFileName(app.Value)} is a protected Windows process; managing it can disrupt the operating system.";
        if (ProtectedProcessGuard.RequiresSharedHostWarning(app.Value)) return "svchost.exe hosts shared Windows services; a policy may affect unrelated system networking.";
        return null;
    }
}
