using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using NetworkIsolation.Core;
using NetworkIsolation.Wfp.Native;

namespace NetworkIsolation.Wfp;

/// <summary>Metadata describing an active WFP filter inside this product's private sublayer.</summary>
public sealed record ActiveWfpFilterInfo(ulong FilterId, string Name, string Description)
{
    /// <summary>WFP layer GUID where the filter is installed.</summary>
    public Guid LayerKey { get; init; }

    /// <summary>Native WFP action constant (e.g. <c>FWP_ACTION_PERMIT</c> or <c>FWP_ACTION_BLOCK</c>).</summary>
    public uint ActionType { get; init; }

    /// <summary>Filter weight or effective weight reported by BFE.</summary>
    public ulong Weight { get; init; }

    /// <summary>Optional UTF-8 provider tag associated with the filter.</summary>
    public string? AppTag { get; init; }
}

/// <summary>
/// Transactional WFP manager for fail-closed per-application interface allowlisting and blocking.
/// User-mode WFP filters enforce fail-closed blocking on disallowed interfaces; they do not perform
/// arbitrary socket route steering.
/// </summary>
public sealed class WfpEngineManager : IDisposable
{
    private const ushort SublayerWeight = 0x8000;
    private const uint TransactionWaitTimeoutMs = 5000;
    private const uint EnumBatchSize = 128;

    private static readonly (WfpLayer Layer, Guid Guid, bool IsV4)[] SupportedAleLayerDescriptors =
    [
        (WfpLayer.AleAuthConnectV4, WfpNative.LayerAleAuthConnectV4, true),
        (WfpLayer.AleAuthConnectV6, WfpNative.LayerAleAuthConnectV6, false),
        (WfpLayer.AleAuthRecvAcceptV4, WfpNative.LayerAleAuthRecvAcceptV4, true),
        (WfpLayer.AleAuthRecvAcceptV6, WfpNative.LayerAleAuthRecvAcceptV6, false)
    ];

    private readonly bool _dynamicSession;
    private readonly object _sync = new();
    private nint _engineHandle;
    private int _disposed;

    /// <summary>
    /// Creates a new WFP engine manager.
    /// Defaults to persistent fail-closed objects (<paramref name="dynamicSession"/> = <see langword="false"/>)
    /// so filters survive process crashes and reboots until explicitly removed.
    /// </summary>
    public WfpEngineManager(bool dynamicSession = false)
    {
        _dynamicSession = dynamicSession;
    }

    /// <summary>True when running with an ephemeral <c>FWPM_SESSION_FLAG_DYNAMIC</c> session.</summary>
    public bool IsDynamicSession => _dynamicSession;

    /// <summary>True when running in persistent fail-closed mode.</summary>
    public bool IsPersistent => !_dynamicSession;

    /// <summary>ALE layers supported for user-mode per-application enforcement.</summary>
    public static IReadOnlyList<WfpLayer> SupportedLayers { get; } =
    [
        WfpLayer.AleAuthConnectV4,
        WfpLayer.AleAuthConnectV6,
        WfpLayer.AleAuthRecvAcceptV4,
        WfpLayer.AleAuthRecvAcceptV6
    ];

    /// <summary>Returns true when the current process has local Administrator privileges.</summary>
    public static bool IsAdministrator() =>
        OperatingSystem.IsWindows() &&
        new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    /// <summary>Returns true if <paramref name="layer"/> supports <c>FWPM_CONDITION_ALE_APP_ID</c> in user-mode WFP.</summary>
    public static bool IsSupportedLayer(WfpLayer layer) =>
        layer is WfpLayer.AleAuthConnectV4 or WfpLayer.AleAuthConnectV6
            or WfpLayer.AleAuthRecvAcceptV4 or WfpLayer.AleAuthRecvAcceptV6;

    /// <summary>Returns true if <paramref name="app"/> uses an application identity supported by this engine.</summary>
    public static bool IsSupportedIdentity(AppIdentity app)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.Kind == AppIdentityKind.Executable && !string.IsNullOrWhiteSpace(app.Value);
    }

    /// <summary>
    /// Atomically installs or replaces fail-closed WFP filters for <paramref name="policy"/> across supported ALE layers.
    /// Rejects unsupported identities, unsupported layers, and unscoped/global filter specifications.
    /// </summary>
    public void ApplyPolicy(NetworkPolicy policy, IReadOnlyCollection<AdapterInfo> adapters)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(adapters);

        string canonicalExePath = ValidateAndNormalizeExecutableIdentity(policy.App);
        if (!Enum.IsDefined(policy.Mode))
            throw new ArgumentOutOfRangeException(nameof(policy), $"Unknown policy mode '{policy.Mode}'.");

        if (policy.Mode == PolicyMode.Unassigned)
        {
            RemoveAppPolicy(policy.App);
            return;
        }

        if (!File.Exists(canonicalExePath))
            throw new FileNotFoundException($"Target executable '{canonicalExePath}' does not exist; cannot resolve WFP ALE_APP_ID.", canonicalExePath);

        IReadOnlyList<FilterSpec> specs = BuildAleFilterPlan(policy, adapters);
        if (specs.Count == 0)
            throw new InvalidOperationException("Refusing to apply an empty filter plan without a fail-closed base block.");

        EnsureWindowsPlatform();

        byte[] appTagBytes = BuildAppTagBytes(canonicalExePath);

        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);

            nint appIdBlobPtr = 0;
            try
            {
                uint appIdStatus = WfpNative.FwpmGetAppIdFromFileName0(canonicalExePath, out appIdBlobPtr);
                ThrowIfWfpError(appIdStatus, $"FwpmGetAppIdFromFileName0({canonicalExePath})");

                byte[] appIdBytes = ReadBlobBytes(appIdBlobPtr);
                if (appIdBytes.Length == 0)
                    throw new InvalidOperationException($"FwpmGetAppIdFromFileName0 returned an empty application ID blob for '{canonicalExePath}'.");

                EnsureEngineOpenLocked();
                EnsureSublayerExistsOrCreateViaTxLocked();

                ExecuteTransactionLocked(() =>
                {
                    IReadOnlyList<ulong> existingFilterIds = FindMatchingAppFilterIdsLocked(appIdBytes, appTagBytes);

                    // Install new rules (including base BLOCK) before deleting old rules inside the same atomic transaction.
                    foreach (FilterSpec spec in specs)
                        AddScopedFilterLocked(spec, canonicalExePath, appIdBlobPtr, appTagBytes);

                    foreach (ulong oldFilterId in existingFilterIds)
                    {
                        uint delStatus = WfpNative.FwpmFilterDeleteById0(_engineHandle, oldFilterId);
                        if (delStatus != WfpNative.ERROR_SUCCESS && delStatus != WfpNative.FWP_E_FILTER_NOT_FOUND)
                            ThrowIfWfpError(delStatus, $"FwpmFilterDeleteById0({oldFilterId})");
                    }
                });
            }
            finally
            {
                if (appIdBlobPtr != 0)
                    WfpNative.FwpmFreeMemory0(ref appIdBlobPtr);
            }
        }
    }

    /// <summary>Atomically removes all filters owned by this product for <paramref name="app"/>.</summary>
    public void RemoveAppPolicy(AppIdentity app)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        string canonicalExePath = ValidateAndNormalizeExecutableIdentity(app);
        EnsureWindowsPlatform();

        byte[] appTagBytes = BuildAppTagBytes(canonicalExePath);

        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);

            nint appIdBlobPtr = 0;
            byte[]? appIdBytes = null;
            try
            {
                uint appIdStatus = WfpNative.FwpmGetAppIdFromFileName0(canonicalExePath, out appIdBlobPtr);
                if (appIdStatus == WfpNative.ERROR_SUCCESS)
                {
                    appIdBytes = ReadBlobBytes(appIdBlobPtr);
                }
                else if (appIdStatus != WfpNative.ERROR_FILE_NOT_FOUND && appIdStatus != WfpNative.ERROR_PATH_NOT_FOUND)
                {
                    ThrowIfWfpError(appIdStatus, $"FwpmGetAppIdFromFileName0({canonicalExePath})");
                }

                EnsureEngineOpenLocked();
                if (!SublayerExistsLocked())
                    return;

                ExecuteTransactionLocked(() =>
                {
                    IReadOnlyList<ulong> matchingIds = FindMatchingAppFilterIdsLocked(appIdBytes, appTagBytes);
                    foreach (ulong filterId in matchingIds)
                    {
                        uint delStatus = WfpNative.FwpmFilterDeleteById0(_engineHandle, filterId);
                        if (delStatus != WfpNative.ERROR_SUCCESS && delStatus != WfpNative.FWP_E_FILTER_NOT_FOUND)
                            ThrowIfWfpError(delStatus, $"FwpmFilterDeleteById0({filterId})");
                    }
                });
            }
            finally
            {
                if (appIdBlobPtr != 0)
                    WfpNative.FwpmFreeMemory0(ref appIdBlobPtr);
            }
        }
    }

    /// <summary>Enumerates all active WFP filters currently registered inside this product's sublayer.</summary>
    public IReadOnlyList<ActiveWfpFilterInfo> ListSublayerFilters()
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        EnsureWindowsPlatform();

        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            EnsureEngineOpenLocked();

            if (!SublayerExistsLocked())
                return [];

            return EnumerateSublayerFiltersInternalLocked()
                .Select(static item => item.Info)
                .ToList();
        }
    }

    /// <summary>Transactionally removes every filter inside this product's sublayer and returns the number deleted.</summary>
    public int ResetSublayerFilters()
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        EnsureWindowsPlatform();

        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            EnsureEngineOpenLocked();

            if (!SublayerExistsLocked())
                return 0;

            int deleted = 0;
            ExecuteTransactionLocked(() =>
            {
                List<EnumeratedFilterRecord> filters = EnumerateSublayerFiltersInternalLocked();
                foreach (EnumeratedFilterRecord filter in filters)
                {
                    uint status = WfpNative.FwpmFilterDeleteById0(_engineHandle, filter.Info.FilterId);
                    if (status == WfpNative.ERROR_SUCCESS)
                    {
                        deleted++;
                    }
                    else if (status != WfpNative.FWP_E_FILTER_NOT_FOUND)
                    {
                        ThrowIfWfpError(status, $"FwpmFilterDeleteById0({filter.Info.FilterId})");
                    }
                }
            });

            return deleted;
        }
    }

    /// <summary>Closes the WFP engine session handle (deleting session objects only if <see cref="IsDynamicSession"/> is true).</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;

        lock (_sync)
        {
            if (_engineHandle != 0)
            {
                _ = WfpNative.FwpmEngineClose0(_engineHandle);
                _engineHandle = 0;
            }
        }
    }

    /// <summary>Resolves a supported ALE <see cref="WfpLayer"/> to its native GUID or throws <see cref="NotSupportedException"/>.</summary>
    internal static Guid ResolveSupportedLayerGuid(WfpLayer layer, out bool isV4)
    {
        switch (layer)
        {
            case WfpLayer.AleAuthConnectV4:
                isV4 = true;
                return WfpNative.LayerAleAuthConnectV4;
            case WfpLayer.AleAuthConnectV6:
                isV4 = false;
                return WfpNative.LayerAleAuthConnectV6;
            case WfpLayer.AleAuthRecvAcceptV4:
                isV4 = true;
                return WfpNative.LayerAleAuthRecvAcceptV4;
            case WfpLayer.AleAuthRecvAcceptV6:
                isV4 = false;
                return WfpNative.LayerAleAuthRecvAcceptV6;
            case WfpLayer.OutboundTransportV4:
            case WfpLayer.OutboundTransportV6:
                throw new NotSupportedException(
                    $"WFP layer '{layer}' is not supported for user-mode per-application filtering because transport layers do not support FWPM_CONDITION_ALE_APP_ID and cannot enforce per-app rules without creating global filters.");
            default:
                throw new NotSupportedException($"WFP layer '{layer}' is not supported.");
        }
    }

    /// <summary>Validates that an application identity is supported and returns its canonical uppercase full path.</summary>
    internal static string ValidateAndNormalizeExecutableIdentity(AppIdentity app)
    {
        ArgumentNullException.ThrowIfNull(app);

        if (app.Kind == AppIdentityKind.UwpPackage)
            throw new NotSupportedException("AppIdentityKind.UwpPackage is not supported in Phase 2 WFP enforcement; only executable file paths are supported.");

        if (app.Kind != AppIdentityKind.Executable)
            throw new NotSupportedException($"AppIdentityKind '{app.Kind}' is not supported.");

        if (string.IsNullOrWhiteSpace(app.Value))
            throw new ArgumentException("Executable path cannot be empty or whitespace.", nameof(app));

        return Path.GetFullPath(app.Value.Trim()).TrimEnd(Path.DirectorySeparatorChar).ToUpperInvariant();
    }

    /// <summary>Validates that a compiled filter specification is strictly scoped and targets a supported ALE layer.</summary>
    internal static void ValidateFilterSpec(FilterSpec spec, AppIdentity app)
    {
        ArgumentNullException.ThrowIfNull(spec);
        _ = ValidateAndNormalizeExecutableIdentity(app);
        _ = ResolveSupportedLayerGuid(spec.Layer, out bool isV4);

        if (!Enum.IsDefined(spec.Action))
            throw new ArgumentOutOfRangeException(nameof(spec), $"Unsupported filter action '{spec.Action}'.");

        if (spec.InterfaceLuid.HasValue && spec.InterfaceLuid.Value == 0)
            throw new InvalidOperationException("Interface LUID 0 is invalid and cannot be used in a WFP filter condition.");

        if (!string.IsNullOrWhiteSpace(spec.RemoteAddress))
        {
            if (isV4)
                _ = ParseIPv4Cidr(spec.RemoteAddress);
            else
                _ = ParseIPv6Cidr(spec.RemoteAddress);
        }

        if (spec.Action == FilterAction.Permit)
        {
            bool hasLuid = spec.InterfaceLuid is > 0;
            bool hasRemote = !string.IsNullOrWhiteSpace(spec.RemoteAddress);
            if (!hasLuid && !hasRemote)
                throw new InvalidOperationException("Refusing to install an unscoped PERMIT filter without an allowed interface LUID or explicit loopback remote address.");
        }
    }

    /// <summary>
    /// Builds a fail-closed filter plan on the 4 supported ALE layers (IPv4 and IPv6 connect + recv/accept).
    /// Every filter is scoped to <paramref name="policy"/>'s executable identity and includes a base BLOCK filter.
    /// </summary>
    internal static IReadOnlyList<FilterSpec> BuildAleFilterPlan(NetworkPolicy policy, IReadOnlyCollection<AdapterInfo> adapters)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(adapters);

        string canonicalExePath = ValidateAndNormalizeExecutableIdentity(policy.App);
        if (policy.Mode == PolicyMode.Unassigned)
            return [];

        var filters = new List<FilterSpec>();
        foreach (var (layer, _, isV4) in SupportedAleLayerDescriptors)
        {
            if (policy.Options.AllowLoopback)
            {
                var loopbackSpec = new FilterSpec(
                    layer,
                    FilterAction.Permit,
                    15,
                    "Loopback exemption",
                    RemoteAddress: isV4 ? "127.0.0.0/8" : "::1/128");
                ValidateFilterSpec(loopbackSpec, policy.App);
                filters.Add(loopbackSpec);
            }

            if (policy.Mode is PolicyMode.Bind or PolicyMode.AllowMultiple)
            {
                foreach (ulong luid in policy.AllowedLuid.Distinct())
                {
                    if (luid == 0)
                        continue;

                    AdapterInfo? adapter = adapters.FirstOrDefault(a => a.NetLuid == luid);
                    if (adapter is null || !adapter.IsUpAndRoutable)
                        continue;

                    bool hasFamilyAddress = isV4 ? adapter.IPv4Addresses.Count > 0 : adapter.IPv6Addresses.Count > 0;
                    if (!hasFamilyAddress)
                        continue;

                    var permitSpec = new FilterSpec(
                        layer,
                        FilterAction.Permit,
                        10,
                        $"Allow {Path.GetFileName(canonicalExePath)} on LUID 0x{luid:X}",
                        InterfaceLuid: luid);
                    ValidateFilterSpec(permitSpec, policy.App);
                    filters.Add(permitSpec);
                }
            }

            var blockSpec = new FilterSpec(
                layer,
                FilterAction.Block,
                1,
                $"Base block {Path.GetFileName(canonicalExePath)}");
            ValidateFilterSpec(blockSpec, policy.App);
            filters.Add(blockSpec);
        }

        return filters;
    }

    internal static WfpNative.FWP_V4_ADDR_AND_MASK ParseIPv4Cidr(string cidr)
    {
        if (string.IsNullOrWhiteSpace(cidr))
            throw new ArgumentException("CIDR string cannot be empty.", nameof(cidr));

        string[] parts = cidr.Split('/', 2, StringSplitOptions.TrimEntries);
        if (!IPAddress.TryParse(parts[0], out IPAddress? ip) || ip.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException($"Invalid IPv4 CIDR address '{cidr}'.", nameof(cidr));

        int prefix = 32;
        if (parts.Length == 2 && (!int.TryParse(parts[1], out prefix) || prefix < 0 || prefix > 32))
            throw new ArgumentException($"Invalid IPv4 prefix length in '{cidr}'.", nameof(cidr));

        byte[] bytes = ip.GetAddressBytes();
        uint addrHostOrder = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
        uint maskHostOrder = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);

        return new WfpNative.FWP_V4_ADDR_AND_MASK
        {
            addr = addrHostOrder,
            mask = maskHostOrder
        };
    }

    internal static WfpNative.FWP_V6_ADDR_AND_MASK ParseIPv6Cidr(string cidr)
    {
        if (string.IsNullOrWhiteSpace(cidr))
            throw new ArgumentException("CIDR string cannot be empty.", nameof(cidr));

        string[] parts = cidr.Split('/', 2, StringSplitOptions.TrimEntries);
        if (!IPAddress.TryParse(parts[0], out IPAddress? ip) || ip.AddressFamily != AddressFamily.InterNetworkV6)
            throw new ArgumentException($"Invalid IPv6 CIDR address '{cidr}'.", nameof(cidr));

        int prefix = 128;
        if (parts.Length == 2 && (!int.TryParse(parts[1], out prefix) || prefix < 0 || prefix > 128))
            throw new ArgumentException($"Invalid IPv6 prefix length in '{cidr}'.", nameof(cidr));

        byte[] bytes = ip.GetAddressBytes();
        return WfpNative.FWP_V6_ADDR_AND_MASK.FromBytes(bytes, (byte)prefix);
    }

    private void EnsureEngineOpenLocked()
    {
        if (_engineHandle != 0)
            return;

        var allocations = new List<nint>(2);
        try
        {
            nint namePtr = AllocUnicodeString("NetworkIsolation WFP Manager", allocations);
            nint descPtr = AllocUnicodeString("Per-application fail-closed network isolation engine", allocations);

            var session = new WfpNative.SESSION
            {
                sessionKey = Guid.Empty,
                displayData = new WfpNative.DISPLAY { name = namePtr, description = descPtr },
                flags = _dynamicSession ? WfpNative.FWPM_SESSION_FLAG_DYNAMIC : WfpNative.FWPM_SESSION_FLAG_NONE,
                txnWaitTimeoutInMSec = TransactionWaitTimeoutMs
            };

            uint status = WfpNative.FwpmEngineOpen0(null, WfpNative.RPC_C_AUTHN_WINNT, 0, ref session, out nint handle);
            ThrowIfWfpError(status, "FwpmEngineOpen0");
            _engineHandle = handle;
        }
        finally
        {
            FreeAll(allocations);
        }
    }

    private void EnsureSublayerExistsOrCreateViaTxLocked()
    {
        if (ProviderExistsWithExpectedPersistenceLocked() && SublayerExistsWithExpectedPersistenceLocked())
            return;

        ExecuteTransactionLocked(EnsureProviderAndSublayerLocked);
    }

    private bool ProviderExistsWithExpectedPersistenceLocked()
    {
        Guid providerKey = WfpNative.ProviderKey;
        uint status = WfpNative.FwpmProviderGetByKey0(_engineHandle, ref providerKey, out nint ptr);
        if (status == WfpNative.FWP_E_PROVIDER_NOT_FOUND || status == WfpNative.FWP_E_NOT_FOUND)
            return false;

        ThrowIfWfpError(status, "FwpmProviderGetByKey0");
        try
        {
            var provider = Marshal.PtrToStructure<WfpNative.PROVIDER>(ptr);
            if (!_dynamicSession && (provider.flags & WfpNative.FWPM_PROVIDER_FLAG_PERSISTENT) == 0)
                throw new InvalidOperationException("Existing WFP provider is non-persistent (dynamic); cannot install persistent fail-closed filters while the dynamic provider is active.");
            return true;
        }
        finally
        {
            if (ptr != 0)
                WfpNative.FwpmFreeMemory0(ref ptr);
        }
    }

    private bool SublayerExistsLocked()
    {
        Guid sublayerKey = WfpNative.SublayerKey;
        uint status = WfpNative.FwpmSubLayerGetByKey0(_engineHandle, ref sublayerKey, out nint ptr);
        if (status == WfpNative.FWP_E_SUBLAYER_NOT_FOUND || status == WfpNative.FWP_E_NOT_FOUND)
            return false;

        ThrowIfWfpError(status, "FwpmSubLayerGetByKey0");
        if (ptr != 0)
            WfpNative.FwpmFreeMemory0(ref ptr);
        return true;
    }

    private bool SublayerExistsWithExpectedPersistenceLocked()
    {
        Guid sublayerKey = WfpNative.SublayerKey;
        uint status = WfpNative.FwpmSubLayerGetByKey0(_engineHandle, ref sublayerKey, out nint ptr);
        if (status == WfpNative.FWP_E_SUBLAYER_NOT_FOUND || status == WfpNative.FWP_E_NOT_FOUND)
            return false;

        ThrowIfWfpError(status, "FwpmSubLayerGetByKey0");
        try
        {
            var sublayer = Marshal.PtrToStructure<WfpNative.SUBLAYER>(ptr);
            if (!_dynamicSession && (sublayer.flags & WfpNative.FWPM_SUBLAYER_FLAG_PERSISTENT) == 0)
                throw new InvalidOperationException("Existing WFP sublayer is non-persistent (dynamic); cannot install persistent fail-closed filters while the dynamic sublayer is active.");
            return true;
        }
        finally
        {
            if (ptr != 0)
                WfpNative.FwpmFreeMemory0(ref ptr);
        }
    }

    private void EnsureProviderAndSublayerLocked()
    {
        var allocations = new List<nint>(8);
        try
        {
            if (!ProviderExistsWithExpectedPersistenceLocked())
            {
                var provider = new WfpNative.PROVIDER
                {
                    providerKey = WfpNative.ProviderKey,
                    displayData = new WfpNative.DISPLAY
                    {
                        name = AllocUnicodeString("NetworkIsolation", allocations),
                        description = AllocUnicodeString("Windows Per-Application Fail-Closed Network Isolation", allocations)
                    },
                    flags = _dynamicSession ? WfpNative.FWPM_PROVIDER_FLAG_NONE : WfpNative.FWPM_PROVIDER_FLAG_PERSISTENT
                };

                uint addProvStatus = WfpNative.FwpmProviderAdd0(_engineHandle, ref provider, 0);
                if (addProvStatus != WfpNative.ERROR_SUCCESS && addProvStatus != WfpNative.FWP_E_ALREADY_EXISTS)
                    ThrowIfWfpError(addProvStatus, "FwpmProviderAdd0");
            }

            if (!SublayerExistsWithExpectedPersistenceLocked())
            {
                nint providerKeyPtr = AllocStruct(WfpNative.ProviderKey, allocations);
                var sublayer = new WfpNative.SUBLAYER
                {
                    subLayerKey = WfpNative.SublayerKey,
                    displayData = new WfpNative.DISPLAY
                    {
                        name = AllocUnicodeString("NetworkIsolation Sublayer", allocations),
                        description = AllocUnicodeString("Fail-closed per-application adapter allowlist sublayer", allocations)
                    },
                    flags = _dynamicSession ? WfpNative.FWPM_SUBLAYER_FLAG_NONE : WfpNative.FWPM_SUBLAYER_FLAG_PERSISTENT,
                    providerKey = providerKeyPtr,
                    weight = SublayerWeight
                };

                uint addSubStatus = WfpNative.FwpmSubLayerAdd0(_engineHandle, ref sublayer, 0);
                if (addSubStatus != WfpNative.ERROR_SUCCESS && addSubStatus != WfpNative.FWP_E_ALREADY_EXISTS)
                    ThrowIfWfpError(addSubStatus, "FwpmSubLayerAdd0");
            }
        }
        finally
        {
            FreeAll(allocations);
        }
    }

    private void AddScopedFilterLocked(FilterSpec spec, string canonicalExePath, nint appIdBlobPtr, byte[] appTagBytes)
    {
        Guid layerGuid = ResolveSupportedLayerGuid(spec.Layer, out bool isV4);
        var allocations = new List<nint>(12);
        try
        {
            var conditions = new List<WfpNative.CONDITION>(3)
            {
                new()
                {
                    field = WfpNative.ConditionApp,
                    match = WfpNative.FWP_MATCH_EQUAL,
                    value = new WfpNative.CVALUE
                    {
                        type = WfpNative.FWP_BYTE_BLOB_TYPE,
                        ptr = appIdBlobPtr
                    }
                }
            };

            if (spec.InterfaceLuid.HasValue)
            {
                if (spec.InterfaceLuid.Value == 0)
                    throw new InvalidOperationException("Refusing to add filter with zero InterfaceLuid.");

                nint luidPtr = AllocUInt64(spec.InterfaceLuid.Value, allocations);
                conditions.Add(new WfpNative.CONDITION
                {
                    field = WfpNative.ConditionInterface,
                    match = WfpNative.FWP_MATCH_EQUAL,
                    value = new WfpNative.CVALUE
                    {
                        type = WfpNative.FWP_UINT64,
                        ptr = luidPtr
                    }
                });
            }

            if (!string.IsNullOrWhiteSpace(spec.RemoteAddress))
            {
                if (isV4)
                {
                    WfpNative.FWP_V4_ADDR_AND_MASK v4Mask = ParseIPv4Cidr(spec.RemoteAddress);
                    nint v4Ptr = AllocStruct(v4Mask, allocations);
                    conditions.Add(new WfpNative.CONDITION
                    {
                        field = WfpNative.ConditionRemote,
                        match = WfpNative.FWP_MATCH_EQUAL,
                        value = new WfpNative.CVALUE
                        {
                            type = WfpNative.FWP_V4_ADDR_MASK,
                            ptr = v4Ptr
                        }
                    });
                }
                else
                {
                    WfpNative.FWP_V6_ADDR_AND_MASK v6Mask = ParseIPv6Cidr(spec.RemoteAddress);
                    nint v6Ptr = AllocStruct(v6Mask, allocations);
                    conditions.Add(new WfpNative.CONDITION
                    {
                        field = WfpNative.ConditionRemote,
                        match = WfpNative.FWP_MATCH_EQUAL,
                        value = new WfpNative.CVALUE
                        {
                            type = WfpNative.FWP_V6_ADDR_MASK,
                            ptr = v6Ptr
                        }
                    });
                }
            }

            // Final structural invariant: no filter may ever be added without ALE_APP_ID, and PERMIT filters must have a scope condition.
            if (conditions.Count == 0 || conditions[0].field != WfpNative.ConditionApp || conditions[0].value.ptr == 0)
                throw new InvalidOperationException("Refusing to install an unscoped WFP filter without FWPM_CONDITION_ALE_APP_ID.");
            if (spec.Action == FilterAction.Permit && conditions.Count < 2)
                throw new InvalidOperationException("Refusing to install an unscoped PERMIT WFP filter.");

            int condSize = Marshal.SizeOf<WfpNative.CONDITION>();
            nint condArrayPtr = Marshal.AllocHGlobal(condSize * conditions.Count);
            allocations.Add(condArrayPtr);
            for (int i = 0; i < conditions.Count; i++)
                Marshal.StructureToPtr(conditions[i], condArrayPtr + i * condSize, false);

            nint providerKeyPtr = AllocStruct(WfpNative.ProviderKey, allocations);
            nint weightPtr = AllocUInt64(spec.Weight, allocations);
            nint tagPtr = AllocBytes(appTagBytes, allocations);

            string scopeSummary = spec.InterfaceLuid.HasValue
                ? $"LUID:0x{spec.InterfaceLuid.Value:X}"
                : spec.RemoteAddress ?? "AppDefaultBlock";

            var filter = new WfpNative.FILTER
            {
                key = Guid.NewGuid(),
                display = new WfpNative.DISPLAY
                {
                    name = AllocUnicodeString($"NetworkIsolation: {spec.Purpose}", allocations),
                    description = AllocUnicodeString($"Layer={spec.Layer}; Action={spec.Action}; App={canonicalExePath}; Scope={scopeSummary}", allocations)
                },
                flags = _dynamicSession ? WfpNative.FWPM_FILTER_FLAG_NONE : WfpNative.FWPM_FILTER_FLAG_PERSISTENT,
                providerKey = providerKeyPtr,
                providerData = new WfpNative.BLOB
                {
                    size = (uint)appTagBytes.Length,
                    data = tagPtr
                },
                layerKey = layerGuid,
                sublayerKey = WfpNative.SublayerKey,
                weight = new WfpNative.VALUE
                {
                    type = WfpNative.FWP_UINT64,
                    ptr = weightPtr
                },
                numConditions = (uint)conditions.Count,
                conditions = condArrayPtr,
                action = new WfpNative.ACTION
                {
                    type = spec.Action == FilterAction.Permit ? WfpNative.FWP_ACTION_PERMIT : WfpNative.FWP_ACTION_BLOCK
                }
            };

            uint status = WfpNative.FwpmFilterAdd0(_engineHandle, ref filter, 0, out _);
            ThrowIfWfpError(status, $"FwpmFilterAdd0({spec.Layer}, {spec.Action})");
        }
        finally
        {
            FreeAll(allocations);
        }
    }

    private IReadOnlyList<ulong> FindMatchingAppFilterIdsLocked(byte[]? appIdBytes, byte[] appTagBytes)
    {
        var matches = new List<ulong>();
        foreach (EnumeratedFilterRecord record in EnumerateSublayerFiltersInternalLocked())
        {
            bool matchedByAppId = appIdBytes is not null && record.AppIdBytes is not null && appIdBytes.AsSpan().SequenceEqual(record.AppIdBytes);
            bool matchedByTag = record.ProviderDataBytes is not null && appTagBytes.AsSpan().SequenceEqual(record.ProviderDataBytes);
            if (matchedByAppId || matchedByTag)
                matches.Add(record.Info.FilterId);
        }
        return matches;
    }

    private List<EnumeratedFilterRecord> EnumerateSublayerFiltersInternalLocked()
    {
        var results = new List<EnumeratedFilterRecord>();
        var allocations = new List<nint>(1);
        try
        {
            nint providerKeyPtr = AllocStruct(WfpNative.ProviderKey, allocations);

            foreach (Guid layerGuid in WfpNative.Layers)
            {
                var template = new WfpNative.ENUM_TEMPLATE
                {
                    providerKey = providerKeyPtr,
                    layerKey = layerGuid,
                    enumType = WfpNative.FWP_FILTER_ENUM_OVERLAPPING,
                    flags = WfpNative.FWP_FILTER_ENUM_FLAG_SORTED,
                    actionMask = WfpNative.FWP_FILTER_ENUM_ACTION_MASK_ALL
                };

                uint createStatus = WfpNative.FwpmFilterCreateEnumHandle0(_engineHandle, ref template, out nint enumHandle);
                if (createStatus == WfpNative.FWP_E_LAYER_NOT_FOUND)
                    continue;
                ThrowIfWfpError(createStatus, $"FwpmFilterCreateEnumHandle0({layerGuid})");

                try
                {
                    while (true)
                    {
                        uint enumStatus = WfpNative.FwpmFilterEnum0(_engineHandle, enumHandle, EnumBatchSize, out nint entriesPtr, out uint returned);
                        ThrowIfWfpError(enumStatus, $"FwpmFilterEnum0({layerGuid})");

                        try
                        {
                            if (returned == 0 || entriesPtr == 0)
                                break;

                            for (int i = 0; i < returned; i++)
                            {
                                nint filterPtr = Marshal.ReadIntPtr(entriesPtr, i * IntPtr.Size);
                                if (filterPtr == 0)
                                    continue;

                                var filter = Marshal.PtrToStructure<WfpNative.FILTER>(filterPtr);
                                if (filter.sublayerKey != WfpNative.SublayerKey)
                                    continue;
                                if (filter.providerKey != 0 && Marshal.PtrToStructure<Guid>(filter.providerKey) != WfpNative.ProviderKey)
                                    continue;

                                results.Add(ReadEnumeratedFilter(filter));
                            }

                            if (returned < EnumBatchSize)
                                break;
                        }
                        finally
                        {
                            if (entriesPtr != 0)
                                WfpNative.FwpmFreeMemory0(ref entriesPtr);
                        }
                    }
                }
                finally
                {
                    _ = WfpNative.FwpmFilterDestroyEnumHandle0(_engineHandle, enumHandle);
                }
            }
        }
        finally
        {
            FreeAll(allocations);
        }

        return results;
    }

    private static EnumeratedFilterRecord ReadEnumeratedFilter(WfpNative.FILTER filter)
    {
        string name = filter.display.name != 0 ? Marshal.PtrToStringUni(filter.display.name) ?? string.Empty : string.Empty;
        string description = filter.display.description != 0 ? Marshal.PtrToStringUni(filter.display.description) ?? string.Empty : string.Empty;

        ulong weight = ReadWeightValue(filter.effectiveWeight);
        if (weight == 0)
            weight = ReadWeightValue(filter.weight);

        byte[]? providerDataBytes = null;
        string? appTag = null;
        if (filter.providerData.size > 0 && filter.providerData.data != 0)
        {
            providerDataBytes = new byte[filter.providerData.size];
            Marshal.Copy(filter.providerData.data, providerDataBytes, 0, providerDataBytes.Length);
            appTag = Encoding.UTF8.GetString(providerDataBytes);
        }

        byte[]? appIdBytes = null;
        if (filter.numConditions > 0 && filter.conditions != 0)
        {
            int condSize = Marshal.SizeOf<WfpNative.CONDITION>();
            for (int i = 0; i < filter.numConditions; i++)
            {
                var cond = Marshal.PtrToStructure<WfpNative.CONDITION>(filter.conditions + i * condSize);
                if (cond.field == WfpNative.ConditionApp &&
                    cond.value.type == WfpNative.FWP_BYTE_BLOB_TYPE &&
                    cond.value.ptr != 0)
                {
                    appIdBytes = ReadBlobBytes(cond.value.ptr);
                    break;
                }
            }
        }

        var info = new ActiveWfpFilterInfo(filter.filterId, name, description)
        {
            LayerKey = filter.layerKey,
            ActionType = filter.action.type,
            Weight = weight,
            AppTag = appTag
        };

        return new EnumeratedFilterRecord(info, appIdBytes, providerDataBytes);
    }

    private static ulong ReadWeightValue(WfpNative.VALUE value)
    {
        if (value.type == WfpNative.FWP_UINT64 && value.ptr != 0)
            return (ulong)Marshal.ReadInt64(value.ptr);
        if (value.type == WfpNative.FWP_UINT8)
            return value.uint8;
        if (value.type == WfpNative.FWP_UINT16)
            return value.uint16;
        if (value.type == WfpNative.FWP_UINT32)
            return value.uint32;
        return 0;
    }

    private void ExecuteTransactionLocked(Action action)
    {
        uint beginStatus = WfpNative.FwpmTransactionBegin0(_engineHandle, 0);
        ThrowIfWfpError(beginStatus, "FwpmTransactionBegin0");

        try
        {
            action();
            uint commitStatus = WfpNative.FwpmTransactionCommit0(_engineHandle);
            ThrowIfWfpError(commitStatus, "FwpmTransactionCommit0");
        }
        catch
        {
            _ = WfpNative.FwpmTransactionAbort0(_engineHandle);
            throw;
        }
    }

    private static void EnsureWindowsPlatform()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows Filtering Platform (WFP) is only supported on Windows.");
    }

    private static byte[] BuildAppTagBytes(string canonicalExePath) =>
        Encoding.UTF8.GetBytes($"APP:{canonicalExePath}");

    private static byte[] ReadBlobBytes(nint blobPtr)
    {
        if (blobPtr == 0)
            return [];

        var blob = Marshal.PtrToStructure<WfpNative.BLOB>(blobPtr);
        if (blob.size == 0 || blob.data == 0)
            return [];

        var bytes = new byte[blob.size];
        Marshal.Copy(blob.data, bytes, 0, bytes.Length);
        return bytes;
    }

    private static nint AllocUnicodeString(string value, List<nint> allocations)
    {
        nint ptr = Marshal.StringToHGlobalUni(value);
        allocations.Add(ptr);
        return ptr;
    }

    private static nint AllocUInt64(ulong value, List<nint> allocations)
    {
        nint ptr = Marshal.AllocHGlobal(sizeof(ulong));
        allocations.Add(ptr);
        Marshal.WriteInt64(ptr, unchecked((long)value));
        return ptr;
    }

    private static nint AllocBytes(byte[] bytes, List<nint> allocations)
    {
        if (bytes.Length == 0)
            return 0;

        nint ptr = Marshal.AllocHGlobal(bytes.Length);
        allocations.Add(ptr);
        Marshal.Copy(bytes, 0, ptr, bytes.Length);
        return ptr;
    }

    private static nint AllocStruct<T>(T value, List<nint> allocations) where T : struct
    {
        nint ptr = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
        allocations.Add(ptr);
        Marshal.StructureToPtr(value, ptr, false);
        return ptr;
    }

    private static void FreeAll(List<nint> allocations)
    {
        for (int i = allocations.Count - 1; i >= 0; i--)
        {
            if (allocations[i] != 0)
                Marshal.FreeHGlobal(allocations[i]);
        }
        allocations.Clear();
    }

    private static void ThrowIfWfpError(uint status, string operation)
    {
        if (status == WfpNative.ERROR_SUCCESS)
            return;

        throw new Win32Exception(unchecked((int)status), $"{operation} failed with WFP/Win32 status 0x{status:X8}.");
    }

    private sealed record EnumeratedFilterRecord(ActiveWfpFilterInfo Info, byte[]? AppIdBytes, byte[]? ProviderDataBytes);
}
