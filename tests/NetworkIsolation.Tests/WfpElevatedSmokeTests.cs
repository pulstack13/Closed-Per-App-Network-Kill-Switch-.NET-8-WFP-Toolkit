using System.Net;
using NetworkIsolation.Core;
using NetworkIsolation.Wfp;
using NetworkIsolation.Wfp.Native;

namespace NetworkIsolation.Tests;

public sealed class ElevatedWindowsFactAttribute : FactAttribute
{
    public ElevatedWindowsFactAttribute()
    {
        if (!OperatingSystem.IsWindows() || !WfpEngineManager.IsAdministrator())
            Skip = "Requires an elevated Windows administrator session to exercise BFE.";
    }
}

public class WfpElevatedSmokeTests
{
    private static string CreateUniqueTestExecutable(out string directory)
    {
        string source = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot locate test host executable.");
        directory = Path.Combine(Path.GetTempPath(), $"NetworkIsolation.WfpSmoke.{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        string target = Path.Combine(directory, Path.GetFileName(source));
        File.Copy(source, target);

        // A copied framework-dependent apphost needs its assembly and runtime metadata beside it.
        string sourceDirectory = Path.GetDirectoryName(source)!;
        string assemblyName = Path.GetFileNameWithoutExtension(source);
        foreach (string extension in new[] { ".dll", ".deps.json", ".runtimeconfig.json" })
        {
            string sourceFile = Path.Combine(sourceDirectory, assemblyName + extension);
            if (File.Exists(sourceFile))
                File.Copy(sourceFile, Path.Combine(directory, Path.GetFileName(sourceFile)));
        }

        return target;
    }

    private static IReadOnlyList<ActiveWfpFilterInfo> ForApp(WfpEngineManager engine, AppIdentity app) =>
        engine.ListSublayerFilters().Where(f => string.Equals(f.AppTag, $"APP:{Path.GetFullPath(app.Value).TrimEnd(Path.DirectorySeparatorChar).ToUpperInvariant()}", StringComparison.Ordinal)).ToArray();

    private static AdapterInfo MakeAdapter(ulong luid, bool up, bool v4, bool v6) =>
        new(
            luid,
            Guid.NewGuid(),
            10,
            "TestAdapter",
            "Test Adapter",
            6,
            up ? "Up" : "Down",
            v4 ? [IPAddress.Parse("192.0.2.10")] : [],
            v6 ? [IPAddress.Parse("2001:db8::10")] : [],
            [],
            10,
            10,
            false,
            up);

    [Fact]
    public void ConstructorDefaultsToPersistentFailClosedMode()
    {
        using var persistent = new WfpEngineManager();
        Assert.True(persistent.IsPersistent);
        Assert.False(persistent.IsDynamicSession);

        using var dynamic = new WfpEngineManager(dynamicSession: true);
        Assert.False(dynamic.IsPersistent);
        Assert.True(dynamic.IsDynamicSession);
    }

    [Fact]
    public void UnsupportedIdentitiesAreExplicitlyRejected()
    {
        using var engine = new WfpEngineManager(dynamicSession: true);

        var uwpIdentity = AppIdentity.UwpPackage("Microsoft.WindowsStore_8wekyb3d8bbwe");
        var uwpPolicy = new NetworkPolicy(uwpIdentity, PolicyMode.BlockAll, [], new PolicyOptions());

        Assert.False(WfpEngineManager.IsSupportedIdentity(uwpIdentity));
        Assert.Throws<NotSupportedException>(() => engine.ApplyPolicy(uwpPolicy, []));
        Assert.Throws<NotSupportedException>(() => engine.RemoveAppPolicy(uwpIdentity));

        var unknownKind = new AppIdentity((AppIdentityKind)999, "sample.exe");
        var unknownPolicy = new NetworkPolicy(unknownKind, PolicyMode.BlockAll, [], new PolicyOptions());
        Assert.Throws<NotSupportedException>(() => engine.ApplyPolicy(unknownPolicy, []));
        Assert.Throws<NotSupportedException>(() => engine.RemoveAppPolicy(unknownKind));

        var emptyExe = new AppIdentity(AppIdentityKind.Executable, "   ");
        Assert.Throws<ArgumentException>(() => engine.ApplyPolicy(new NetworkPolicy(emptyExe, PolicyMode.BlockAll, [], new PolicyOptions()), []));
    }

    [Fact]
    public void UnsupportedTransportLayersAreExplicitlyRejected()
    {
        Assert.True(WfpEngineManager.IsSupportedLayer(WfpLayer.AleAuthConnectV4));
        Assert.True(WfpEngineManager.IsSupportedLayer(WfpLayer.AleAuthConnectV6));
        Assert.True(WfpEngineManager.IsSupportedLayer(WfpLayer.AleAuthRecvAcceptV4));
        Assert.True(WfpEngineManager.IsSupportedLayer(WfpLayer.AleAuthRecvAcceptV6));

        Assert.False(WfpEngineManager.IsSupportedLayer(WfpLayer.OutboundTransportV4));
        Assert.False(WfpEngineManager.IsSupportedLayer(WfpLayer.OutboundTransportV6));
        Assert.False(WfpEngineManager.IsSupportedLayer((WfpLayer)999));

        Assert.Throws<NotSupportedException>(() => WfpEngineManager.ResolveSupportedLayerGuid(WfpLayer.OutboundTransportV4, out _));
        Assert.Throws<NotSupportedException>(() => WfpEngineManager.ResolveSupportedLayerGuid(WfpLayer.OutboundTransportV6, out _));
        Assert.Throws<NotSupportedException>(() => WfpEngineManager.ResolveSupportedLayerGuid((WfpLayer)999, out _));

        var app = AppIdentity.Executable("sample.exe");
        Assert.Throws<NotSupportedException>(() => WfpEngineManager.ValidateFilterSpec(
            new FilterSpec(WfpLayer.OutboundTransportV4, FilterAction.Block, 1, "Invalid layer"), app));
        Assert.Throws<NotSupportedException>(() => WfpEngineManager.ValidateFilterSpec(
            new FilterSpec(WfpLayer.OutboundTransportV6, FilterAction.Block, 1, "Invalid layer"), app));
    }

    [Fact]
    public void UnscopedAndGlobalFiltersAreRejected()
    {
        var app = AppIdentity.Executable("sample.exe");

        // PERMIT without LUID or explicit loopback remote address must be rejected.
        Assert.Throws<InvalidOperationException>(() => WfpEngineManager.ValidateFilterSpec(
            new FilterSpec(WfpLayer.AleAuthConnectV4, FilterAction.Permit, 10, "Unscoped permit"), app));

        // Zero interface LUID must never be accepted.
        Assert.Throws<InvalidOperationException>(() => WfpEngineManager.ValidateFilterSpec(
            new FilterSpec(WfpLayer.AleAuthConnectV4, FilterAction.Permit, 10, "Zero LUID", InterfaceLuid: 0), app));

        // Zero LUID in policy AllowedLuid is ignored and produces only fail-closed blocks (plus loopback if enabled).
        var zeroLuidPolicy = new NetworkPolicy(app, PolicyMode.Bind, [0UL], new PolicyOptions(AllowLoopback: false));
        var plan = WfpEngineManager.BuildAleFilterPlan(zeroLuidPolicy, [MakeAdapter(0UL, true, true, true)]);
        Assert.Equal(4, plan.Count);
        Assert.DoesNotContain(plan, f => f.Action == FilterAction.Permit);
        Assert.All(plan, f => Assert.True(WfpEngineManager.IsSupportedLayer(f.Layer)));
    }

    [Fact]
    public void AleFilterPlanEnforcesFailClosedAndFamilySymmetry()
    {
        var app = AppIdentity.Executable("sample.exe");

        // IPv4-only adapter must not receive an IPv6 adapter PERMIT (IPv6 fails closed via base BLOCK).
        var v4OnlyAdapter = MakeAdapter(0x0006000000010000UL, up: true, v4: true, v6: false);
        var policy = new NetworkPolicy(app, PolicyMode.Bind, [v4OnlyAdapter.NetLuid], new PolicyOptions(AllowLoopback: true));

        var plan = WfpEngineManager.BuildAleFilterPlan(policy, [v4OnlyAdapter]);
        Assert.Equal(2, plan.Count(f => f.Action == FilterAction.Permit && f.InterfaceLuid == v4OnlyAdapter.NetLuid));
        Assert.DoesNotContain(plan, f => f.Layer is WfpLayer.AleAuthConnectV6 or WfpLayer.AleAuthRecvAcceptV6 && f.InterfaceLuid.HasValue);
        Assert.Equal(4, plan.Count(f => f.Action == FilterAction.Block && f.Weight == 1));

        // Disconnected adapter produces zero adapter PERMIT filters (only loopback + 4 base blocks).
        var downAdapter = MakeAdapter(v4OnlyAdapter.NetLuid, up: false, v4: true, v6: true);
        var disconnectedPlan = WfpEngineManager.BuildAleFilterPlan(policy, [downAdapter]);
        Assert.DoesNotContain(disconnectedPlan, f => f.InterfaceLuid.HasValue);
        Assert.Equal(4, disconnectedPlan.Count(f => f.Action == FilterAction.Block));
    }

    [Fact]
    public void MissingExecutableIsRejectedBeforeMutatingWfp()
    {
        using var engine = new WfpEngineManager(dynamicSession: true);
        string missingPath = Path.Combine(Path.GetTempPath(), $"missing-network-isolation-{Guid.NewGuid():N}.exe");
        var policy = new NetworkPolicy(AppIdentity.Executable(missingPath), PolicyMode.BlockAll, [], new PolicyOptions());

        Assert.Throws<FileNotFoundException>(() => engine.ApplyPolicy(policy, []));
    }

    [ElevatedWindowsFact]
    public void ElevatedBfeSmokeTest_InstallEnumerateReplaceAndResetDynamicSession()
    {
        string targetExe = CreateUniqueTestExecutable(out string tempDirectory);
        var app = AppIdentity.Executable(targetExe);
        var adapter = MakeAdapter(0x0006000000020000UL, up: true, v4: true, v6: true);

        using var engine = new WfpEngineManager(dynamicSession: true);
        try
        {
            // 1. Install Bind policy across all 4 ALE layers.
            var bindPolicy = new NetworkPolicy(app, PolicyMode.Bind, [adapter.NetLuid], new PolicyOptions(AllowLoopback: true));
            engine.ApplyPolicy(bindPolicy, [adapter]);

            var installed = ForApp(engine, app);
            Assert.Equal(12, installed.Count);
            Assert.Equal(4, installed.Count(f => f.ActionType == WfpNative.FWP_ACTION_BLOCK));
            Assert.Equal(8, installed.Count(f => f.ActionType == WfpNative.FWP_ACTION_PERMIT));

            // 2. Transition atomically to disconnected adapter (fail-closed: zero adapter permits, base blocks hold).
            var downAdapter = MakeAdapter(adapter.NetLuid, up: false, v4: true, v6: true);
            engine.ApplyPolicy(bindPolicy, [downAdapter]);

            var failClosed = ForApp(engine, app);
            Assert.Equal(8, failClosed.Count); // 4 loopback permits + 4 base blocks
            Assert.Equal(4, failClosed.Count(f => f.ActionType == WfpNative.FWP_ACTION_BLOCK));

            // 3. Remove app policy and verify clean removal.
            engine.RemoveAppPolicy(app);
            var afterRemove = ForApp(engine, app);
            Assert.Empty(afterRemove);
        }
        finally
        {
            try
            {
                engine.RemoveAppPolicy(app);
            }
            finally
            {
                if (Directory.Exists(tempDirectory))
                    Directory.Delete(tempDirectory, recursive: true);
            }
        }
    }

    [ElevatedWindowsFact]
    public void ElevatedBfeSmokeTest_PersistentFiltersSurviveSessionDisposeUntilReset()
    {
        string targetExe = CreateUniqueTestExecutable(out string tempDirectory);
        var app = AppIdentity.Executable(targetExe);
        var policy = new NetworkPolicy(app, PolicyMode.BlockAll, [], new PolicyOptions(AllowLoopback: false));

        try
        {
            using (var writer = new WfpEngineManager(dynamicSession: false))
            {
                writer.ApplyPolicy(policy, []);
            }

            using var reader = new WfpEngineManager(dynamicSession: false);
            var persisted = ForApp(reader, app);
            Assert.Equal(4, persisted.Count);
            Assert.All(persisted, f => Assert.Equal(WfpNative.FWP_ACTION_BLOCK, f.ActionType));

            Assert.Equal(4, persisted.Count);
            reader.RemoveAppPolicy(app);
            Assert.Empty(ForApp(reader, app));
        }
        finally
        {
            try
            {
                using var cleanup = new WfpEngineManager(dynamicSession: false);
                cleanup.RemoveAppPolicy(app);
            }
            finally
            {
                if (Directory.Exists(tempDirectory))
                    Directory.Delete(tempDirectory, recursive: true);
            }
        }
    }
}
