using System.Globalization;
using System.Net.Sockets;
using NetworkIsolation.Core;
using NetworkIsolation.Wfp;

var command = args.FirstOrDefault()?.ToLowerInvariant() ?? "help";

if (command == "adapters")
{
    using var provider = new IpHelperAdapterProvider();
    foreach (var adapter in provider.GetAdapters())
    {
        Console.WriteLine($"{adapter.FriendlyName} | LUID: 0x{adapter.NetLuid:X} | GUID: {adapter.InterfaceGuid} | ifIndex: {adapter.InterfaceIndex} | {adapter.OperStatus} | Routable: {adapter.IsUpAndRoutable}");
        Console.WriteLine($"  IPv4: {string.Join(", ", adapter.IPv4Addresses)}");
        Console.WriteLine($"  IPv6: {string.Join(", ", adapter.IPv6Addresses)}");
        Console.WriteLine($"  DNS:  {string.Join(", ", adapter.DnsServers)}");
    }
    return;
}

if (command == "wfp-hold")
{
    if (args.Length is < 3 or > 4)
    {
        PrintUsage();
        Environment.ExitCode = 2;
        return;
    }

    if (!OperatingSystem.IsWindows())
        throw new PlatformNotSupportedException("WFP testing is available only on Windows.");
    if (!WfpEngineManager.IsAdministrator())
        throw new UnauthorizedAccessException("Run this command from an elevated Administrator terminal.");

    string executablePath = Path.GetFullPath(args[1]);
    if (!File.Exists(executablePath))
        throw new FileNotFoundException("The target executable does not exist.", executablePath);

    string luidText = args[2];
    ulong luid;
    bool parsedLuid = luidText.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
        ? ulong.TryParse(luidText.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out luid) && luid > 0
        : ulong.TryParse(luidText, NumberStyles.None, CultureInfo.InvariantCulture, out luid) && luid > 0;
    if (!parsedLuid)
        throw new ArgumentException("Adapter LUID must be a non-zero decimal number or 0x-prefixed hexadecimal value.", nameof(args));

    int seconds = 120;
    if (args.Length == 4 && (!int.TryParse(args[3], NumberStyles.None, CultureInfo.InvariantCulture, out seconds) || seconds is < 1 or > 3600))
        throw new ArgumentException("Duration must be between 1 and 3600 seconds.", nameof(args));

    using var adapterProvider = new IpHelperAdapterProvider();
    AdapterInfo? adapter = adapterProvider.GetAdapters().FirstOrDefault(a => a.NetLuid == luid);
    if (adapter is null || !adapter.IsUpAndRoutable)
        throw new InvalidOperationException($"Adapter LUID 0x{luid:X} was not found as currently up and routable.");

    using var engine = new WfpEngineManager(dynamicSession: true);
    string appTag = $"APP:{executablePath.TrimEnd(Path.DirectorySeparatorChar).ToUpperInvariant()}";
    if (engine.ListSublayerFilters().Any(f => string.Equals(f.AppTag, appTag, StringComparison.Ordinal)))
        throw new InvalidOperationException("This executable already has filters in the NetworkIsolation sublayer. Refusing to replace an existing policy during a PoC run.");

    var policy = new NetworkPolicy(
        AppIdentity.Executable(executablePath),
        PolicyMode.Bind,
        [adapter.NetLuid],
        new PolicyOptions(AllowLoopback: true));

    engine.ApplyPolicy(policy, [adapter]);
    Console.WriteLine($"Temporary WFP policy active for: {executablePath}");
    Console.WriteLine($"Allowed adapter: {adapter.FriendlyName} (LUID 0x{adapter.NetLuid:X})");
    Console.WriteLine($"Rules expire automatically when this process exits; timeout: {seconds} seconds.");
    Console.WriteLine("Now generate TCP/UDP/IPv4/IPv6 traffic from that executable. Disconnect the selected adapter to verify traffic fails closed.");
    Console.WriteLine("This command filters traffic routed over other interfaces; it does not steer Windows routes.");
    Console.WriteLine("Press Ctrl+C to end the temporary WFP session early.");

    using var cancellation = new CancellationTokenSource();
    ConsoleCancelEventHandler cancelHandler = (_, eventArgs) =>
    {
        eventArgs.Cancel = true;
        cancellation.Cancel();
    };
    Console.CancelKeyPress += cancelHandler;
    try
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(seconds), cancellation.Token);
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            // Dynamic WFP filters are removed when engine.Dispose closes this session.
        }
    }
    finally
    {
        Console.CancelKeyPress -= cancelHandler;
    }

    Console.WriteLine("Closing temporary WFP session and removing its filters.");
    return;
}

if (command == "dns-probe")
{
    if (args.Length is < 3 or > 4)
    {
        PrintUsage();
        Environment.ExitCode = 2;
        return;
    }

    if (!OperatingSystem.IsWindows())
        throw new PlatformNotSupportedException("WFP testing is available only on Windows.");
    if (!WfpEngineManager.IsAdministrator())
        throw new UnauthorizedAccessException("Run this command from an elevated Administrator terminal.");

    ulong luid = ParseLuid(args[1]);
    string host = args[2];
    int port = 443;
    if (args.Length == 4 && (!int.TryParse(args[3], NumberStyles.None, CultureInfo.InvariantCulture, out port) || port is < 1 or > 65535))
        throw new ArgumentException("Port must be between 1 and 65535.", nameof(args));

    using var adapterProvider = new IpHelperAdapterProvider();
    AdapterInfo? adapter = adapterProvider.GetAdapters().FirstOrDefault(a => a.NetLuid == luid);
    if (adapter is null || !adapter.IsUpAndRoutable)
        throw new InvalidOperationException($"Adapter LUID 0x{luid:X} was not found as currently up and routable.");

    using var engine = new WfpEngineManager(dynamicSession: true);
    string executablePath = Path.GetFullPath(Environment.ProcessPath ?? throw new InvalidOperationException("Cannot identify the running PoC executable."));
    string appTag = $"APP:{executablePath.TrimEnd(Path.DirectorySeparatorChar).ToUpperInvariant()}";
    if (engine.ListSublayerFilters().Any(f => string.Equals(f.AppTag, appTag, StringComparison.Ordinal)))
        throw new InvalidOperationException("The PoC executable already has filters in the NetworkIsolation sublayer. Refusing to replace an existing policy.");

    var policy = new NetworkPolicy(
        AppIdentity.Executable(executablePath),
        PolicyMode.Bind,
        [adapter.NetLuid],
        new PolicyOptions(AllowLoopback: true));
    engine.ApplyPolicy(policy, [adapter]);

    Console.WriteLine($"Testing strict adapter-bound DNS and TCP connect for {host}:{port}");
    Console.WriteLine($"Adapter: {adapter.FriendlyName} (LUID 0x{adapter.NetLuid:X})");
    Console.WriteLine("The probe sends DNS queries directly to this adapter's configured DNS servers; it does not use the shared Windows DNS Client.");

    using TcpClient client = await AdapterBoundProxy.ConnectViaAdapterAsync(host, port, adapter, CancellationToken.None);
    Console.WriteLine($"Resolved and connected successfully: {client.Client.LocalEndPoint} -> {client.Client.RemoteEndPoint}");
    Console.WriteLine("The temporary WFP session will remove the probe filters when this command exits.");
    return;
}

PrintUsage();

static ulong ParseLuid(string text)
{
    bool parsed = text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
        ? ulong.TryParse(text.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong hex) && hex > 0
        : ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out ulong dec) && dec > 0;
    if (!parsed)
        throw new ArgumentException("Adapter LUID must be a non-zero decimal number or 0x-prefixed hexadecimal value.", nameof(text));
    return text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
        ? ulong.Parse(text.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture)
        : ulong.Parse(text, NumberStyles.None, CultureInfo.InvariantCulture);
}

static void PrintUsage()
{
    Console.WriteLine("NetworkIsolation Phase 2 proof of concept");
    Console.WriteLine("Commands:");
    Console.WriteLine("  adapters");
    Console.WriteLine("      List Windows network adapters and their NET_LUID values.");
    Console.WriteLine("  wfp-hold <executable-path> <adapter-luid> [seconds]");
    Console.WriteLine("      Apply temporary fail-closed filters (Administrator; default 120 seconds, maximum 3600).");
    Console.WriteLine("  dns-probe <adapter-luid> <hostname> [port]");
    Console.WriteLine("      Query DNS directly through the selected adapter, then make a TCP connection (Administrator; default port 443).");
}
