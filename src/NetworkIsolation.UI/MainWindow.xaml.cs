using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using NetworkIsolation.Core;
using NetworkIsolation.Wfp;

namespace NetworkIsolation.UI;

public partial class MainWindow : Window
{
    private readonly IpHelperAdapterProvider _adapterProvider = new();
    private readonly WfpEngineManager _wfp = new(dynamicSession: true);
    private readonly DispatcherTimer _refreshTimer = new() { Interval = TimeSpan.FromSeconds(5) };
    private readonly Dictionary<string, ulong?> _selectedByExecutable = new(StringComparer.OrdinalIgnoreCase);

    public ObservableCollection<AppRow> Apps { get; } = [];
    public ObservableCollection<AdapterChoice> Adapters { get; } = [];

    public MainWindow()
    {
        InitializeComponent();
        DataContext = this;
        _refreshTimer.Tick += (_, _) =>
        {
            if (!AppsGrid.IsKeyboardFocusWithin)
                RefreshSnapshot();
        };
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        RefreshSnapshot();
        _refreshTimer.Start();
        if (!WfpEngineManager.IsAdministrator())
            StatusText.Text = "Viewing is available normally. Run as Administrator to apply or remove rules.";
    }

    private void Refresh_Click(object sender, RoutedEventArgs e) => RefreshSnapshot();

    private void RefreshSnapshot()
    {
        try
        {
            var adapters = _adapterProvider.GetAdapters()
                .Where(a => !a.IsLoopback && a.IsUpAndRoutable)
                .OrderBy(a => a.FriendlyName, StringComparer.CurrentCultureIgnoreCase)
                .ToArray();

            Adapters.Clear();
            Adapters.Add(new AdapterChoice(null, "No rule"));
            foreach (AdapterInfo adapter in adapters)
                Adapters.Add(new AdapterChoice(adapter.NetLuid, $"{adapter.FriendlyName} ({adapter.OperStatus})"));

            var active = new Dictionary<string, List<(string Name, int Pid)>>(StringComparer.OrdinalIgnoreCase);
            foreach (Process process in Process.GetProcesses())
            {
                using (process)
                {
                    try
                    {
                        if (process.MainWindowHandle == 0)
                            continue;

                        string imagePath = process.MainModule?.FileName ?? string.Empty;
                        if (string.IsNullOrWhiteSpace(imagePath))
                            continue;
                        string path = Path.GetFullPath(imagePath);
                        if (!File.Exists(path))
                            continue;

                        if (!active.TryGetValue(path, out var instances))
                            active[path] = instances = [];
                        instances.Add((process.ProcessName, process.Id));
                    }
                    catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or UnauthorizedAccessException or NotSupportedException)
                    {
                        // Some protected or short-lived processes do not expose their image path.
                    }
                }
            }

            Apps.Clear();
            foreach (var entry in active.OrderBy(p => p.Value[0].Name, StringComparer.CurrentCultureIgnoreCase))
            {
                _selectedByExecutable.TryGetValue(entry.Key, out ulong? selectedLuid);
                Apps.Add(new AppRow(
                    Path.GetFileNameWithoutExtension(entry.Key),
                    entry.Key,
                    string.Join(", ", entry.Value.Select(p => p.Pid).Order()),
                    selectedLuid));
            }

            string elevationNote = WfpEngineManager.IsAdministrator() ? string.Empty : " · Run as Administrator to apply rules";
            StatusText.Text = $"{Apps.Count} applications · {adapters.Length} active adapters · rules clear when this window closes{elevationNote}.";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Could not refresh apps or adapters: {ex.Message}";
        }
    }

    private void Apply_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: AppRow row })
            return;
        if (!WfpEngineManager.IsAdministrator())
        {
            StatusText.Text = "To apply a network rule, close the app and choose Run as administrator.";
            return;
        }
        if (row.SelectedLuid is not ulong luid)
        {
            StatusText.Text = "Choose a network adapter first.";
            return;
        }

        try
        {
            AdapterInfo? adapter = _adapterProvider.GetAdapters().FirstOrDefault(a => a.NetLuid == luid && !a.IsLoopback && a.IsUpAndRoutable);
            if (adapter is null)
            {
                StatusText.Text = "That adapter is no longer available. Refresh the list and try again.";
                return;
            }

            var policy = new NetworkPolicy(
                AppIdentity.Executable(row.ExecutablePath),
                PolicyMode.Bind,
                [adapter.NetLuid],
                new PolicyOptions(AllowLoopback: true));
            _wfp.ApplyPolicy(policy, [adapter]);
            _selectedByExecutable[row.ExecutablePath] = adapter.NetLuid;
            row.AppliedLuid = adapter.NetLuid;
            row.SelectedLuid = adapter.NetLuid;
            StatusText.Text = $"{row.DisplayName} is allowed on {adapter.FriendlyName}. If Windows routes it over another adapter, its connection will be blocked.";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Could not apply rule: {ex.Message}";
        }
    }

    private void Remove_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: AppRow row })
            return;
        if (!WfpEngineManager.IsAdministrator())
        {
            StatusText.Text = "To remove a network rule, close the app and choose Run as administrator.";
            return;
        }

        try
        {
            _wfp.RemoveAppPolicy(AppIdentity.Executable(row.ExecutablePath));
            _selectedByExecutable.Remove(row.ExecutablePath);
            row.AppliedLuid = null;
            row.SelectedLuid = null;
            StatusText.Text = $"Removed the network rule for {row.DisplayName}.";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Could not remove rule: {ex.Message}";
        }
    }

    private void Window_Closed(object? sender, EventArgs e)
    {
        _refreshTimer.Stop();
        _adapterProvider.Dispose();
        _wfp.Dispose();
    }
}

public sealed record AdapterChoice(ulong? NetLuid, string DisplayName);

public sealed class AppRow : INotifyPropertyChanged
{
    private ulong? _selectedLuid;
    private ulong? _appliedLuid;

    public string DisplayName { get; }
    public string ExecutablePath { get; }
    public string ProcessIdsText { get; }
    public string RuleStatus => AppliedLuid is null ? "No rule" : "Rule active";

    public ulong? AppliedLuid
    {
        get => _appliedLuid;
        set
        {
            if (_appliedLuid == value)
                return;
            _appliedLuid = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(AppliedLuid)));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(RuleStatus)));
        }
    }

    public ulong? SelectedLuid
    {
        get => _selectedLuid;
        set
        {
            if (_selectedLuid == value)
                return;
            _selectedLuid = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SelectedLuid)));
        }
    }

    public AppRow(string displayName, string executablePath, string processIdsText, ulong? selectedLuid)
    {
        DisplayName = displayName;
        ExecutablePath = executablePath;
        ProcessIdsText = processIdsText;
        _selectedLuid = selectedLuid;
        _appliedLuid = selectedLuid;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}
