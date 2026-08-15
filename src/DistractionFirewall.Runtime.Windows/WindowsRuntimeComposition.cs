using System.Security.Principal;
using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Core.Leases;
using DistractionFirewall.Core.Persistence;
using DistractionFirewall.Core.Time;
using DistractionFirewall.Enforcement.Windows;
using DistractionFirewall.Enforcement.Windows.Dns;

namespace DistractionFirewall.Runtime.Windows;

public sealed class WindowsRuntimeComposition : IDisposable
{
    private readonly IDisposable[] _liveAdapters;
    private bool _disposed;

    private WindowsRuntimeComposition(
        RuntimePaths paths,
        RuntimeSettings settings,
        FileLeaseCapsuleStore store,
        WindowsBootTimeAuthority timeAuthority,
        IDisposable[] liveAdapters,
        LeaseRuntimeCoordinator runtime)
    {
        Paths = paths;
        Settings = settings;
        Store = store;
        TimeAuthority = timeAuthority;
        _liveAdapters = liveAdapters;
        Runtime = runtime;
    }

    public RuntimePaths Paths { get; }

    public RuntimeSettings Settings { get; }

    public FileLeaseCapsuleStore Store { get; }

    public WindowsBootTimeAuthority TimeAuthority { get; }

    public LeaseRuntimeCoordinator Runtime { get; }

    public static WindowsRuntimeComposition CreateLive(
        RuntimePaths paths,
        RuntimeSettings settings,
        bool requireLocalSystem)
    {
        ArgumentNullException.ThrowIfNull(paths);
        settings = RuntimeSettingsLoader.Validate(settings);
        RuntimePathResolver.DemandLiveMutationPrerequisites(paths);
        DemandPrivilegedIdentity(requireLocalSystem);

        var store = new FileLeaseCapsuleStore(paths.LeaseStoreDirectory);
        var timeAuthority = new WindowsBootTimeAuthority(new NativeWindowsBootIdentifierSource());
        var observedAddressStore = new FileDnsObservedAddressStore(
            paths.DnsObservationStorePath,
            paths.DnsObservedAddressesPath);
        observedAddressStore.EnsureCreatedAsync(CancellationToken.None)
            .AsTask().GetAwaiter().GetResult();
        var addressSource = new WindowsObservedAddressSource(observedAddressStore);
        var targetSnapshotStore = new ProtectedLeaseTargetSnapshotStore(
            paths.DnsDataDirectory,
            paths.DnsTargetSnapshotPath);
        targetSnapshotStore.EnsureInactivePlaceholder();
        var seeder = new WindowsDnsUpstreamObservationSeeder(
            observedAddressStore,
            new ExplicitDnsSeedResolver(new SocketExplicitDnsQueryTransport()));
        LeaseTargetSnapshotDnsEnforcementAdapter? dnsAdapter = null;
        WindowsEnforcementAdapter? windowsAdapter = null;
        try
        {
            dnsAdapter = new LeaseTargetSnapshotDnsEnforcementAdapter(
                WindowsDnsEnforcementFactory.CreateLiveWindowsDns(new LiveWindowsDnsEnforcementOptions
                {
                    ProductInstanceId = settings.ProductInstanceId,
                    OwnershipLedgerDirectory = paths.OwnershipLedgerDirectory,
                    DnsFilterExecutablePath = paths.DnsFilterExecutablePath,
                    TargetSnapshotPath = paths.DnsTargetSnapshotPath,
                    ObservationStorePath = paths.DnsObservedAddressesPath,
                    ObservationSeeder = seeder,
                }),
                targetSnapshotStore);
            windowsAdapter = WindowsEnforcementFactory.CreateLiveWindows(new LiveWindowsEnforcementOptions
            {
                ProductInstanceId = settings.ProductInstanceId,
                OwnershipLedgerDirectory = paths.OwnershipLedgerDirectory,
                WorkerExecutablePath = paths.WorkerExecutablePath,
                ObservedAddressSource = addressSource,
            });
            var runtime = new LeaseRuntimeCoordinator(
                store,
                new IEnforcementAdapter[] { dnsAdapter, windowsAdapter },
                timeAuthority);
            return new WindowsRuntimeComposition(
                paths,
                settings,
                store,
                timeAuthority,
                [dnsAdapter, windowsAdapter],
                runtime);
        }
        catch
        {
            windowsAdapter?.Dispose();
            dnsAdapter?.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        Exception? firstFailure = null;
        foreach (var adapter in _liveAdapters.Reverse())
        {
            try
            {
                adapter.Dispose();
            }
            catch (Exception exception)
            {
                firstFailure ??= exception;
            }
        }
        _disposed = true;
        GC.SuppressFinalize(this);
        if (firstFailure is not null)
        {
            throw new InvalidOperationException(
                "One or more live enforcement adapters failed to dispose.",
                firstFailure);
        }
    }

    private static void DemandPrivilegedIdentity(bool requireLocalSystem)
    {
        using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        var user = identity.User
            ?? throw new UnauthorizedAccessException("The runtime process token has no user SID.");
        if (requireLocalSystem)
        {
            if (!user.IsWellKnown(WellKnownSidType.LocalSystemSid))
            {
                throw new UnauthorizedAccessException("This runtime host must execute as LocalSystem.");
            }

            return;
        }

        var principal = new WindowsPrincipal(identity);
        if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
        {
            throw new UnauthorizedAccessException(
                "Console live mode requires an elevated Administrators token.");
        }
    }
}
