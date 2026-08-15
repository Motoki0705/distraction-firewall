using DistractionFirewall.ActivationService;
using DistractionFirewall.Contracts;
using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Core.Leases;
using DistractionFirewall.Core.Persistence;
using DistractionFirewall.Core.Targets;
using DistractionFirewall.Core.Time;

namespace DistractionFirewall.LeaseLifecycleTests;

internal sealed class TestWorkspace : IDisposable
{
    public TestWorkspace()
    {
        RootPath = Path.Combine(
            Path.GetTempPath(),
            "distraction-firewall-tests",
            Guid.NewGuid().ToString("N"));
        Store = new FileLeaseCapsuleStore(RootPath);
    }

    public string RootPath { get; }

    public FileLeaseCapsuleStore Store { get; }

    public void Dispose()
    {
        var testRoot = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "distraction-firewall-tests")) +
            Path.DirectorySeparatorChar;
        var resolved = Path.GetFullPath(RootPath);
        if (!resolved.StartsWith(testRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"Refusing to remove unexpected test path '{resolved}'.");
        }

        if (Directory.Exists(resolved))
        {
            Directory.Delete(resolved, recursive: true);
        }

        GC.SuppressFinalize(this);
    }
}

internal sealed class ActivationHarness : IDisposable
{
    public ActivationHarness(IEnforcementAdapter? adapter = null)
    {
        Workspace = new TestWorkspace();
        Time = new MutableTimeAuthority(TestData.Now);
        Adapter = adapter ?? new InProcessEnforcementAdapter();
        var runtime = new LeaseRuntimeCoordinator(Workspace.Store, [Adapter], Time);
        var launcher = new DelegateLeaseWorkerLauncher(
            (leaseId, _) =>
            {
                LaunchedLeaseIds.Add(leaseId);
                if (CancelLaunch)
                {
                    return Task.FromException<LeaseWorkerLaunchResult>(new OperationCanceledException());
                }

                return Task.FromResult(new LeaseWorkerLaunchResult(
                    LaunchSucceeds,
                    LaunchSucceeds ? "started" : "launch failed"));
            },
            _ => Task.FromResult(new LeaseWorkerLaunchResult(
                LauncherHealthy,
                LauncherHealthy ? "healthy" : "unavailable")));
        Coordinator = new LeaseActivationCoordinator(
            TestData.Catalog(),
            Workspace.Store,
            runtime,
            Time,
            new LeaseNonceService(Enumerable.Range(1, 32).Select(value => (byte)value).ToArray()),
            launcher);
    }

    public TestWorkspace Workspace { get; }

    public MutableTimeAuthority Time { get; }

    public IEnforcementAdapter Adapter { get; }

    public LeaseActivationCoordinator Coordinator { get; }

    public List<Guid> LaunchedLeaseIds { get; } = [];

    public bool LauncherHealthy { get; set; } = true;

    public bool LaunchSucceeds { get; set; } = true;

    public bool CancelLaunch { get; set; }

    public void Dispose()
    {
        Workspace.Dispose();
        GC.SuppressFinalize(this);
    }
}

internal sealed class MutableTimeAuthority : ITimeAuthority
{
    public MutableTimeAuthority(DateTimeOffset utcNow)
    {
        Snapshot = new TimeSnapshot(utcNow, "test-boot", MonotonicTicks: 0, MonotonicFrequency: 1000);
    }

    public TimeSnapshot Snapshot { get; private set; }

    public TimeSnapshot Capture() => Snapshot;

    public void Advance(TimeSpan elapsed)
    {
        Snapshot = Snapshot with
        {
            UtcNow = Snapshot.UtcNow.Add(elapsed),
            MonotonicTicks = checked(Snapshot.MonotonicTicks +
                (long)(elapsed.TotalSeconds * Snapshot.MonotonicFrequency)),
        };
    }
}

internal static class TestData
{
    public static readonly DateTimeOffset Now = new(2026, 8, 15, 0, 0, 0, TimeSpan.Zero);

    public static TargetDefinition Target(string stableId = "youtube") => new()
    {
        StableId = stableId,
        DisplayName = "YouTube",
        CatalogVersion = "1.0.0",
        ExactHosts = ["youtu.be"],
        SuffixHosts = ["youtube.com"],
        CnameSuffixes = ["youtube-ui.l.google.com"],
        BrowserUrlPatterns = ["*://*.youtube.com/*"],
        IpBlockPolicy = new IpBlockPolicyDefinition
        {
            Mode = IpBlockMode.Disabled,
        },
        KnownCollateral = Array.Empty<KnownCollateralDefinition>(),
        Coverage = ["web"],
    };

    public static TargetCatalog Catalog() => new([Target()]);

    public static PreparedLease Preparation(
        Guid? preparationId = null,
        Guid? requestId = null) => new()
        {
            PreparationId = preparationId ?? Guid.NewGuid(),
            RequestId = requestId ?? Guid.NewGuid(),
            RequestFingerprint = "prepare-fingerprint",
            NonceHash = new string('a', 64),
            PreparedAtUtc = Now,
            PreparationExpiresAtUtc = Now.AddMinutes(2),
            ResolvedExpiresAtUtc = Now.AddHours(1),
            RequestedDuration = TimeSpan.FromHours(1),
            TargetSnapshot = [Target()],
            RuleHash = "rule-hash",
        };

    public static LeaseManifest Manifest(
        Guid leaseId,
        DateTimeOffset? expiresAtUtc = null,
        TimeSpan? requestedDuration = null) => new()
        {
            SchemaVersion = LeaseManifest.CurrentSchemaVersion,
            LeaseId = leaseId,
            TargetSnapshot = [Target()],
            RuleHash = "rule-hash",
            CreatedAtUtc = Now,
            ActivatedAtUtc = Now,
            ExpiresAtUtc = expiresAtUtc ?? Now.AddHours(1),
            RequestedDuration = requestedDuration ?? TimeSpan.FromHours(1),
            BootId = "test-boot",
            MonotonicAnchorTicks = 0,
            MonotonicFrequency = 1000,
            InstallIntent = RuntimeInstallIntent.Keep,
            PreparationId = Guid.NewGuid(),
            PrepareRequestId = Guid.NewGuid(),
            CommitRequestId = Guid.NewGuid(),
            CommitRequestFingerprint = "commit-fingerprint",
        };

    public static LeaseRuntimeState State(Guid leaseId, LeaseState state, long sequence = 0) => new()
    {
        LeaseId = leaseId,
        State = state,
        Sequence = sequence,
        UpdatedAtUtc = Now,
        LastHeartbeatUtc = Now,
        Health = state == LeaseState.Active ? LeaseHealth.Healthy : LeaseHealth.Unknown,
        AppInstallState = AppInstallState.Installed,
        RuntimeInstallIntent = RuntimeInstallIntent.Keep,
        RuntimeInstallState = RuntimeInstallState.Installed,
    };
}
