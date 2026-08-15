using System.Globalization;
using System.Security.Cryptography;
using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Enforcement.Windows.Mutation;
using DistractionFirewall.Enforcement.Windows.Ownership;

namespace DistractionFirewall.Enforcement.Windows.Dns;

public sealed class WindowsDnsEnforcementAdapter :
    IEnforcementReconciliationAdapter,
    IWindowsPrimaryBlockingAdapter,
    IWindowsIncrementalArtifactAdapter,
    IDisposable
{
    private const int ArtifactSchemaVersion = 2;
    private const string FilterTaskProperty = "filter_task";
    private const string FilterTaskRecordsProperty = "filter_task_records";
    private const string ReadyTokenProperty = "ready_token";

    private readonly IWindowsDnsSettingsStore _dnsStore;
    private readonly IDnsFilterLauncher _filterLauncher;
    private readonly IDnsFilterReadyProbe _readyProbe;
    private readonly IWindowsDnsUpstreamObservationSeeder _observationSeeder;
    private readonly OwnedMutationCoordinator _coordinator;
    private readonly IOwnershipLedger _ledger;
    private readonly WindowsMutationGate _mutationGate;
    private readonly string _targetSnapshotPath;
    private readonly string _observationStorePath;
    private readonly TimeSpan _readyTimeout;
    private readonly IDisposable? _ownedLifetime;
    private bool _disposed;

    internal WindowsDnsEnforcementAdapter(
        IWindowsDnsSettingsStore dnsStore,
        IDnsFilterLauncher filterLauncher,
        IDnsFilterReadyProbe readyProbe,
        IWindowsDnsUpstreamObservationSeeder observationSeeder,
        OwnedMutationCoordinator coordinator,
        IOwnershipLedger ledger,
        WindowsMutationGate mutationGate,
        string targetSnapshotPath,
        string observationStorePath,
        TimeSpan readyTimeout,
        IDisposable? ownedLifetime = null)
    {
        _dnsStore = dnsStore ?? throw new ArgumentNullException(nameof(dnsStore));
        _filterLauncher = filterLauncher ?? throw new ArgumentNullException(nameof(filterLauncher));
        _readyProbe = readyProbe ?? throw new ArgumentNullException(nameof(readyProbe));
        _observationSeeder = observationSeeder ?? throw new ArgumentNullException(nameof(observationSeeder));
        _coordinator = coordinator ?? throw new ArgumentNullException(nameof(coordinator));
        _ledger = ledger ?? throw new ArgumentNullException(nameof(ledger));
        _mutationGate = mutationGate ?? throw new ArgumentNullException(nameof(mutationGate));
        DnsFilterTaskDefinitionBuilder.ValidateDataPath(targetSnapshotPath, nameof(targetSnapshotPath));
        DnsFilterTaskDefinitionBuilder.ValidateDataPath(observationStorePath, nameof(observationStorePath));
        _targetSnapshotPath = Path.GetFullPath(targetSnapshotPath);
        _observationStorePath = Path.GetFullPath(observationStorePath);
        if (readyTimeout <= TimeSpan.Zero || readyTimeout > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentOutOfRangeException(
                nameof(readyTimeout),
                "DNS filter readiness timeout must be greater than zero and no more than one minute.");
        }

        _readyTimeout = readyTimeout;
        _ownedLifetime = ownedLifetime;
    }

    public string AdapterId => "windows-dns-loopback";

    public Task<EnforcementHealth> CheckHealthAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        if (!_mutationGate.IsEnabled)
        {
            return Task.FromResult(new EnforcementHealth(
                AdapterId,
                Available: false,
                Healthy: false,
                "Live Windows mutation was not explicitly enabled."));
        }

        var dnsAvailable = _dnsStore.CheckAvailable(out var dnsSummary);
        var launcherAvailable = _filterLauncher.CheckAvailable(out var launcherSummary);
        return Task.FromResult(new EnforcementHealth(
            AdapterId,
            Available: dnsAvailable && launcherAvailable,
            Healthy: dnsAvailable && launcherAvailable,
            dnsSummary + " " + launcherSummary));
    }

    public async Task<EnforcementArtifact> ApplyAsync(
        EnforcementContext context,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(context);
        _mutationGate.Demand();

        var initial = await _dnsStore.EnumerateActiveAsync(cancellationToken).ConfigureAwait(false);
        ValidateMutationSnapshots(initial);
        var readyToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        var taskRecords = new List<string>();
        var ownedDnsRecords = new List<string>();
        DnsFilterLaunchResult? filterTask = null;
        IReadOnlyList<DnsInterfaceSettingsState>? readySnapshots = null;
        try
        {
            (filterTask, readySnapshots) = await ConvergeFilterUpstreamsAsync(
                context,
                readyToken,
                initial,
                new Dictionary<string, OwnershipMutationRecord>(StringComparer.Ordinal),
                taskRecords,
                cancellationToken).ConfigureAwait(false);
            await SeedUpstreamObservationsAsync(context, readySnapshots, cancellationToken).ConfigureAwait(false);
            await ApplySnapshotsAsync(context.LeaseId, readySnapshots, ownedDnsRecords, cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            await RestoreDnsRecordsBestEffortAsync(ownedDnsRecords).ConfigureAwait(false);
            await RestoreFilterTasksBestEffortAsync(taskRecords).ConfigureAwait(false);

            throw;
        }

        return CreateArtifact(
            ownedDnsRecords,
            filterTask ?? throw new InvalidOperationException("DNS filter task was not created."),
            taskRecords,
            readyToken,
            activeCount: readySnapshots?.Count ?? 0,
            reconcileGeneration: 0);
    }

    public async Task<EnforcementArtifact> ReconcileAsync(
        EnforcementContext context,
        EnforcementArtifact existingArtifact,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(context);
        ValidateArtifact(existingArtifact);
        _mutationGate.Demand();

        var existingResources = await GetOwnedDnsResourcesAsync(existingArtifact, cancellationToken)
            .ConfigureAwait(false);
        var allTaskRecords = ParseTaskRecordIds(existingArtifact);
        var originalTaskRecordCount = allTaskRecords.Count;
        var readyToken = existingArtifact.Properties[ReadyTokenProperty];
        DnsFilterTaskDefinitionBuilder.ValidateReadyToken(readyToken);
        var initial = await _dnsStore.EnumerateActiveAsync(cancellationToken).ConfigureAwait(false);
        ValidateMutationSnapshots(initial);
        var newlyOwnedRecords = new List<string>();
        DnsFilterLaunchResult? filterTask = null;
        IReadOnlyList<DnsInterfaceSettingsState>? readySnapshots = null;
        try
        {
            (filterTask, readySnapshots) = await ConvergeFilterUpstreamsAsync(
                context,
                readyToken,
                initial,
                existingResources,
                allTaskRecords,
                cancellationToken).ConfigureAwait(false);
            await SeedUpstreamObservationsAsync(context, readySnapshots, cancellationToken).ConfigureAwait(false);
            foreach (var snapshot in readySnapshots.OrderBy(CreateResourceId, StringComparer.Ordinal))
            {
                var resourceId = CreateResourceId(snapshot);
                if (existingResources.TryGetValue(resourceId, out var record))
                {
                    var current = await _dnsStore.ReadAsync(resourceId, cancellationToken).ConfigureAwait(false);
                    if (!_dnsStore.StatesEqual(current, record.DesiredState))
                    {
                        throw new OwnershipConflictException(
                            resourceId,
                            "An owned DNS setting changed; reconciliation refused to overwrite foreign state.");
                    }

                    continue;
                }

                if (IsLoopback(snapshot))
                {
                    continue;
                }

                await ApplySnapshotAsync(
                    context.LeaseId,
                    snapshot,
                    newlyOwnedRecords,
                    cancellationToken).ConfigureAwait(false);
            }
        }
        catch
        {
            await RestoreDnsRecordsBestEffortAsync(newlyOwnedRecords).ConfigureAwait(false);
            var newlyOwnedTaskRecords = allTaskRecords.Skip(originalTaskRecordCount).ToArray();
            await RestoreFilterTasksBestEffortAsync(newlyOwnedTaskRecords).ConfigureAwait(false);
            if (originalTaskRecordCount > 0)
            {
                await ProbeBestEffortAsync(context.LeaseId, readyToken).ConfigureAwait(false);
            }

            throw;
        }

        var mergedRecords = existingArtifact.OwnedResourceIds
            .Concat(newlyOwnedRecords)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var generation = int.Parse(
            existingArtifact.Properties["reconcile_generation"],
            NumberStyles.None,
            CultureInfo.InvariantCulture) + 1;
        return CreateArtifact(
            mergedRecords,
            filterTask ?? throw new InvalidOperationException("DNS filter task was not reconciled."),
            allTaskRecords,
            readyToken,
            readySnapshots?.Count ?? 0,
            generation);
    }

    public async Task<EnforcementVerification> VerifyAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(context);
        ValidateArtifact(artifact);

        try
        {
            await _readyProbe.WaitUntilReadyAsync(
                new DnsFilterReadinessRequest(context.LeaseId, artifact.Properties[ReadyTokenProperty]),
                _readyTimeout,
                cancellationToken).ConfigureAwait(false);
            var snapshots = await _dnsStore.EnumerateActiveAsync(cancellationToken).ConfigureAwait(false);
            var verified = snapshots.Count > 0 && snapshots.All(IsLoopback);
            return new EnforcementVerification(
                AdapterId,
                TargetBlocked: verified,
                GeneralConnectivityAvailable: true,
                verified
                    ? "All active adapter families use the ready loopback DNS filter."
                    : "An active adapter family is not using loopback DNS; reconciliation is required.");
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return new EnforcementVerification(
                AdapterId,
                TargetBlocked: false,
                GeneralConnectivityAvailable: false,
                "DNS filter verification failed: " + exception.Message);
        }
    }

    public EnforcementArtifact MergeReconciledArtifact(
        EnforcementArtifact existingArtifact,
        EnforcementArtifact reconciledArtifact)
    {
        ValidateArtifact(existingArtifact);
        ValidateArtifact(reconciledArtifact);
        if (!string.Equals(
                existingArtifact.Properties[ReadyTokenProperty],
                reconciledArtifact.Properties[ReadyTokenProperty],
                StringComparison.Ordinal)
            || !string.Equals(
                existingArtifact.Properties[FilterTaskProperty],
                reconciledArtifact.Properties[FilterTaskProperty],
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("DNS reconciliation replaced the lease-bound filter identity.");
        }

        var reconciledDnsRecords = reconciledArtifact.OwnedResourceIds.ToHashSet(StringComparer.Ordinal);
        if (existingArtifact.OwnedResourceIds.Any(recordId => !reconciledDnsRecords.Contains(recordId)))
        {
            throw new InvalidDataException("DNS reconciliation discarded an existing ownership record.");
        }

        var reconciledTaskRecords = ParseTaskRecordIds(reconciledArtifact).ToHashSet(StringComparer.Ordinal);
        if (ParseTaskRecordIds(existingArtifact).Any(recordId => !reconciledTaskRecords.Contains(recordId)))
        {
            throw new InvalidDataException("DNS reconciliation discarded an existing task ownership record.");
        }

        return reconciledArtifact;
    }

    public EnforcementArtifact? CreateRollbackArtifact(
        EnforcementArtifact existingArtifact,
        EnforcementArtifact reconciledArtifact)
    {
        _ = MergeReconciledArtifact(existingArtifact, reconciledArtifact);
        var existingDnsRecords = existingArtifact.OwnedResourceIds.ToHashSet(StringComparer.Ordinal);
        var newDnsRecords = reconciledArtifact.OwnedResourceIds
            .Where(recordId => !existingDnsRecords.Contains(recordId))
            .ToArray();
        var existingTaskRecords = ParseTaskRecordIds(existingArtifact).ToHashSet(StringComparer.Ordinal);
        var newTaskRecords = ParseTaskRecordIds(reconciledArtifact)
            .Where(recordId => !existingTaskRecords.Contains(recordId))
            .ToArray();
        if (newDnsRecords.Length == 0 && newTaskRecords.Length == 0)
        {
            return null;
        }

        var rollbackProperties = new Dictionary<string, string>(
            reconciledArtifact.Properties,
            StringComparer.Ordinal)
        {
            [FilterTaskRecordsProperty] = string.Join(',', newTaskRecords),
        };
        return reconciledArtifact with
        {
            OwnedResourceIds = newDnsRecords,
            Properties = rollbackProperties,
        };
    }

    public async Task<RestoreResult> RestoreAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(context);
        ValidateArtifact(artifact);
        _mutationGate.Demand();

        var failures = 0;
        var conflicts = 0;
        foreach (var recordId in artifact.OwnedResourceIds.Reverse())
        {
            try
            {
                var result = await _coordinator.RestoreAsync(_dnsStore, recordId, cancellationToken)
                    .ConfigureAwait(false);
                failures += result.Restored ? 0 : 1;
                conflicts += result.Conflict ? 1 : 0;
            }
            catch when (!cancellationToken.IsCancellationRequested)
            {
                failures++;
            }
        }

        if (failures == 0)
        {
            foreach (var taskRecord in ParseTaskRecordIds(artifact).AsEnumerable().Reverse())
            {
                try
                {
                    var result = await _filterLauncher.RestoreTaskAsync(taskRecord, cancellationToken)
                        .ConfigureAwait(false);
                    failures += result is null || result.Restored ? 0 : 1;
                    conflicts += result?.Conflict == true ? 1 : 0;
                }
                catch when (!cancellationToken.IsCancellationRequested)
                {
                    failures++;
                }
            }
        }

        return new RestoreResult(
            AdapterId,
            Restored: failures == 0,
            Retryable: failures > 0,
            failures == 0
                ? "Owned static DNS settings and the per-lease task were restored by compare-and-swap."
                : $"Restore retained {failures} resources, including {conflicts} ownership conflicts.");
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _ownedLifetime?.Dispose();
        _disposed = true;
    }

    private static void ValidateMutationSnapshots(IReadOnlyList<DnsInterfaceSettingsState> snapshots)
    {
        if (snapshots.Count == 0)
        {
            throw new InvalidOperationException("No active adapter DNS families with nameservers were found.");
        }

        var duplicate = snapshots
            .GroupBy(CreateResourceId, StringComparer.Ordinal)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicate is not null)
        {
            throw new InvalidDataException($"Duplicate DNS snapshot '{duplicate.Key}' was returned.");
        }

        var unsafeSnapshot = snapshots.FirstOrDefault(snapshot =>
            snapshot.Origin == DnsConfigurationOrigin.Unknown || snapshot.NameServers.Count == 0);
        if (unsafeSnapshot is not null)
        {
            throw new InvalidOperationException(
                $"DNS mutation for '{CreateResourceId(unsafeSnapshot)}' was refused because its origin " +
                $"is '{unsafeSnapshot.Origin}'. Profile/ambiguous DNS configuration remains fail-closed.");
        }
    }

    private async Task ApplySnapshotsAsync(
        Guid leaseId,
        IEnumerable<DnsInterfaceSettingsState> snapshots,
        ICollection<string> ownedRecords,
        CancellationToken cancellationToken)
    {
        foreach (var snapshot in snapshots.OrderBy(CreateResourceId, StringComparer.Ordinal))
        {
            await ApplySnapshotAsync(leaseId, snapshot, ownedRecords, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task ApplySnapshotAsync(
        Guid leaseId,
        DnsInterfaceSettingsState snapshot,
        ICollection<string> ownedRecords,
        CancellationToken cancellationToken)
    {
        var resourceId = CreateResourceId(snapshot);
        var expected = DnsSettingsStateCodec.Encode(snapshot);
        var desired = DnsSettingsStateCodec.Encode(
            DnsSettingsStateCodec.CreateLoopback(snapshot.InterfaceId, snapshot.AddressFamily));
        var snapshotBoundStore = new SnapshotBoundDnsStore(_dnsStore, resourceId, expected);
        var result = await _coordinator.ApplyAsync(
            snapshotBoundStore,
            AdapterId,
            leaseId,
            resourceId,
            desired,
            failIfPresent: false,
            cancellationToken).ConfigureAwait(false);
        if (result.Owned && result.RecordId is not null)
        {
            ownedRecords.Add(result.RecordId);
        }
    }

    private async Task<IReadOnlyDictionary<string, OwnershipMutationRecord>> GetOwnedDnsResourcesAsync(
        EnforcementArtifact artifact,
        CancellationToken cancellationToken)
    {
        var records = new Dictionary<string, OwnershipMutationRecord>(StringComparer.Ordinal);
        foreach (var recordId in artifact.OwnedResourceIds)
        {
            var record = await _ledger.GetAsync(recordId, cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidDataException($"DNS ownership record '{recordId}' is missing.");
            if (!string.Equals(record.AdapterId, AdapterId, StringComparison.Ordinal)
                || !record.ResourceId.StartsWith("dns-interface:", StringComparison.Ordinal))
            {
                throw new InvalidDataException($"Ownership record '{recordId}' is not a DNS adapter record.");
            }

            if (!records.TryAdd(record.ResourceId, record))
            {
                throw new InvalidDataException("DNS artifact contains duplicate owned resources.");
            }
        }

        return records;
    }

    private EnforcementArtifact CreateArtifact(
        IReadOnlyList<string> ownedDnsRecords,
        DnsFilterLaunchResult filterTask,
        IReadOnlyList<string> filterTaskRecords,
        string readyToken,
        int activeCount,
        int reconcileGeneration)
    {
        return new EnforcementArtifact(
            AdapterId,
            ArtifactSchemaVersion,
            ownedDnsRecords,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [FilterTaskProperty] = filterTask.TaskResourceId,
                [FilterTaskRecordsProperty] = string.Join(',', filterTaskRecords),
                [ReadyTokenProperty] = readyToken,
                ["active_interface_family_count"] = activeCount.ToString(CultureInfo.InvariantCulture),
                ["snapshot_origin_policy"] = "static-or-dhcp-profile-fail-closed",
                ["dhcp_upstream_refresh"] = "initial-or-new-interface-snapshot-only",
                ["reconcile_generation"] = reconcileGeneration.ToString(CultureInfo.InvariantCulture),
            });
    }

    private static string CreateResourceId(DnsInterfaceSettingsState snapshot)
    {
        return new DnsInterfaceResourceId(snapshot.InterfaceId, snapshot.AddressFamily).ToString();
    }

    private static bool IsLoopback(DnsInterfaceSettingsState snapshot)
    {
        var expected = DnsSettingsStateCodec.CreateLoopback(snapshot.InterfaceId, snapshot.AddressFamily);
        return DnsSettingsStateCodec.Equivalent(
            DnsSettingsStateCodec.Encode(snapshot),
            DnsSettingsStateCodec.Encode(expected));
    }

    private DnsFilterLaunchRequest CreateLaunchRequest(
        EnforcementContext context,
        string readyToken,
        IReadOnlyList<string> upstreamNameServers)
    {
        return new DnsFilterLaunchRequest(
            context.LeaseId,
            context.ExpiresAtUtc,
            _targetSnapshotPath,
            _observationStorePath,
            readyToken,
            upstreamNameServers);
    }

    private async Task<(DnsFilterLaunchResult FilterTask, IReadOnlyList<DnsInterfaceSettingsState> Snapshots)>
        ConvergeFilterUpstreamsAsync(
            EnforcementContext context,
            string readyToken,
            IReadOnlyList<DnsInterfaceSettingsState> initialSnapshots,
            IReadOnlyDictionary<string, OwnershipMutationRecord> existingResources,
            List<string> filterTaskRecords,
            CancellationToken cancellationToken)
    {
        var snapshots = initialSnapshots;
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var upstreams = BuildFilterUpstreams(snapshots, existingResources);
            var expectedTaskRecord = filterTaskRecords.LastOrDefault();
            var filterTask = await _filterLauncher.EnsureStartedAsync(
                CreateLaunchRequest(context, readyToken, upstreams),
                expectedTaskRecord,
                cancellationToken).ConfigureAwait(false);
            if (filterTask.OwnershipRecordId is not null
                && !filterTaskRecords.Contains(filterTask.OwnershipRecordId, StringComparer.Ordinal))
            {
                filterTaskRecords.Add(filterTask.OwnershipRecordId);
            }

            await _readyProbe.WaitUntilReadyAsync(
                new DnsFilterReadinessRequest(context.LeaseId, readyToken),
                _readyTimeout,
                cancellationToken).ConfigureAwait(false);
            var current = await _dnsStore.EnumerateActiveAsync(cancellationToken).ConfigureAwait(false);
            ValidateMutationSnapshots(current);
            var currentUpstreams = BuildFilterUpstreams(current, existingResources);
            if (upstreams.SequenceEqual(currentUpstreams, StringComparer.OrdinalIgnoreCase))
            {
                return (filterTask, current);
            }

            snapshots = current;
        }

        throw new InvalidOperationException(
            "Active DNS upstreams did not stabilize after three task CAS/restart attempts.");
    }

    private static string[] BuildFilterUpstreams(
        IReadOnlyList<DnsInterfaceSettingsState> snapshots,
        IReadOnlyDictionary<string, OwnershipMutationRecord> existingResources)
    {
        // Once an owned DHCP family is overridden with loopback, documented interface APIs expose
        // only that effective/static override, not the latent DHCP lease resolver list. Preserve
        // the initial owned snapshot and add current resolvers from newly active families. Never
        // invent a public-resolver fallback; a changed DHCP lease is an alpha live-VM limitation.
        var activeResources = snapshots.Select(CreateResourceId).ToHashSet(StringComparer.Ordinal);
        var candidates = snapshots
            .Where(snapshot => !IsLoopback(snapshot))
            .SelectMany(snapshot => snapshot.NameServers)
            .Concat(existingResources.Values
                .Where(record => activeResources.Contains(record.ResourceId) && record.OriginalState.Exists)
                .Select(record => DnsSettingsStateCodec.Decode(record.OriginalState))
                .Where(original => original.Origin != DnsConfigurationOrigin.Unknown && !IsLoopback(original))
                .SelectMany(original => original.NameServers))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return DnsFilterTaskDefinitionBuilder.NormalizeUpstreams(candidates);
    }

    private Task SeedUpstreamObservationsAsync(
        EnforcementContext context,
        IReadOnlyList<DnsInterfaceSettingsState> snapshots,
        CancellationToken cancellationToken)
    {
        var upstreams = snapshots
            .Where(snapshot => !IsLoopback(snapshot))
            .Select(snapshot => new WindowsDnsUpstreamServerSet(
                snapshot.InterfaceId,
                snapshot.AddressFamily == DnsAddressFamily.IPv4 ? "ipv4" : "ipv6",
                snapshot.NameServers.ToArray()))
            .ToArray();
        if (upstreams.Length == 0)
        {
            return Task.CompletedTask;
        }

        return _observationSeeder.SeedAsync(
            new WindowsDnsObservationSeedRequest(
                context.LeaseId,
                context.ExpiresAtUtc,
                _targetSnapshotPath,
                _observationStorePath,
                upstreams),
            cancellationToken);
    }

    private async Task RestoreDnsRecordsBestEffortAsync(IEnumerable<string> recordIds)
    {
        foreach (var recordId in recordIds.Reverse())
        {
            try
            {
                _ = await _coordinator.RestoreAsync(_dnsStore, recordId, CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch
            {
                // The durable ownership record remains for the recovery worker.
            }
        }
    }

    private async Task RestoreFilterTasksBestEffortAsync(IEnumerable<string> recordIds)
    {
        foreach (var recordId in recordIds.Reverse())
        {
            try
            {
                _ = await _filterLauncher.RestoreTaskAsync(recordId, CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch
            {
                // The durable ownership record remains for the recovery worker.
            }
        }
    }

    private async Task ProbeBestEffortAsync(Guid leaseId, string readyToken)
    {
        try
        {
            await _readyProbe.WaitUntilReadyAsync(
                new DnsFilterReadinessRequest(leaseId, readyToken),
                _readyTimeout,
                CancellationToken.None).ConfigureAwait(false);
        }
        catch
        {
            // The prior task definition was restarted; the recovery worker will retry if needed.
        }
    }

    private static List<string> ParseTaskRecordIds(EnforcementArtifact artifact)
    {
        return artifact.Properties[FilterTaskRecordsProperty]
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.Ordinal)
            .ToList();
    }

    private void ValidateArtifact(EnforcementArtifact artifact)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        if (!string.Equals(artifact.AdapterId, AdapterId, StringComparison.Ordinal)
            || artifact.SchemaVersion != ArtifactSchemaVersion
            || !artifact.Properties.ContainsKey(FilterTaskProperty)
            || !artifact.Properties.ContainsKey(FilterTaskRecordsProperty)
            || !artifact.Properties.ContainsKey(ReadyTokenProperty)
            || !artifact.Properties.ContainsKey("reconcile_generation"))
        {
            throw new ArgumentException("The enforcement artifact does not belong to this adapter.", nameof(artifact));
        }

        DnsFilterTaskDefinitionBuilder.ValidateReadyToken(artifact.Properties[ReadyTokenProperty]);
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    private sealed class SnapshotBoundDnsStore : ICompareExchangeResourceStore, IPostWriteVerificationStore
    {
        private readonly IWindowsDnsSettingsStore _inner;
        private readonly string _resourceId;
        private readonly OwnedResourceState _expectedOriginal;

        public SnapshotBoundDnsStore(
            IWindowsDnsSettingsStore inner,
            string resourceId,
            OwnedResourceState expectedOriginal)
        {
            _inner = inner;
            _resourceId = resourceId;
            _expectedOriginal = expectedOriginal;
        }

        public async ValueTask<OwnedResourceState> ReadAsync(
            string resourceId,
            CancellationToken cancellationToken)
        {
            ValidateResourceId(resourceId);
            var current = await _inner.ReadAsync(resourceId, cancellationToken).ConfigureAwait(false);
            if (!_inner.StatesEqual(current, _expectedOriginal)
                && !_inner.StatesEqual(
                    current,
                    DnsSettingsStateCodec.Encode(DnsSettingsStateCodec.CreateLoopback(
                        DnsInterfaceResourceId.Parse(resourceId).InterfaceId,
                        DnsInterfaceResourceId.Parse(resourceId).AddressFamily))))
            {
                throw new OwnershipConflictException(
                    resourceId,
                    "DNS settings changed after the readiness snapshot; mutation was refused.");
            }

            return current;
        }

        public bool StatesEqual(OwnedResourceState left, OwnedResourceState right)
        {
            return _inner.StatesEqual(left, right);
        }

        public bool ReplacementWasApplied(
            OwnedResourceState actual,
            OwnedResourceState replacement)
        {
            return _inner is IPostWriteVerificationStore postWriteVerification
                ? postWriteVerification.ReplacementWasApplied(actual, replacement)
                : _inner.StatesEqual(actual, replacement);
        }

        public ValueTask<bool> TryWriteAsync(
            string resourceId,
            OwnedResourceState expected,
            OwnedResourceState replacement,
            CancellationToken cancellationToken)
        {
            ValidateResourceId(resourceId);
            return _inner.TryWriteAsync(resourceId, expected, replacement, cancellationToken);
        }

        private void ValidateResourceId(string resourceId)
        {
            if (!string.Equals(resourceId, _resourceId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Snapshot-bound DNS store received another resource ID.");
            }
        }
    }
}
