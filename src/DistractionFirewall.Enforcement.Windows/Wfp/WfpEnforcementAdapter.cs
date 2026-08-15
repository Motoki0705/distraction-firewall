using System.Net;
using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Core.Targets;
using DistractionFirewall.Enforcement.Windows.Mutation;
using DistractionFirewall.Enforcement.Windows.Ownership;

namespace DistractionFirewall.Enforcement.Windows.Wfp;

public interface IWindowsObservedAddressSource
{
    ValueTask<IReadOnlyCollection<IPAddress>> GetObservedAddressesAsync(
        EnforcementContext context,
        CancellationToken cancellationToken);
}

internal sealed class EmptyWindowsObservedAddressSource : IWindowsObservedAddressSource
{
    public ValueTask<IReadOnlyCollection<IPAddress>> GetObservedAddressesAsync(
        EnforcementContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult<IReadOnlyCollection<IPAddress>>([]);
    }
}

public sealed class WfpEnforcementAdapter :
    IEnforcementReconciliationAdapter,
    IWindowsPendingVerificationAdapter,
    IWindowsIncrementalArtifactAdapter
{
    private readonly IWfpPolicyStore _policyStore;
    private readonly IOwnershipLedger _ledger;
    private readonly IWindowsObservedAddressSource _addressSource;
    private readonly WindowsMutationGate _mutationGate;

    internal WfpEnforcementAdapter(
        IWfpPolicyStore policyStore,
        IOwnershipLedger ledger,
        IWindowsObservedAddressSource addressSource,
        WindowsMutationGate mutationGate)
    {
        _policyStore = policyStore ?? throw new ArgumentNullException(nameof(policyStore));
        _ledger = ledger ?? throw new ArgumentNullException(nameof(ledger));
        _addressSource = addressSource ?? throw new ArgumentNullException(nameof(addressSource));
        _mutationGate = mutationGate ?? throw new ArgumentNullException(nameof(mutationGate));
    }

    public string AdapterId => "windows-wfp";

    public Task<EnforcementHealth> CheckHealthAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_mutationGate.IsEnabled)
        {
            return Task.FromResult(new EnforcementHealth(
                AdapterId,
                Available: false,
                Healthy: false,
                "Live Windows mutation was not explicitly enabled."));
        }

        var healthy = _policyStore.CheckAvailable(out var summary);
        return Task.FromResult(new EnforcementHealth(AdapterId, healthy, healthy, summary));
    }

    public async Task<EnforcementArtifact> ApplyAsync(
        EnforcementContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        _mutationGate.Demand();

        var filters = await BuildDesiredFiltersAsync(context, cancellationToken).ConfigureAwait(false);
        DemandRequiredAddressFloor(context, filters);
        var records = new List<OwnershipMutationRecord>(filters.Count);

        foreach (var filter in filters)
        {
            var record = await _ledger.PrepareAsync(
                AdapterId,
                context.LeaseId,
                WfpFilterSpecCodec.ResourceId(filter),
                OwnedResourceState.Missing,
                WfpFilterSpecCodec.Encode(filter),
                cancellationToken).ConfigureAwait(false);
            records.Add(record);
        }

        cancellationToken.ThrowIfCancellationRequested();
        _policyStore.EnsurePersistentFilters(filters);
        foreach (var record in records)
        {
            await _ledger.SetPhaseAsync(
                record.RecordId,
                OwnershipMutationPhase.Applied,
                conflictReason: null,
                CancellationToken.None).ConfigureAwait(false);
        }

        return CreateArtifact(records.Select(record => record.RecordId).ToArray(), filters.Count);
    }

    public async Task<EnforcementVerification> VerifyAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ValidateArtifact(artifact);
        var owned = await LoadAndValidateFiltersAsync(
            context,
            artifact,
            requireAppliedPhase: true,
            cancellationToken).ConfigureAwait(false);
        var desired = await BuildDesiredFiltersAsync(context, cancellationToken).ConfigureAwait(false);
        var ownedKeys = owned.Select(item => item.Filter.FilterKey).ToHashSet();
        var desiredKeys = desired.Select(filter => filter.FilterKey).ToHashSet();
        if (ownedKeys.Count == 0 && desiredKeys.Count == 0)
        {
            if (RequiresObservedAddressFloor(context))
            {
                return new EnforcementVerification(
                    AdapterId,
                    TargetBlocked: false,
                    GeneralConnectivityAvailable: true,
                    "Required WFP address floor is not met: no TTL-valid public target-attributed address is available.");
            }

            return new EnforcementVerification(
                AdapterId,
                TargetBlocked: false,
                GeneralConnectivityAvailable: true,
                "Pending observations: no TTL-valid target-attributed addresses are currently available.");
        }

        if (!ownedKeys.SetEquals(desiredKeys))
        {
            return new EnforcementVerification(
                AdapterId,
                TargetBlocked: false,
                GeneralConnectivityAvailable: true,
                $"Observed-address reconciliation is required (owned {ownedKeys.Count}, current {desiredKeys.Count}).");
        }

        var verified = _policyStore.VerifyPersistentFilters(
            owned.Select(item => item.Filter).ToArray(),
            out var summary);
        return new EnforcementVerification(
            AdapterId,
            TargetBlocked: verified,
            GeneralConnectivityAvailable: true,
            summary);
    }

    public async Task<EnforcementArtifact> ReconcileAsync(
        EnforcementContext context,
        EnforcementArtifact existingArtifact,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ValidateArtifact(existingArtifact);
        _mutationGate.Demand();

        var existing = await LoadAndValidateFiltersAsync(
            context,
            existingArtifact,
            requireAppliedPhase: true,
            cancellationToken).ConfigureAwait(false);
        var desired = await BuildDesiredFiltersAsync(context, cancellationToken).ConfigureAwait(false);
        DemandRequiredAddressFloor(context, desired);
        var existingByKey = existing.ToDictionary(item => item.Filter.FilterKey);
        var desiredByKey = desired.ToDictionary(filter => filter.FilterKey);
        var retained = existing
            .Where(item => desiredByKey.ContainsKey(item.Filter.FilterKey))
            .ToArray();
        var removals = existing
            .Where(item => !desiredByKey.ContainsKey(item.Filter.FilterKey))
            .ToArray();
        var additions = desired
            .Where(filter => !existingByKey.ContainsKey(filter.FilterKey))
            .ToArray();
        var additionRecords = new List<OwnedWfpFilter>(additions.Length);
        foreach (var filter in additions)
        {
            var record = await _ledger.PrepareAsync(
                AdapterId,
                context.LeaseId,
                WfpFilterSpecCodec.ResourceId(filter),
                OwnedResourceState.Missing,
                WfpFilterSpecCodec.Encode(filter),
                cancellationToken).ConfigureAwait(false);
            additionRecords.Add(new OwnedWfpFilter(record, filter));
        }

        cancellationToken.ThrowIfCancellationRequested();
        _policyStore.ReconcilePersistentFilters(
            desired,
            removals.Select(item => item.Filter).ToArray());

        // Once the WFP transaction commits, finish the durable ownership transition even if
        // the caller cancels. Prepared records allow crash recovery before these writes finish.
        foreach (var addition in additionRecords)
        {
            await _ledger.SetPhaseAsync(
                addition.Record.RecordId,
                OwnershipMutationPhase.Applied,
                conflictReason: null,
                CancellationToken.None).ConfigureAwait(false);
        }

        foreach (var removal in removals)
        {
            await _ledger.SetPhaseAsync(
                removal.Record.RecordId,
                OwnershipMutationPhase.Restored,
                conflictReason: null,
                CancellationToken.None).ConfigureAwait(false);
        }

        var finalRecords = retained
            .Concat(additionRecords)
            .OrderBy(item => item.Filter.FilterKey)
            .Select(item => item.Record.RecordId)
            .ToArray();
        return CreateArtifact(finalRecords, desired.Count);
    }

    public bool IsPending(EnforcementArtifact artifact, EnforcementVerification verification)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        ArgumentNullException.ThrowIfNull(verification);
        return !verification.TargetBlocked
            && verification.GeneralConnectivityAvailable
            && artifact.OwnedResourceIds.Count == 0
            && artifact.Properties.TryGetValue("address_source_empty", out var empty)
            && bool.TryParse(empty, out var sourceEmpty)
            && sourceEmpty
            && verification.Summary.StartsWith("Pending observations:", StringComparison.Ordinal);
    }

    public EnforcementArtifact MergeReconciledArtifact(
        EnforcementArtifact existingArtifact,
        EnforcementArtifact reconciledArtifact)
    {
        ValidateArtifact(existingArtifact);
        ValidateArtifact(reconciledArtifact);
        return reconciledArtifact;
    }

    public EnforcementArtifact? CreateRollbackArtifact(
        EnforcementArtifact existingArtifact,
        EnforcementArtifact reconciledArtifact)
    {
        _ = MergeReconciledArtifact(existingArtifact, reconciledArtifact);
        var existingIds = existingArtifact.OwnedResourceIds.ToHashSet(StringComparer.Ordinal);
        var newIds = reconciledArtifact.OwnedResourceIds
            .Where(recordId => !existingIds.Contains(recordId))
            .ToArray();
        return newIds.Length == 0 ? null : CreateArtifact(newIds, newIds.Length);
    }

    public async Task<RestoreResult> RestoreAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ValidateArtifact(artifact);
        _mutationGate.Demand();

        WfpFilterSpec[] filters;
        try
        {
            var owned = await LoadAndValidateFiltersAsync(
                context,
                artifact,
                requireAppliedPhase: false,
                cancellationToken).ConfigureAwait(false);
            filters = owned.Select(item => item.Filter).ToArray();
            _policyStore.RestoreKnownFilters(filters);
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            foreach (var recordId in artifact.OwnedResourceIds)
            {
                await _ledger.SetPhaseAsync(
                    recordId,
                    OwnershipMutationPhase.Conflict,
                    exception.Message,
                    cancellationToken).ConfigureAwait(false);
            }

            return new RestoreResult(
                AdapterId,
                Restored: false,
                Retryable: true,
                "WFP restore transaction was aborted: " + exception.Message);
        }

        foreach (var recordId in artifact.OwnedResourceIds)
        {
            await _ledger.SetPhaseAsync(
                recordId,
                OwnershipMutationPhase.Restored,
                conflictReason: null,
                cancellationToken).ConfigureAwait(false);
        }

        return new RestoreResult(
            AdapterId,
            Restored: true,
            Retryable: false,
            $"Removed {filters.Length} known, product-owned WFP filters; provider and sublayer remain installed.");
    }

    private async Task<IReadOnlyList<OwnedWfpFilter>> LoadAndValidateFiltersAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        bool requireAppliedPhase,
        CancellationToken cancellationToken)
    {
        var filters = new List<OwnedWfpFilter>(artifact.OwnedResourceIds.Count);
        var recordIds = new HashSet<string>(StringComparer.Ordinal);
        var filterKeys = new HashSet<Guid>();
        foreach (var recordId in artifact.OwnedResourceIds)
        {
            if (!recordIds.Add(recordId))
            {
                throw new InvalidDataException("WFP artifact contains a duplicate ownership record.");
            }

            var record = await _ledger.GetAsync(recordId, cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidDataException($"WFP ownership record '{recordId}' is missing.");
            if (!string.Equals(record.AdapterId, AdapterId, StringComparison.Ordinal)
                || record.LeaseId != context.LeaseId)
            {
                throw new InvalidDataException("WFP ownership record does not belong to this adapter and lease.");
            }

            if (requireAppliedPhase && record.Phase != OwnershipMutationPhase.Applied)
            {
                throw new InvalidDataException(
                    $"WFP ownership record '{recordId}' is not in the applied phase.");
            }

            if (!OwnedResourceState.ExactEquals(record.OriginalState, OwnedResourceState.Missing))
            {
                throw new InvalidDataException("WFP ownership record has an unexpected original state.");
            }

            var filter = WfpFilterSpecCodec.Decode(record.DesiredState);
            var expected = WfpFilterSpec.CreateForLayer(
                context.LeaseId,
                filter.ParseAddress(),
                filter.LayerKey);
            if (expected.FilterKey != filter.FilterKey
                || expected.LayerKey != filter.LayerKey
                || !string.Equals(record.ResourceId, WfpFilterSpecCodec.ResourceId(filter), StringComparison.Ordinal))
            {
                throw new InvalidDataException("WFP ownership record failed deterministic GUID validation.");
            }

            if (!filterKeys.Add(filter.FilterKey))
            {
                throw new InvalidDataException("WFP artifact contains a duplicate filter key.");
            }

            filters.Add(new OwnedWfpFilter(record, filter));
        }

        return filters;
    }

    private async Task<IReadOnlyList<WfpFilterSpec>> BuildDesiredFiltersAsync(
        EnforcementContext context,
        CancellationToken cancellationToken)
    {
        var addresses = await _addressSource.GetObservedAddressesAsync(context, cancellationToken)
            .ConfigureAwait(false);
        return addresses
            .Select(FileDnsObservedAddressStore.NormalizePublicAddress)
            .Distinct()
            .SelectMany(address => WfpFilterSpec.CreateForAddress(context.LeaseId, address))
            .OrderBy(filter => filter.FilterKey)
            .ToArray();
    }

    private static void DemandRequiredAddressFloor(
        EnforcementContext context,
        IReadOnlyCollection<WfpFilterSpec> filters)
    {
        if (filters.Count == 0 && RequiresObservedAddressFloor(context))
        {
            throw new InvalidOperationException(
                "Required WFP enforcement cannot activate or reconcile because no TTL-valid public " +
                "target-attributed IP address is available.");
        }
    }

    private static bool RequiresObservedAddressFloor(EnforcementContext context) =>
        context.Targets.Any(target =>
            target.IpBlockPolicy.Mode == IpBlockMode.DnsObserved &&
            target.IpBlockPolicy.SharedAddressAction == SharedAddressAction.Block);

    private EnforcementArtifact CreateArtifact(
        IReadOnlyList<string> recordIds,
        int filterCount)
    {
        return new EnforcementArtifact(
            AdapterId,
            SchemaVersion: 1,
            recordIds,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["filter_count"] = filterCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["address_source_empty"] = (filterCount == 0).ToString(
                    System.Globalization.CultureInfo.InvariantCulture),
                ["pending_observations"] = (filterCount == 0).ToString(
                    System.Globalization.CultureInfo.InvariantCulture),
                ["provider_key"] = WfpProductConstants.ProviderKey.ToString("D"),
                ["sublayer_key"] = WfpProductConstants.SubLayerKey.ToString("D"),
            });
    }

    private void ValidateArtifact(EnforcementArtifact artifact)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        if (!string.Equals(artifact.AdapterId, AdapterId, StringComparison.Ordinal)
            || artifact.SchemaVersion != 1)
        {
            throw new ArgumentException("The enforcement artifact does not belong to this adapter.", nameof(artifact));
        }
    }

    private sealed record OwnedWfpFilter(
        OwnershipMutationRecord Record,
        WfpFilterSpec Filter);
}
