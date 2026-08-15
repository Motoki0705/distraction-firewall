namespace DistractionFirewall.Enforcement.Windows.Ownership;

internal sealed record OwnedApplyResult(
    bool Owned,
    bool AlreadySatisfied,
    string? RecordId);

internal sealed record OwnedRestoreResult(
    bool Restored,
    bool Conflict,
    string Summary);

internal sealed class OwnedMutationCoordinator
{
    private readonly IOwnershipLedger _ledger;

    public OwnedMutationCoordinator(IOwnershipLedger ledger)
    {
        _ledger = ledger ?? throw new ArgumentNullException(nameof(ledger));
    }

    public async Task<OwnedApplyResult> ApplyAsync(
        ICompareExchangeResourceStore store,
        string adapterId,
        Guid leaseId,
        string resourceId,
        OwnedResourceState desiredState,
        bool failIfPresent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(store);
        var current = await store.ReadAsync(resourceId, cancellationToken).ConfigureAwait(false);
        if (store.StatesEqual(current, desiredState))
        {
            return new OwnedApplyResult(Owned: false, AlreadySatisfied: true, RecordId: null);
        }

        if (failIfPresent && current.Exists)
        {
            throw new OwnershipConflictException(
                resourceId,
                $"An existing value of type '{current.ContentType}' conflicts with the required value.");
        }

        var record = await _ledger.PrepareAsync(
            adapterId,
            leaseId,
            resourceId,
            current,
            desiredState,
            cancellationToken).ConfigureAwait(false);

        if (record.Phase == OwnershipMutationPhase.Applied)
        {
            var retryCurrent = await store.ReadAsync(resourceId, cancellationToken).ConfigureAwait(false);
            if (!store.StatesEqual(retryCurrent, desiredState))
            {
                await MarkConflictAsync(record.RecordId, "Owned resource changed after apply.", cancellationToken)
                    .ConfigureAwait(false);
                throw new OwnershipConflictException(resourceId, "Owned resource changed after apply.");
            }

            return new OwnedApplyResult(Owned: true, AlreadySatisfied: true, record.RecordId);
        }

        if (!await store.TryWriteAsync(resourceId, current, desiredState, cancellationToken).ConfigureAwait(false))
        {
            await MarkConflictAsync(record.RecordId, "Compare-and-swap apply lost a race.", cancellationToken)
                .ConfigureAwait(false);
            throw new OwnershipConflictException(resourceId, "Compare-and-swap apply lost a race.");
        }

        var applied = await store.ReadAsync(resourceId, cancellationToken).ConfigureAwait(false);
        if (!ReplacementWasApplied(store, applied, desiredState))
        {
            await MarkConflictAsync(record.RecordId, "Post-write verification failed.", cancellationToken)
                .ConfigureAwait(false);
            throw new IOException($"Post-write verification failed for '{resourceId}'.");
        }

        await _ledger.SetPhaseAsync(
            record.RecordId,
            OwnershipMutationPhase.Applied,
            conflictReason: null,
            cancellationToken).ConfigureAwait(false);
        return new OwnedApplyResult(Owned: true, AlreadySatisfied: false, record.RecordId);
    }

    public async Task<OwnedRestoreResult> RestoreAsync(
        ICompareExchangeResourceStore store,
        string recordId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(store);
        var record = await _ledger.GetAsync(recordId, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Ownership record '{recordId}' was not found.");
        if (record.Phase == OwnershipMutationPhase.Restored)
        {
            return new OwnedRestoreResult(true, false, "Already restored.");
        }

        await _ledger.SetPhaseAsync(
            recordId,
            OwnershipMutationPhase.RestorePending,
            conflictReason: null,
            cancellationToken).ConfigureAwait(false);

        var current = await store.ReadAsync(record.ResourceId, cancellationToken).ConfigureAwait(false);
        if (!store.StatesEqual(current, record.DesiredState))
        {
            const string reason = "Current state no longer equals the owned desired state; no restore was attempted.";
            await MarkConflictAsync(recordId, reason, cancellationToken).ConfigureAwait(false);
            return new OwnedRestoreResult(false, true, reason);
        }

        if (!await store.TryWriteAsync(
                record.ResourceId,
                current,
                record.OriginalState,
                cancellationToken).ConfigureAwait(false))
        {
            const string reason = "Compare-and-swap restore lost a race; no foreign state was overwritten.";
            await MarkConflictAsync(recordId, reason, cancellationToken).ConfigureAwait(false);
            return new OwnedRestoreResult(false, true, reason);
        }

        var restored = await store.ReadAsync(record.ResourceId, cancellationToken).ConfigureAwait(false);
        if (!ReplacementWasApplied(store, restored, record.OriginalState))
        {
            const string reason = "Post-restore verification failed.";
            await MarkConflictAsync(recordId, reason, cancellationToken).ConfigureAwait(false);
            return new OwnedRestoreResult(false, true, reason);
        }

        await _ledger.SetPhaseAsync(
            recordId,
            OwnershipMutationPhase.Restored,
            conflictReason: null,
            cancellationToken).ConfigureAwait(false);
        return new OwnedRestoreResult(true, false, "Restored by compare-and-swap.");
    }

    private Task<OwnershipMutationRecord> MarkConflictAsync(
        string recordId,
        string reason,
        CancellationToken cancellationToken)
    {
        return _ledger.SetPhaseAsync(
            recordId,
            OwnershipMutationPhase.Conflict,
            reason,
            cancellationToken);
    }

    private static bool ReplacementWasApplied(
        ICompareExchangeResourceStore store,
        OwnedResourceState actual,
        OwnedResourceState replacement)
    {
        return store is IPostWriteVerificationStore postWriteVerification
            ? postWriteVerification.ReplacementWasApplied(actual, replacement)
            : store.StatesEqual(actual, replacement);
    }
}
