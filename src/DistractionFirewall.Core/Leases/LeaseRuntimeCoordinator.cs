using DistractionFirewall.Contracts;
using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Core.Persistence;
using DistractionFirewall.Core.Time;

namespace DistractionFirewall.Core.Leases;

public sealed class LeaseRuntimeCoordinator
{
    private const string ActivationFailedCode = "activation_failed";
    private const string EnforcementDegradedCode = "enforcement_degraded";
    private const string ReleasePendingCode = "release_pending";
    private readonly IEnforcementAdapter[] _adapters;
    private readonly Dictionary<string, IEnforcementAdapter> _adaptersById;
    private readonly ILeaseCapsuleStore _store;
    private readonly ITimeAuthority _timeAuthority;

    public LeaseRuntimeCoordinator(
        ILeaseCapsuleStore store,
        IEnumerable<IEnforcementAdapter> adapters,
        ITimeAuthority timeAuthority)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(adapters);
        ArgumentNullException.ThrowIfNull(timeAuthority);
        _store = store;
        _timeAuthority = timeAuthority;
        _adapters = adapters.ToArray();
        if (_adapters.Any(adapter => string.IsNullOrWhiteSpace(adapter.AdapterId)) ||
            _adapters.Select(adapter => adapter.AdapterId).Distinct(StringComparer.Ordinal).Count() != _adapters.Length)
        {
            throw new ArgumentException("Enforcement adapter IDs must be non-empty and unique.", nameof(adapters));
        }

        _adaptersById = _adapters.ToDictionary(adapter => adapter.AdapterId, StringComparer.Ordinal);
    }

    public int AdapterCount => _adapters.Length;

    public async Task<IReadOnlyList<EnforcementHealth>> CheckHealthAsync(CancellationToken cancellationToken)
    {
        var health = new List<EnforcementHealth>(_adapters.Length);
        foreach (var adapter in _adapters)
        {
            try
            {
                health.Add(await adapter.CheckHealthAsync(cancellationToken).ConfigureAwait(false));
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                health.Add(new EnforcementHealth(
                    adapter.AdapterId,
                    Available: false,
                    Healthy: false,
                    $"Health check failed: {exception.GetType().Name}."));
            }
        }

        return health;
    }

    public async Task<LeaseRuntimeState> ActivateAsync(Guid leaseId, CancellationToken cancellationToken)
    {
        var (manifest, state) = await LoadRequiredAsync(leaseId, cancellationToken).ConfigureAwait(false);
        if (state.State == LeaseState.Active)
        {
            return state;
        }

        if (state.State != LeaseState.Activating)
        {
            throw new LeaseRuntimeException(
                $"Lease '{leaseId}' cannot activate from state {state.State}.",
                state);
        }

        try
        {
            await ApplyAndVerifyAsync(manifest, cancellationToken).ConfigureAwait(false);
            var now = _timeAuthority.Capture().UtcNow;
            state = LeaseStateMachine.Transition(state, LeaseState.Active, now, LeaseHealth.Healthy);
            state = Touch(state, now, LeaseHealth.Healthy, errorCode: null);
            await _store.SaveStateAsync(state, cancellationToken).ConfigureAwait(false);
            return state;
        }
        catch (Exception exception) when (exception is not LeaseRuntimeException)
        {
            var recoveryToken = CancellationToken.None;
            state = await _store.GetStateAsync(leaseId, recoveryToken).ConfigureAwait(false) ?? state;
            if (state.State == LeaseState.Activating)
            {
                var now = _timeAuthority.Capture().UtcNow;
                state = LeaseStateMachine.Transition(
                    state,
                    LeaseState.Releasing,
                    now,
                    LeaseHealth.Degraded,
                    ActivationFailedCode);
                await _store.SaveStateAsync(state, recoveryToken).ConfigureAwait(false);
            }

            var recovered = await ReleaseCoreAsync(manifest, state, recoveryToken).ConfigureAwait(false);
            throw new LeaseRuntimeException(
                $"Lease '{leaseId}' activation failed and entered {recovered.State}.",
                recovered,
                exception);
        }
    }

    public async Task<LeaseRuntimeState> ReconcileAsync(Guid leaseId, CancellationToken cancellationToken)
    {
        var (manifest, state) = await LoadRequiredAsync(leaseId, cancellationToken).ConfigureAwait(false);
        if (state.State == LeaseState.Completed)
        {
            return state;
        }

        var snapshot = _timeAuthority.Capture();
        if (LeaseExpiryEvaluator.IsExpired(manifest, snapshot))
        {
            return await ReleaseCoreAsync(manifest, state, cancellationToken).ConfigureAwait(false);
        }

        if (state.State == LeaseState.Activating)
        {
            return await ActivateAsync(leaseId, cancellationToken).ConfigureAwait(false);
        }

        if (state.State == LeaseState.Releasing)
        {
            return await ReleaseCoreAsync(manifest, state, cancellationToken).ConfigureAwait(false);
        }

        if (state.State != LeaseState.Active)
        {
            throw new LeaseRuntimeException($"Lease '{leaseId}' cannot reconcile from state {state.State}.", state);
        }

        try
        {
            await ApplyAndVerifyAsync(manifest, cancellationToken).ConfigureAwait(false);
            state = Touch(state, snapshot.UtcNow, LeaseHealth.Healthy, errorCode: null);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            state = Touch(
                state,
                snapshot.UtcNow,
                LeaseHealth.Degraded,
                $"{EnforcementDegradedCode}:{exception.GetType().Name}");
        }

        await _store.SaveStateAsync(state, cancellationToken).ConfigureAwait(false);
        return state;
    }

    public async Task<LeaseRuntimeState> ReleaseAsync(Guid leaseId, CancellationToken cancellationToken)
    {
        var (manifest, state) = await LoadRequiredAsync(leaseId, cancellationToken).ConfigureAwait(false);
        return await ReleaseCoreAsync(manifest, state, cancellationToken).ConfigureAwait(false);
    }

    private async Task ApplyAndVerifyAsync(LeaseManifest manifest, CancellationToken cancellationToken)
    {
        if (_adapters.Length == 0)
        {
            throw new InvalidOperationException("No enforcement adapters are configured.");
        }

        var context = CreateContext(manifest);
        var artifacts = (await _store.GetArtifactsAsync(manifest.LeaseId, cancellationToken).ConfigureAwait(false)).ToList();
        foreach (var adapter in _adapters)
        {
            var artifact = artifacts.SingleOrDefault(item =>
                string.Equals(item.AdapterId, adapter.AdapterId, StringComparison.Ordinal));
            if (artifact is null)
            {
                artifact = await adapter.ApplyAsync(context, cancellationToken).ConfigureAwait(false);
                if (!string.Equals(artifact.AdapterId, adapter.AdapterId, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        $"Adapter '{adapter.AdapterId}' returned artifact owner '{artifact.AdapterId}'.");
                }

                artifacts.Add(artifact);
                await _store.SaveArtifactsAsync(manifest.LeaseId, artifacts, cancellationToken).ConfigureAwait(false);
            }

            var verification = await adapter.VerifyAsync(context, artifact, cancellationToken).ConfigureAwait(false);
            if (!verification.TargetBlocked || !verification.GeneralConnectivityAvailable)
            {
                EnforcementArtifact replacement;
                if (adapter is IEnforcementReconciliationAdapter reconciliationAdapter)
                {
                    replacement = await reconciliationAdapter.ReconcileAsync(
                        context,
                        artifact,
                        cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    throw new InvalidOperationException(
                        $"Adapter '{adapter.AdapterId}' cannot safely reconcile its artifact.");
                }

                if (!string.Equals(replacement.AdapterId, adapter.AdapterId, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        $"Adapter '{adapter.AdapterId}' returned artifact owner '{replacement.AdapterId}'.");
                }

                var artifactIndex = artifacts.FindIndex(item =>
                    string.Equals(item.AdapterId, adapter.AdapterId, StringComparison.Ordinal));
                artifacts[artifactIndex] = replacement;
                await _store.SaveArtifactsAsync(manifest.LeaseId, artifacts, cancellationToken).ConfigureAwait(false);
                verification = await adapter.VerifyAsync(
                    context,
                    replacement,
                    cancellationToken).ConfigureAwait(false);
                if (!verification.TargetBlocked || !verification.GeneralConnectivityAvailable)
                {
                    throw new InvalidOperationException(
                        $"Adapter '{adapter.AdapterId}' verification failed: {verification.Summary}");
                }
            }
        }
    }

    private async Task<LeaseRuntimeState> ReleaseCoreAsync(
        LeaseManifest manifest,
        LeaseRuntimeState state,
        CancellationToken cancellationToken)
    {
        if (state.State == LeaseState.Completed)
        {
            return state;
        }

        var now = _timeAuthority.Capture().UtcNow;
        if (state.State is LeaseState.Active or LeaseState.Activating)
        {
            state = LeaseStateMachine.Transition(
                state,
                LeaseState.Releasing,
                now,
                state.Health,
                state.LastErrorCode);
            await _store.SaveStateAsync(state, cancellationToken).ConfigureAwait(false);
        }
        else if (state.State != LeaseState.Releasing)
        {
            throw new LeaseRuntimeException(
                $"Lease '{manifest.LeaseId}' cannot release from state {state.State}.",
                state);
        }

        var context = CreateContext(manifest);
        var remaining = (await _store.GetArtifactsAsync(
            manifest.LeaseId,
            cancellationToken).ConfigureAwait(false)).ToList();
        for (var index = remaining.Count - 1; index >= 0; index--)
        {
            var artifact = remaining[index];
            if (!_adaptersById.TryGetValue(artifact.AdapterId, out var adapter))
            {
                continue;
            }

            RestoreResult result;
            try
            {
                result = await adapter.RestoreAsync(context, artifact, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                result = new RestoreResult(
                    artifact.AdapterId,
                    Restored: false,
                    Retryable: true,
                    $"Restore threw {exception.GetType().Name}.");
            }

            if (!result.Restored)
            {
                continue;
            }

            remaining.RemoveAt(index);
            await _store.SaveArtifactsAsync(
                manifest.LeaseId,
                remaining,
                cancellationToken).ConfigureAwait(false);
        }

        now = _timeAuthority.Capture().UtcNow;
        if (remaining.Count == 0)
        {
            state = LeaseStateMachine.Transition(
                state,
                LeaseState.Completed,
                now,
                LeaseHealth.Healthy,
                state.LastErrorCode);
        }
        else
        {
            state = Touch(state, now, LeaseHealth.ReleasePending, ReleasePendingCode);
        }

        await _store.SaveStateAsync(state, cancellationToken).ConfigureAwait(false);
        return state;
    }

    private async Task<(LeaseManifest Manifest, LeaseRuntimeState State)> LoadRequiredAsync(
        Guid leaseId,
        CancellationToken cancellationToken)
    {
        if (leaseId == Guid.Empty)
        {
            throw new ArgumentException("A non-empty lease ID is required.", nameof(leaseId));
        }

        var manifest = await _store.GetManifestAsync(leaseId, cancellationToken).ConfigureAwait(false)
            ?? throw new FileNotFoundException($"Lease '{leaseId}' does not have a manifest.");
        var state = await _store.GetStateAsync(leaseId, cancellationToken).ConfigureAwait(false)
            ?? throw new FileNotFoundException($"Lease '{leaseId}' does not have runtime state.");
        return (manifest, state);
    }

    private static EnforcementContext CreateContext(LeaseManifest manifest) => new(
        manifest.LeaseId,
        manifest.RuleHash,
        manifest.ExpiresAtUtc,
        manifest.TargetSnapshot);

    private static LeaseRuntimeState Touch(
        LeaseRuntimeState state,
        DateTimeOffset changedAtUtc,
        LeaseHealth health,
        string? errorCode) => state with
        {
            Sequence = checked(state.Sequence + 1),
            UpdatedAtUtc = changedAtUtc.ToUniversalTime(),
            LastHeartbeatUtc = changedAtUtc.ToUniversalTime(),
            Health = health,
            LastErrorCode = errorCode,
        };
}

public sealed class LeaseRuntimeException : Exception
{
    public LeaseRuntimeException(string message, LeaseRuntimeState state)
        : base(message)
    {
        State = state;
    }

    public LeaseRuntimeException(string message, LeaseRuntimeState state, Exception innerException)
        : base(message, innerException)
    {
        State = state;
    }

    public LeaseRuntimeState State { get; }
}
