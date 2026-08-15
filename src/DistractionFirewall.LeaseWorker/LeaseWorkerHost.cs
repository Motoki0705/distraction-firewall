using DistractionFirewall.Contracts;
using DistractionFirewall.Core.Leases;
using DistractionFirewall.Core.Persistence;

namespace DistractionFirewall.LeaseWorker;

public sealed class LeaseWorkerHost
{
    private readonly ILeaseLifecycleStore _store;
    private readonly LeaseRuntimeCoordinator _runtime;
    private readonly TimeSpan _heartbeatInterval;

    public LeaseWorkerHost(
        ILeaseLifecycleStore store,
        LeaseRuntimeCoordinator runtime,
        TimeSpan? heartbeatInterval = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(runtime);
        _store = store;
        _runtime = runtime;
        _heartbeatInterval = heartbeatInterval ?? TimeSpan.FromSeconds(5);
        if (_heartbeatInterval <= TimeSpan.Zero || _heartbeatInterval > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentOutOfRangeException(
                nameof(heartbeatInterval),
                "Heartbeat interval must be positive and no more than one minute.");
        }
    }

    public async Task<LeaseRuntimeState?> RecoverActiveAsync(CancellationToken cancellationToken)
    {
        var leaseId = await _store.GetActiveLeaseIdAsync(cancellationToken).ConfigureAwait(false);
        return leaseId is null
            ? null
            : await RunAsync(leaseId.Value, cancellationToken).ConfigureAwait(false);
    }

    public async Task<LeaseRuntimeState> RunAsync(Guid leaseId, CancellationToken cancellationToken)
    {
        if (leaseId == Guid.Empty)
        {
            throw new ArgumentException("A non-empty lease ID is required.", nameof(leaseId));
        }

        _ = await _store.GetManifestAsync(leaseId, cancellationToken).ConfigureAwait(false)
            ?? throw new FileNotFoundException($"Lease '{leaseId}' does not have a manifest.");

        await WaitForActivationArtifactAsync(leaseId, cancellationToken).ConfigureAwait(false);

        while (true)
        {
            var state = await _runtime.ReconcileAsync(leaseId, cancellationToken).ConfigureAwait(false);
            if (state.State == LeaseState.Completed)
            {
                return state;
            }

            await Task.Delay(_heartbeatInterval, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task WaitForActivationArtifactAsync(
        Guid leaseId,
        CancellationToken cancellationToken)
    {
        var timeoutAt = DateTimeOffset.UtcNow.AddSeconds(10);
        while (DateTimeOffset.UtcNow < timeoutAt)
        {
            var state = await _store.GetStateAsync(leaseId, cancellationToken).ConfigureAwait(false)
                ?? throw new FileNotFoundException($"Lease '{leaseId}' does not have runtime state.");
            if (state.State != LeaseState.Activating ||
                (await _store.GetArtifactsAsync(leaseId, cancellationToken).ConfigureAwait(false)).Count != 0)
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken).ConfigureAwait(false);
        }
    }
}
