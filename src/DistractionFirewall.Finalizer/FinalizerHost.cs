using DistractionFirewall.Contracts;
using DistractionFirewall.Core.Leases;
using DistractionFirewall.Core.Persistence;
using DistractionFirewall.Core.Time;

namespace DistractionFirewall.Finalizer;

public sealed class FinalizerHost
{
    private readonly ILeaseCapsuleStore _store;
    private readonly ITimeAuthority _timeAuthority;
    private readonly LeaseFinalizer _finalizer;

    public FinalizerHost(
        ILeaseCapsuleStore store,
        ITimeAuthority timeAuthority,
        LeaseFinalizer finalizer)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(timeAuthority);
        ArgumentNullException.ThrowIfNull(finalizer);
        _store = store;
        _timeAuthority = timeAuthority;
        _finalizer = finalizer;
    }

    public async Task<LeaseRuntimeState> RunExpiredOrPendingAsync(
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
        if (state.State is not LeaseState.Releasing and not LeaseState.Completed &&
            !LeaseExpiryEvaluator.IsExpired(manifest, _timeAuthority.Capture()))
        {
            throw new InvalidOperationException(
                "Finalizer refuses to release a lease before its immutable deadline.");
        }

        return await _finalizer.RunAsync(leaseId, cancellationToken).ConfigureAwait(false);
    }
}
