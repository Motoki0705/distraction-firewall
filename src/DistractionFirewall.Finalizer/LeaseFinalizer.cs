using DistractionFirewall.Core.Leases;

namespace DistractionFirewall.Finalizer;

public sealed class LeaseFinalizer
{
    private readonly LeaseRuntimeCoordinator _runtime;

    public LeaseFinalizer(LeaseRuntimeCoordinator runtime)
    {
        ArgumentNullException.ThrowIfNull(runtime);
        _runtime = runtime;
    }

    public Task<LeaseRuntimeState> RunAsync(Guid leaseId, CancellationToken cancellationToken)
    {
        if (leaseId == Guid.Empty)
        {
            throw new ArgumentException("A non-empty lease ID is required.", nameof(leaseId));
        }

        return _runtime.ReleaseAsync(leaseId, cancellationToken);
    }
}
