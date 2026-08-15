namespace DistractionFirewall.Core.Persistence;

public interface ILeaseLifecycleStore : ILeaseCapsuleStore
{
    Task<Guid?> GetActiveLeaseIdAsync(CancellationToken cancellationToken);
}

public sealed class LeaseStoreConflictException : IOException
{
    public LeaseStoreConflictException(string message)
        : base(message)
    {
    }
}
