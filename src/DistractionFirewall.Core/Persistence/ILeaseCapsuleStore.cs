using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Core.Leases;

namespace DistractionFirewall.Core.Persistence;

public interface ILeaseCapsuleStore
{
    Task<bool> HasActiveLeaseAsync(CancellationToken cancellationToken);

    Task SavePreparationAsync(PreparedLease preparation, CancellationToken cancellationToken);

    Task<PreparedLease?> GetPreparationAsync(Guid preparationId, CancellationToken cancellationToken);

    Task CreateCapsuleAsync(
        LeaseManifest manifest,
        LeaseRuntimeState state,
        CancellationToken cancellationToken);

    Task<LeaseManifest?> GetManifestAsync(Guid leaseId, CancellationToken cancellationToken);

    Task<LeaseRuntimeState?> GetStateAsync(Guid leaseId, CancellationToken cancellationToken);

    Task SaveStateAsync(LeaseRuntimeState state, CancellationToken cancellationToken);

    Task SaveArtifactsAsync(
        Guid leaseId,
        IReadOnlyList<EnforcementArtifact> artifacts,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<EnforcementArtifact>> GetArtifactsAsync(
        Guid leaseId,
        CancellationToken cancellationToken);
}
