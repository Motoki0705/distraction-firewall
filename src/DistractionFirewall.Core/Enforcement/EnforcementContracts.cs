namespace DistractionFirewall.Core.Enforcement;

public sealed record EnforcementContext(
    Guid LeaseId,
    string RuleHash,
    DateTimeOffset ExpiresAtUtc,
    IReadOnlyList<Targets.TargetDefinition> Targets);

public sealed record EnforcementArtifact(
    string AdapterId,
    int SchemaVersion,
    IReadOnlyList<string> OwnedResourceIds,
    IReadOnlyDictionary<string, string> Properties);

public sealed record EnforcementHealth(
    string AdapterId,
    bool Available,
    bool Healthy,
    string Summary);

public sealed record EnforcementVerification(
    string AdapterId,
    bool TargetBlocked,
    bool GeneralConnectivityAvailable,
    string Summary);

public sealed record RestoreResult(
    string AdapterId,
    bool Restored,
    bool Retryable,
    string Summary);

public interface IEnforcementAdapter
{
    string AdapterId { get; }

    Task<EnforcementHealth> CheckHealthAsync(CancellationToken cancellationToken);

    Task<EnforcementArtifact> ApplyAsync(
        EnforcementContext context,
        CancellationToken cancellationToken);

    Task<EnforcementVerification> VerifyAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        CancellationToken cancellationToken);

    Task<RestoreResult> RestoreAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        CancellationToken cancellationToken);
}

/// <summary>
/// Optional capability for adapters that can repair an existing, owned
/// enforcement artifact without replacing it through a fresh apply operation.
/// </summary>
public interface IEnforcementReconciliationAdapter : IEnforcementAdapter
{
    Task<EnforcementArtifact> ReconcileAsync(
        EnforcementContext context,
        EnforcementArtifact existingArtifact,
        CancellationToken cancellationToken);
}
