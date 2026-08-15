using System.Collections.Concurrent;

namespace DistractionFirewall.Core.Enforcement;

public sealed class UnavailableEnforcementAdapter : IEnforcementAdapter
{
    private readonly string _summary;

    public UnavailableEnforcementAdapter(string adapterId, string summary)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(adapterId);
        ArgumentException.ThrowIfNullOrWhiteSpace(summary);
        AdapterId = adapterId;
        _summary = summary;
    }

    public string AdapterId { get; }

    public Task<EnforcementHealth> CheckHealthAsync(CancellationToken cancellationToken) =>
        Task.FromResult(new EnforcementHealth(AdapterId, Available: false, Healthy: false, _summary));

    public Task<EnforcementArtifact> ApplyAsync(
        EnforcementContext context,
        CancellationToken cancellationToken) =>
        Task.FromException<EnforcementArtifact>(
            new InvalidOperationException($"Enforcement adapter '{AdapterId}' is unavailable: {_summary}"));

    public Task<EnforcementVerification> VerifyAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        CancellationToken cancellationToken) =>
        Task.FromResult(new EnforcementVerification(
            AdapterId,
            TargetBlocked: false,
            GeneralConnectivityAvailable: false,
            _summary));

    public Task<RestoreResult> RestoreAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        CancellationToken cancellationToken) =>
        Task.FromResult(new RestoreResult(AdapterId, Restored: false, Retryable: true, _summary));
}

public sealed class InProcessEnforcementAdapter : IEnforcementAdapter
{
    private readonly ConcurrentDictionary<Guid, EnforcementArtifact> _artifacts = new();
    private int _applyCount;
    private int _restoreCount;

    public InProcessEnforcementAdapter(string adapterId = "in-process")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(adapterId);
        AdapterId = adapterId;
    }

    public string AdapterId { get; }

    public int ApplyCount => Volatile.Read(ref _applyCount);

    public int RestoreCount => Volatile.Read(ref _restoreCount);

    public Task<EnforcementHealth> CheckHealthAsync(CancellationToken cancellationToken) =>
        Task.FromResult(new EnforcementHealth(
            AdapterId,
            Available: true,
            Healthy: true,
            "In-process test enforcement is available; no operating-system settings are changed."));

    public Task<EnforcementArtifact> ApplyAsync(
        EnforcementContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var artifact = _artifacts.GetOrAdd(
            context.LeaseId,
            leaseId => new EnforcementArtifact(
                AdapterId,
                SchemaVersion: 1,
                [$"in-process:{leaseId:N}"],
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["rule_hash"] = context.RuleHash,
                }));
        Interlocked.Increment(ref _applyCount);
        return Task.FromResult(artifact);
    }

    public Task<EnforcementVerification> VerifyAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(artifact);
        var applied = _artifacts.ContainsKey(context.LeaseId) &&
            string.Equals(artifact.AdapterId, AdapterId, StringComparison.Ordinal) &&
            artifact.OwnedResourceIds.Contains($"in-process:{context.LeaseId:N}", StringComparer.Ordinal);
        return Task.FromResult(new EnforcementVerification(
            AdapterId,
            TargetBlocked: applied,
            GeneralConnectivityAvailable: true,
            applied ? "In-process artifact is active." : "In-process artifact is missing."));
    }

    public Task<RestoreResult> RestoreAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        _artifacts.TryRemove(context.LeaseId, out _);
        Interlocked.Increment(ref _restoreCount);
        return Task.FromResult(new RestoreResult(
            AdapterId,
            Restored: true,
            Retryable: false,
            "In-process artifact is absent."));
    }
}
