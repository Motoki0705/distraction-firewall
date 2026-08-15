using DistractionFirewall.Core.Enforcement;

namespace DistractionFirewall.LeaseLifecycleTests;

internal sealed class ScriptedEnforcementAdapter : IEnforcementAdapter
{
    private readonly Queue<bool> _restoreResults;
    private readonly IList<string>? _restoreOrder;

    public ScriptedEnforcementAdapter(
        string adapterId,
        bool verificationSucceeds = true,
        IEnumerable<bool>? restoreResults = null,
        IList<string>? restoreOrder = null)
    {
        AdapterId = adapterId;
        VerificationSucceeds = verificationSucceeds;
        _restoreResults = new Queue<bool>(restoreResults ?? [true]);
        _restoreOrder = restoreOrder;
    }

    public string AdapterId { get; }

    public int ApplyCount { get; private set; }

    public int RestoreCount { get; private set; }

    public bool VerificationSucceeds { get; set; }

    public Task<EnforcementHealth> CheckHealthAsync(CancellationToken cancellationToken) =>
        Task.FromResult(new EnforcementHealth(AdapterId, Available: true, Healthy: true, "test adapter healthy"));

    public Task<EnforcementArtifact> ApplyAsync(
        EnforcementContext context,
        CancellationToken cancellationToken)
    {
        ApplyCount++;
        return Task.FromResult(new EnforcementArtifact(
            AdapterId,
            SchemaVersion: 1,
            [$"test:{AdapterId}:{context.LeaseId:N}"],
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["rule_hash"] = context.RuleHash,
            }));
    }

    public Task<EnforcementVerification> VerifyAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        CancellationToken cancellationToken) => Task.FromResult(new EnforcementVerification(
            AdapterId,
            TargetBlocked: VerificationSucceeds,
            GeneralConnectivityAvailable: true,
            VerificationSucceeds ? "blocked" : "not blocked"));

    public Task<RestoreResult> RestoreAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        CancellationToken cancellationToken)
    {
        RestoreCount++;
        _restoreOrder?.Add(AdapterId);
        var restored = _restoreResults.Count == 0 || _restoreResults.Dequeue();
        return Task.FromResult(new RestoreResult(
            AdapterId,
            restored,
            Retryable: !restored,
            restored ? "restored" : "retry"));
    }
}

internal sealed class ReconciliationEnforcementAdapter : IEnforcementReconciliationAdapter
{
    private bool _requireReconciliation;

    public string AdapterId => "reconciliation";

    public int ApplyCount { get; private set; }

    public int ReconcileCount { get; private set; }

    public EnforcementArtifact? ReconciliationInput { get; private set; }

    public void RequireReconciliation() => _requireReconciliation = true;

    public Task<EnforcementHealth> CheckHealthAsync(CancellationToken cancellationToken) =>
        Task.FromResult(new EnforcementHealth(AdapterId, Available: true, Healthy: true, "healthy"));

    public Task<EnforcementArtifact> ApplyAsync(
        EnforcementContext context,
        CancellationToken cancellationToken)
    {
        ApplyCount++;
        return Task.FromResult(CreateArtifact(context.LeaseId, "initial"));
    }

    public Task<EnforcementArtifact> ReconcileAsync(
        EnforcementContext context,
        EnforcementArtifact existingArtifact,
        CancellationToken cancellationToken)
    {
        ReconcileCount++;
        ReconciliationInput = existingArtifact;
        return Task.FromResult(CreateArtifact(context.LeaseId, "reconciled"));
    }

    public Task<EnforcementVerification> VerifyAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        CancellationToken cancellationToken)
    {
        var reconciled = artifact.Properties.TryGetValue("generation", out var generation) &&
            string.Equals(generation, "reconciled", StringComparison.Ordinal);
        var blocked = !_requireReconciliation || reconciled;
        return Task.FromResult(new EnforcementVerification(
            AdapterId,
            TargetBlocked: blocked,
            GeneralConnectivityAvailable: true,
            blocked ? "blocked" : "reconciliation required"));
    }

    public Task<RestoreResult> RestoreAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        CancellationToken cancellationToken) =>
        Task.FromResult(new RestoreResult(AdapterId, Restored: true, Retryable: false, "restored"));

    private EnforcementArtifact CreateArtifact(Guid leaseId, string generation) => new(
        AdapterId,
        SchemaVersion: 1,
        [$"reconciliation:{leaseId:N}"],
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["generation"] = generation,
        });
}
