using DistractionFirewall.Contracts;
using DistractionFirewall.Core.Targets;

namespace DistractionFirewall.Core.Leases;

public sealed record PreparedLease
{
    public required Guid PreparationId { get; init; }

    public required Guid RequestId { get; init; }

    public required string RequestFingerprint { get; init; }

    public required string NonceHash { get; init; }

    public required DateTimeOffset PreparedAtUtc { get; init; }

    public required DateTimeOffset PreparationExpiresAtUtc { get; init; }

    public required DateTimeOffset ResolvedExpiresAtUtc { get; init; }

    public required TimeSpan RequestedDuration { get; init; }

    public required IReadOnlyList<TargetDefinition> TargetSnapshot { get; init; }

    public required string RuleHash { get; init; }
}

public sealed record LeaseManifest
{
    public const int CurrentSchemaVersion = 1;

    public required int SchemaVersion { get; init; }

    public required Guid LeaseId { get; init; }

    public required IReadOnlyList<TargetDefinition> TargetSnapshot { get; init; }

    public required string RuleHash { get; init; }

    public required DateTimeOffset CreatedAtUtc { get; init; }

    public required DateTimeOffset ActivatedAtUtc { get; init; }

    public required DateTimeOffset ExpiresAtUtc { get; init; }

    public required TimeSpan RequestedDuration { get; init; }

    public required string BootId { get; init; }

    public required long MonotonicAnchorTicks { get; init; }

    public required long MonotonicFrequency { get; init; }

    public required RuntimeInstallIntent InstallIntent { get; init; }

    public Guid PreparationId { get; init; }

    public Guid PrepareRequestId { get; init; }

    public Guid CommitRequestId { get; init; }

    public string CommitRequestFingerprint { get; init; } = string.Empty;
}

public sealed record LeaseRuntimeState
{
    public required Guid LeaseId { get; init; }

    public required LeaseState State { get; init; }

    public required long Sequence { get; init; }

    public required DateTimeOffset UpdatedAtUtc { get; init; }

    public required DateTimeOffset? LastHeartbeatUtc { get; init; }

    public required LeaseHealth Health { get; init; }

    public required AppInstallState AppInstallState { get; init; }

    public required RuntimeInstallIntent RuntimeInstallIntent { get; init; }

    public required RuntimeInstallState RuntimeInstallState { get; init; }

    public string? LastErrorCode { get; init; }

    public bool WorkerHandoffCompleted { get; init; }
}
