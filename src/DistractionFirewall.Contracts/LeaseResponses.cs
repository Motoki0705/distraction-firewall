namespace DistractionFirewall.Contracts;

public sealed record LeaseWarning(
    string Code,
    string Message);

public sealed record PrepareLeaseResponse(
    int ProtocolVersion,
    Guid PreparationId,
    string Nonce,
    DateTimeOffset PreparedAtUtc,
    DateTimeOffset PreparationExpiresAtUtc,
    DateTimeOffset ResolvedExpiresAtUtc,
    TimeSpan RequestedDuration,
    IReadOnlyList<TargetSnapshotDto> Targets,
    string RuleHash,
    IReadOnlyList<LeaseWarning> Warnings);

public sealed record CommitLeaseResponse(
    int ProtocolVersion,
    Guid LeaseId,
    LeaseState State,
    DateTimeOffset ActivatedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    IReadOnlyList<TargetSnapshotDto> Targets,
    LeaseHealth Health);

public sealed record LeaseStatusResponse(
    int ProtocolVersion,
    LeaseState State,
    Guid? LeaseId,
    DateTimeOffset? ActivatedAtUtc,
    DateTimeOffset? ExpiresAtUtc,
    IReadOnlyList<TargetSnapshotDto> Targets,
    LeaseHealth Health,
    AppInstallState AppInstallState,
    RuntimeInstallIntent RuntimeInstallIntent,
    RuntimeInstallState RuntimeInstallState,
    long Sequence);

public sealed record CapabilitiesResponse(
    int ProtocolVersion,
    int MinimumDurationMinutes,
    int MaximumDurationMinutes,
    int MaximumActiveLeases,
    bool SupportsAbsoluteDeadline,
    IReadOnlyList<string> Methods);

public sealed record DiagnosticCheck(
    string Id,
    string DisplayName,
    DiagnosticSeverity Severity,
    bool IsHealthy,
    string Summary);

public sealed record DiagnosticsResponse(
    int ProtocolVersion,
    DateTimeOffset CheckedAtUtc,
    IReadOnlyList<DiagnosticCheck> Checks);
