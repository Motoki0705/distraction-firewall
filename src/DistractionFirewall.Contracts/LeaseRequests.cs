namespace DistractionFirewall.Contracts;

public sealed record ProtocolRequest(int ProtocolVersion);

public sealed record LeaseEndRequest(
    LeaseEndMode Mode,
    int? DurationMinutes,
    DateTimeOffset? UntilUtc,
    string? InputTimeZoneId = null,
    DateTime? InputLocalTime = null);

public sealed record PrepareLeaseRequest(
    int ProtocolVersion,
    Guid RequestId,
    IReadOnlyList<string> TargetIds,
    LeaseEndRequest End);

public sealed record CommitLeaseRequest(
    int ProtocolVersion,
    Guid RequestId,
    Guid PreparationId,
    string Nonce);
