namespace DistractionFirewall.Core.Time;

public enum LocalDeadlineStatus
{
    Valid,
    Ambiguous,
    Invalid,
}

public sealed record LocalDeadlineResolution(
    LocalDeadlineStatus Status,
    IReadOnlyList<DateTimeOffset> Candidates);

public static class LocalDeadlineResolver
{
    public static LocalDeadlineResolution Resolve(DateTime localTime, TimeZoneInfo timeZone)
    {
        ArgumentNullException.ThrowIfNull(timeZone);
        localTime = DateTime.SpecifyKind(localTime, DateTimeKind.Unspecified);

        if (timeZone.IsInvalidTime(localTime))
        {
            return new LocalDeadlineResolution(LocalDeadlineStatus.Invalid, Array.Empty<DateTimeOffset>());
        }

        if (timeZone.IsAmbiguousTime(localTime))
        {
            var candidates = timeZone.GetAmbiguousTimeOffsets(localTime)
                .Select(offset => new DateTimeOffset(localTime, offset))
                .OrderBy(candidate => candidate.UtcDateTime)
                .ToArray();
            return new LocalDeadlineResolution(LocalDeadlineStatus.Ambiguous, candidates);
        }

        var candidate = new DateTimeOffset(localTime, timeZone.GetUtcOffset(localTime));
        return new LocalDeadlineResolution(LocalDeadlineStatus.Valid, [candidate]);
    }
}
