using DistractionFirewall.Contracts;

namespace DistractionFirewall.Core.Time;

public static class LeaseDeadlineResolver
{
    public const int MinimumDurationMinutes = 1;

    public const int MaximumDurationMinutes = 12 * 60;

    public static ResolvedLeaseDeadline Resolve(LeaseEndRequest request, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(request);
        nowUtc = nowUtc.ToUniversalTime();

        return request.Mode switch
        {
            LeaseEndMode.Duration => ResolveDuration(request, nowUtc),
            LeaseEndMode.Until => ResolveUntil(request, nowUtc),
            _ => throw new LeaseValidationException(
                LeaseErrorCode.InvalidRequest,
                $"Unknown lease end mode '{request.Mode}'."),
        };
    }

    private static ResolvedLeaseDeadline ResolveDuration(LeaseEndRequest request, DateTimeOffset nowUtc)
    {
        if (request.UntilUtc is not null ||
            request.DurationMinutes is < MinimumDurationMinutes or > MaximumDurationMinutes)
        {
            throw new LeaseValidationException(
                LeaseErrorCode.DurationOutOfRange,
                $"Duration must be between {MinimumDurationMinutes} and {MaximumDurationMinutes} minutes.");
        }

        var duration = TimeSpan.FromMinutes(request.DurationMinutes!.Value);
        DateTimeOffset expiresAtUtc;
        try
        {
            expiresAtUtc = nowUtc.Add(duration);
        }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new LeaseValidationException(
                LeaseErrorCode.DeadlineOutOfRange,
                "The calculated deadline is outside the supported date range.",
                exception);
        }

        return new ResolvedLeaseDeadline(nowUtc, expiresAtUtc, duration);
    }

    private static ResolvedLeaseDeadline ResolveUntil(LeaseEndRequest request, DateTimeOffset nowUtc)
    {
        if (request.DurationMinutes is not null || request.UntilUtc is null)
        {
            throw new LeaseValidationException(
                LeaseErrorCode.InvalidRequest,
                "An absolute lease requires until_utc and must not include duration_minutes.");
        }

        var expiresAtUtc = request.UntilUtc.Value.ToUniversalTime();
        var duration = expiresAtUtc - nowUtc;
        if (duration < TimeSpan.FromMinutes(MinimumDurationMinutes) ||
            duration > TimeSpan.FromMinutes(MaximumDurationMinutes))
        {
            throw new LeaseValidationException(
                LeaseErrorCode.DeadlineOutOfRange,
                "The absolute deadline must be at least one minute and no more than twelve hours away.");
        }

        return new ResolvedLeaseDeadline(nowUtc, expiresAtUtc, duration);
    }
}

public sealed record ResolvedLeaseDeadline(
    DateTimeOffset ResolvedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    TimeSpan RequestedDuration);

public sealed class LeaseValidationException : Exception
{
    public LeaseValidationException(LeaseErrorCode errorCode, string message)
        : base(message)
    {
        ErrorCode = errorCode;
    }

    public LeaseValidationException(LeaseErrorCode errorCode, string message, Exception innerException)
        : base(message, innerException)
    {
        ErrorCode = errorCode;
    }

    public LeaseErrorCode ErrorCode { get; }
}
