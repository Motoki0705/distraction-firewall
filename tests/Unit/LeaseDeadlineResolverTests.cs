using DistractionFirewall.Contracts;
using DistractionFirewall.Core.Time;

namespace DistractionFirewall.UnitTests;

public sealed class LeaseDeadlineResolverTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 15, 3, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(1)]
    [InlineData(720)]
    public void Resolve_duration_accepts_documented_boundaries(int minutes)
    {
        var request = new LeaseEndRequest(LeaseEndMode.Duration, minutes, null);

        var result = LeaseDeadlineResolver.Resolve(request, Now);

        Assert.Equal(TimeSpan.FromMinutes(minutes), result.RequestedDuration);
        Assert.Equal(Now.AddMinutes(minutes), result.ExpiresAtUtc);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(721)]
    [InlineData(-1)]
    public void Resolve_duration_rejects_values_outside_range(int minutes)
    {
        var request = new LeaseEndRequest(LeaseEndMode.Duration, minutes, null);

        var exception = Assert.Throws<LeaseValidationException>(
            () => LeaseDeadlineResolver.Resolve(request, Now));

        Assert.Equal(LeaseErrorCode.DurationOutOfRange, exception.ErrorCode);
    }

    [Fact]
    public void Resolve_until_does_not_round_a_deadline_over_twelve_hours()
    {
        var request = new LeaseEndRequest(LeaseEndMode.Until, null, Now.AddHours(12).AddTicks(1));

        var exception = Assert.Throws<LeaseValidationException>(
            () => LeaseDeadlineResolver.Resolve(request, Now));

        Assert.Equal(LeaseErrorCode.DeadlineOutOfRange, exception.ErrorCode);
    }

    [Fact]
    public void Resolve_rejects_mixed_duration_and_until_fields()
    {
        var request = new LeaseEndRequest(LeaseEndMode.Duration, 60, Now.AddHours(1));

        Assert.Throws<LeaseValidationException>(() => LeaseDeadlineResolver.Resolve(request, Now));
    }
}
