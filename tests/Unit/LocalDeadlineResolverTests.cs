using DistractionFirewall.Core.Time;

namespace DistractionFirewall.UnitTests;

public sealed class LocalDeadlineResolverTests
{
    private static readonly TimeZoneInfo DstZone = CreateDstZone();

    [Fact]
    public void Resolve_rejects_a_clock_time_in_the_dst_gap()
    {
        var result = LocalDeadlineResolver.Resolve(new DateTime(2026, 3, 8, 2, 30, 0), DstZone);

        Assert.Equal(LocalDeadlineStatus.Invalid, result.Status);
        Assert.Empty(result.Candidates);
    }

    [Fact]
    public void Resolve_returns_both_offsets_in_the_dst_fold()
    {
        var result = LocalDeadlineResolver.Resolve(new DateTime(2026, 11, 1, 1, 30, 0), DstZone);

        Assert.Equal(LocalDeadlineStatus.Ambiguous, result.Status);
        Assert.Equal(2, result.Candidates.Count);
        Assert.Equal(TimeSpan.FromHours(1), result.Candidates[1].UtcDateTime - result.Candidates[0].UtcDateTime);
    }

    private static TimeZoneInfo CreateDstZone()
    {
        var daylightDelta = TimeSpan.FromHours(1);
        var start = TimeZoneInfo.TransitionTime.CreateFloatingDateRule(
            new DateTime(1, 1, 1, 2, 0, 0),
            3,
            2,
            DayOfWeek.Sunday);
        var end = TimeZoneInfo.TransitionTime.CreateFloatingDateRule(
            new DateTime(1, 1, 1, 2, 0, 0),
            11,
            1,
            DayOfWeek.Sunday);
        var rule = TimeZoneInfo.AdjustmentRule.CreateAdjustmentRule(
            new DateTime(2020, 1, 1),
            new DateTime(2030, 12, 31),
            daylightDelta,
            start,
            end);
        return TimeZoneInfo.CreateCustomTimeZone(
            "Test/DST",
            TimeSpan.FromHours(-5),
            "Test DST zone",
            "Test standard",
            "Test daylight",
            [rule]);
    }
}
