namespace DistractionFirewall.Core.Time;

public sealed record TimeSnapshot(
    DateTimeOffset UtcNow,
    string BootId,
    long MonotonicTicks,
    long MonotonicFrequency);

public interface ITimeAuthority
{
    TimeSnapshot Capture();
}

public sealed class SystemTimeAuthority : ITimeAuthority
{
    private readonly string _bootId = $"process-fallback-{Environment.TickCount64}";

    public TimeSnapshot Capture() => new(
        DateTimeOffset.UtcNow,
        _bootId,
        System.Diagnostics.Stopwatch.GetTimestamp(),
        System.Diagnostics.Stopwatch.Frequency);
}
