using DistractionFirewall.Contracts;
using DistractionFirewall.Core.Leases;
using DistractionFirewall.Core.Targets;
using DistractionFirewall.Core.Time;

namespace DistractionFirewall.UnitTests;

public sealed class LeaseExpiryEvaluatorTests
{
    [Fact]
    public void Same_boot_requires_both_utc_and_monotonic_deadlines()
    {
        var manifest = CreateManifest();

        Assert.False(LeaseExpiryEvaluator.IsExpired(
            manifest,
            new TimeSnapshot(manifest.ExpiresAtUtc, "boot-a", 9_999, 1_000)));
        Assert.True(LeaseExpiryEvaluator.IsExpired(
            manifest,
            new TimeSnapshot(manifest.ExpiresAtUtc, "boot-a", 10_000, 1_000)));
    }

    [Fact]
    public void New_boot_releases_when_persisted_utc_deadline_has_passed()
    {
        var manifest = CreateManifest();

        Assert.True(LeaseExpiryEvaluator.IsExpired(
            manifest,
            new TimeSnapshot(manifest.ExpiresAtUtc, "boot-b", 0, 1_000)));
    }

    private static LeaseManifest CreateManifest() => new()
    {
        SchemaVersion = LeaseManifest.CurrentSchemaVersion,
        LeaseId = Guid.Parse("80cbad71-adf1-49ab-a75d-b71f13d84cef"),
        TargetSnapshot = Array.Empty<TargetDefinition>(),
        RuleHash = new string('a', 64),
        CreatedAtUtc = new DateTimeOffset(2026, 8, 15, 0, 0, 0, TimeSpan.Zero),
        ActivatedAtUtc = new DateTimeOffset(2026, 8, 15, 0, 0, 0, TimeSpan.Zero),
        ExpiresAtUtc = new DateTimeOffset(2026, 8, 15, 0, 0, 10, TimeSpan.Zero),
        RequestedDuration = TimeSpan.FromSeconds(10),
        BootId = "boot-a",
        MonotonicAnchorTicks = 0,
        MonotonicFrequency = 1_000,
        InstallIntent = RuntimeInstallIntent.Keep,
    };
}
