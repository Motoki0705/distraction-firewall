using DistractionFirewall.Core.Time;

namespace DistractionFirewall.Core.Leases;

public static class LeaseExpiryEvaluator
{
    public static bool IsExpired(LeaseManifest manifest, TimeSnapshot current)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(current);

        if (current.UtcNow < manifest.ExpiresAtUtc)
        {
            return false;
        }

        if (!string.Equals(current.BootId, manifest.BootId, StringComparison.Ordinal))
        {
            return true;
        }

        if (manifest.MonotonicFrequency <= 0 || current.MonotonicFrequency != manifest.MonotonicFrequency)
        {
            return false;
        }

        var elapsedTicks = current.MonotonicTicks - manifest.MonotonicAnchorTicks;
        if (elapsedTicks < 0)
        {
            return false;
        }

        var requiredTicks = manifest.RequestedDuration.TotalSeconds * manifest.MonotonicFrequency;
        return elapsedTicks >= requiredTicks;
    }
}
