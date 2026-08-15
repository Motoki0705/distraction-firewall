namespace DistractionFirewall.Finalizer;

public enum FinalizerMode
{
    ReleaseSession,
    GuardRuntimeUninstall,
    CleanupRuntimeInstallation,
}

public sealed record FinalizerCommand(FinalizerMode Mode, Guid? LeaseId)
{
    public const string Usage =
        "Usage: distraction-firewall-finalizer release --session <lease-guid> | " +
        "guard-runtime-uninstall | cleanup-runtime-installation";

    public static FinalizerCommand Parse(IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        if (arguments.Count == 3 &&
            string.Equals(arguments[0], "release", StringComparison.Ordinal) &&
            string.Equals(arguments[1], "--session", StringComparison.Ordinal) &&
            Guid.TryParseExact(arguments[2], "D", out var leaseId) &&
            leaseId != Guid.Empty)
        {
            return new FinalizerCommand(FinalizerMode.ReleaseSession, leaseId);
        }

        if (arguments.Count == 1 &&
            string.Equals(arguments[0], "guard-runtime-uninstall", StringComparison.Ordinal))
        {
            return new FinalizerCommand(FinalizerMode.GuardRuntimeUninstall, LeaseId: null);
        }

        if (arguments.Count == 1 &&
            string.Equals(arguments[0], "cleanup-runtime-installation", StringComparison.Ordinal))
        {
            return new FinalizerCommand(FinalizerMode.CleanupRuntimeInstallation, LeaseId: null);
        }

        throw new ArgumentException(Usage, nameof(arguments));
    }
}
