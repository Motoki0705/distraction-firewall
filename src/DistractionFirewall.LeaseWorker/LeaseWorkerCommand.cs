namespace DistractionFirewall.LeaseWorker;

public enum LeaseWorkerMode
{
    BootRecovery,
    ReconcileSession,
}

public sealed record LeaseWorkerCommand(LeaseWorkerMode Mode, Guid? LeaseId)
{
    public const string Usage =
        "Usage: distraction-firewall-lease-worker [reconcile --session <lease-guid>]";

    public static LeaseWorkerCommand Parse(IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        if (arguments.Count == 0)
        {
            return new LeaseWorkerCommand(LeaseWorkerMode.BootRecovery, LeaseId: null);
        }

        if (arguments.Count == 3 &&
            string.Equals(arguments[0], "reconcile", StringComparison.Ordinal) &&
            string.Equals(arguments[1], "--session", StringComparison.Ordinal) &&
            Guid.TryParseExact(arguments[2], "D", out var leaseId) &&
            leaseId != Guid.Empty)
        {
            return new LeaseWorkerCommand(LeaseWorkerMode.ReconcileSession, leaseId);
        }

        throw new ArgumentException(Usage, nameof(arguments));
    }
}
