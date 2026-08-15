using DistractionFirewall.Contracts;

namespace DistractionFirewall.Core.Leases;

public static class LeaseStateMachine
{
    private static readonly Dictionary<LeaseState, IReadOnlySet<LeaseState>> AllowedTransitions =
        new Dictionary<LeaseState, IReadOnlySet<LeaseState>>
        {
            [LeaseState.Idle] = new HashSet<LeaseState> { LeaseState.Prepared },
            [LeaseState.Prepared] = new HashSet<LeaseState> { LeaseState.Activating },
            [LeaseState.Activating] = new HashSet<LeaseState> { LeaseState.Active, LeaseState.Releasing },
            [LeaseState.Active] = new HashSet<LeaseState> { LeaseState.Releasing },
            [LeaseState.Releasing] = new HashSet<LeaseState> { LeaseState.Completed },
            [LeaseState.Completed] = new HashSet<LeaseState>(),
        };

    public static LeaseRuntimeState Transition(
        LeaseRuntimeState current,
        LeaseState next,
        DateTimeOffset changedAtUtc,
        LeaseHealth? health = null,
        string? errorCode = null)
    {
        ArgumentNullException.ThrowIfNull(current);
        if (!AllowedTransitions[current.State].Contains(next))
        {
            throw new InvalidOperationException($"Lease state cannot transition from {current.State} to {next}.");
        }

        return current with
        {
            State = next,
            Sequence = checked(current.Sequence + 1),
            UpdatedAtUtc = changedAtUtc.ToUniversalTime(),
            Health = health ?? current.Health,
            LastErrorCode = errorCode,
        };
    }

    public static LeaseRuntimeState WithInstallState(
        LeaseRuntimeState current,
        AppInstallState appState,
        RuntimeInstallIntent runtimeIntent,
        RuntimeInstallState runtimeState,
        DateTimeOffset changedAtUtc) => current with
        {
            AppInstallState = appState,
            RuntimeInstallIntent = runtimeIntent,
            RuntimeInstallState = runtimeState,
            Sequence = checked(current.Sequence + 1),
            UpdatedAtUtc = changedAtUtc.ToUniversalTime(),
        };
}
