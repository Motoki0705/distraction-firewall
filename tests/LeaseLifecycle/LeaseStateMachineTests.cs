using DistractionFirewall.Contracts;
using DistractionFirewall.Core.Leases;

namespace DistractionFirewall.LeaseLifecycleTests;

public sealed class LeaseStateMachineTests
{
    [Fact]
    public void Documented_activation_and_completion_path_is_valid()
    {
        var state = CreateState(LeaseState.Idle);

        state = LeaseStateMachine.Transition(state, LeaseState.Prepared, Now());
        state = LeaseStateMachine.Transition(state, LeaseState.Activating, Now());
        state = LeaseStateMachine.Transition(state, LeaseState.Active, Now(), LeaseHealth.Healthy);
        state = LeaseStateMachine.Transition(state, LeaseState.Releasing, Now());
        state = LeaseStateMachine.Transition(state, LeaseState.Completed, Now());

        Assert.Equal(LeaseState.Completed, state.State);
        Assert.Equal(5, state.Sequence);
    }

    [Theory]
    [InlineData(LeaseState.Active, LeaseState.Completed)]
    [InlineData(LeaseState.Active, LeaseState.Prepared)]
    [InlineData(LeaseState.Completed, LeaseState.Active)]
    public void Invalid_or_early_release_transitions_are_rejected(LeaseState current, LeaseState next)
    {
        Assert.Throws<InvalidOperationException>(
            () => LeaseStateMachine.Transition(CreateState(current), next, Now()));
    }

    [Fact]
    public void App_removal_and_runtime_uninstall_intent_do_not_end_an_active_lease()
    {
        var active = CreateState(LeaseState.Active);

        var updated = LeaseStateMachine.WithInstallState(
            active,
            AppInstallState.Removed,
            RuntimeInstallIntent.RemoveAfterCompletion,
            RuntimeInstallState.Installed,
            Now());

        Assert.Equal(LeaseState.Active, updated.State);
        Assert.Equal(AppInstallState.Removed, updated.AppInstallState);
        Assert.Equal(RuntimeInstallIntent.RemoveAfterCompletion, updated.RuntimeInstallIntent);
    }

    private static DateTimeOffset Now() => new(2026, 8, 15, 0, 0, 0, TimeSpan.Zero);

    private static LeaseRuntimeState CreateState(LeaseState state) => new()
    {
        LeaseId = Guid.Parse("048a6f96-c278-4722-af3d-b47f15c85180"),
        State = state,
        Sequence = 0,
        UpdatedAtUtc = Now(),
        LastHeartbeatUtc = null,
        Health = LeaseHealth.Unknown,
        AppInstallState = AppInstallState.Installed,
        RuntimeInstallIntent = RuntimeInstallIntent.Keep,
        RuntimeInstallState = RuntimeInstallState.Installed,
    };
}
