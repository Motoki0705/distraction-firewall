using DistractionFirewall.Contracts;
using DistractionFirewall.Core.Leases;
using DistractionFirewall.Runtime.Windows;

namespace DistractionFirewall.LeaseLifecycleTests;

public sealed class ScheduledTaskLeaseWorkerLauncherTests
{
    [Fact]
    public async Task Launch_requires_fixed_task_and_confirms_capsule_sequence_progress()
    {
        using var workspace = new TestWorkspace();
        var leaseId = Guid.NewGuid();
        var active = TestData.State(leaseId, LeaseState.Active, sequence: 1);
        await workspace.Store.CreateCapsuleAsync(
            TestData.Manifest(leaseId),
            active,
            CancellationToken.None);
        var controller = new FakeRecoveryTaskController(async cancellationToken =>
        {
            var current = await workspace.Store.GetStateAsync(leaseId, cancellationToken)
                ?? throw new InvalidOperationException("test state missing");
            await workspace.Store.SaveStateAsync(
                current with
                {
                    Sequence = current.Sequence + 1,
                    UpdatedAtUtc = TestData.Now.AddSeconds(1),
                    LastHeartbeatUtc = TestData.Now.AddSeconds(1),
                },
                cancellationToken);
        });
        var launcher = new ScheduledTaskLeaseWorkerLauncher(
            workspace.Store,
            controller,
            confirmationTimeout: TimeSpan.FromMilliseconds(100),
            pollInterval: TimeSpan.FromMilliseconds(1));

        var health = await launcher.CheckHealthAsync(CancellationToken.None);
        var result = await launcher.LaunchAsync(leaseId, CancellationToken.None);

        Assert.True(health.Started);
        Assert.True(result.Started);
        Assert.Equal(1, controller.RunCount);
        Assert.Contains("sequence 2", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Launch_does_not_run_task_for_non_active_capsule()
    {
        using var workspace = new TestWorkspace();
        var controller = new FakeRecoveryTaskController(_ => Task.CompletedTask);
        var launcher = new ScheduledTaskLeaseWorkerLauncher(
            workspace.Store,
            controller,
            confirmationTimeout: TimeSpan.FromMilliseconds(20),
            pollInterval: TimeSpan.FromMilliseconds(1));

        var result = await launcher.LaunchAsync(Guid.NewGuid(), CancellationToken.None);

        Assert.False(result.Started);
        Assert.Equal(0, controller.RunCount);
    }

    private sealed class FakeRecoveryTaskController : IRecoveryTaskController
    {
        private readonly Func<CancellationToken, Task> _runAsync;

        public FakeRecoveryTaskController(Func<CancellationToken, Task> runAsync)
        {
            _runAsync = runAsync;
        }

        public int RunCount { get; private set; }

        public Task<LeaseWorkerLaunchResult> CheckInfrastructureAsync(
            CancellationToken cancellationToken) => Task.FromResult(
                new LeaseWorkerLaunchResult(Started: true, "fake scheduler healthy"));

        public async Task RunAsync(CancellationToken cancellationToken)
        {
            RunCount++;
            await _runAsync(cancellationToken);
        }
    }
}
