using DistractionFirewall.Contracts;
using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Core.Leases;
using DistractionFirewall.Finalizer;
using DistractionFirewall.LeaseWorker;

namespace DistractionFirewall.LeaseLifecycleTests;

public sealed class WorkerAndFinalizerTests
{
    [Fact]
    public async Task Boot_recovery_exits_cleanly_when_no_lease_is_active()
    {
        using var workspace = new TestWorkspace();
        var runtime = new LeaseRuntimeCoordinator(
            workspace.Store,
            [new InProcessEnforcementAdapter()],
            new MutableTimeAuthority(TestData.Now));
        var worker = new LeaseWorkerHost(workspace.Store, runtime);

        var state = await worker.RecoverActiveAsync(CancellationToken.None);

        Assert.Null(state);
    }

    [Fact]
    public async Task Worker_restores_and_completes_an_expired_lease()
    {
        using var workspace = new TestWorkspace();
        var time = new MutableTimeAuthority(TestData.Now);
        var adapter = new InProcessEnforcementAdapter();
        var runtime = new LeaseRuntimeCoordinator(workspace.Store, [adapter], time);
        var leaseId = Guid.NewGuid();
        await workspace.Store.CreateCapsuleAsync(
            TestData.Manifest(
                leaseId,
                expiresAtUtc: TestData.Now.AddMinutes(1),
                requestedDuration: TimeSpan.FromMinutes(1)),
            TestData.State(leaseId, LeaseState.Activating),
            CancellationToken.None);
        _ = await runtime.ActivateAsync(leaseId, CancellationToken.None);
        time.Advance(TimeSpan.FromMinutes(2));
        var worker = new LeaseWorkerHost(workspace.Store, runtime, TimeSpan.FromMilliseconds(1));

        var state = await worker.RunAsync(leaseId, CancellationToken.None);

        Assert.Equal(LeaseState.Completed, state.State);
        Assert.Equal(1, adapter.RestoreCount);
        Assert.False(await workspace.Store.HasActiveLeaseAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Finalizer_is_idempotent_after_completion()
    {
        using var workspace = new TestWorkspace();
        var adapter = new InProcessEnforcementAdapter();
        var runtime = new LeaseRuntimeCoordinator(
            workspace.Store,
            [adapter],
            new MutableTimeAuthority(TestData.Now));
        var leaseId = Guid.NewGuid();
        await workspace.Store.CreateCapsuleAsync(
            TestData.Manifest(leaseId),
            TestData.State(leaseId, LeaseState.Activating),
            CancellationToken.None);
        _ = await runtime.ActivateAsync(leaseId, CancellationToken.None);
        var finalizer = new LeaseFinalizer(runtime);

        var first = await finalizer.RunAsync(leaseId, CancellationToken.None);
        var second = await finalizer.RunAsync(leaseId, CancellationToken.None);

        Assert.Equal(LeaseState.Completed, first.State);
        Assert.Equal(first, second);
        Assert.Equal(1, adapter.RestoreCount);
    }

    [Fact]
    public async Task Finalizer_host_refuses_early_release_but_allows_expired_release()
    {
        using var workspace = new TestWorkspace();
        var time = new MutableTimeAuthority(TestData.Now);
        var adapter = new InProcessEnforcementAdapter();
        var runtime = new LeaseRuntimeCoordinator(workspace.Store, [adapter], time);
        var leaseId = Guid.NewGuid();
        await workspace.Store.CreateCapsuleAsync(
            TestData.Manifest(leaseId),
            TestData.State(leaseId, LeaseState.Activating),
            CancellationToken.None);
        _ = await runtime.ActivateAsync(leaseId, CancellationToken.None);
        var host = new FinalizerHost(
            workspace.Store,
            time,
            new LeaseFinalizer(runtime));

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            host.RunExpiredOrPendingAsync(leaseId, CancellationToken.None));
        time.Advance(TimeSpan.FromHours(2));
        var completed = await host.RunExpiredOrPendingAsync(leaseId, CancellationToken.None);

        Assert.Equal(LeaseState.Completed, completed.State);
    }
}
