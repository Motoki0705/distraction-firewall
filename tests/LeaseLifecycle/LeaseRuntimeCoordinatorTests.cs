using DistractionFirewall.Contracts;
using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Core.Leases;

namespace DistractionFirewall.LeaseLifecycleTests;

public sealed class LeaseRuntimeCoordinatorTests
{
    [Fact]
    public async Task Verification_failure_rolls_back_artifacts_in_reverse_order()
    {
        using var workspace = new TestWorkspace();
        var restoreOrder = new List<string>();
        var first = new ScriptedEnforcementAdapter("first", restoreOrder: restoreOrder);
        var second = new ScriptedEnforcementAdapter(
            "second",
            verificationSucceeds: false,
            restoreOrder: restoreOrder);
        var runtime = new LeaseRuntimeCoordinator(
            workspace.Store,
            [first, second],
            new MutableTimeAuthority(TestData.Now));
        var leaseId = Guid.NewGuid();
        await workspace.Store.CreateCapsuleAsync(
            TestData.Manifest(leaseId),
            TestData.State(leaseId, LeaseState.Activating),
            CancellationToken.None);

        var exception = await Assert.ThrowsAsync<LeaseRuntimeException>(() =>
            runtime.ActivateAsync(leaseId, CancellationToken.None));

        Assert.Equal(LeaseState.Completed, exception.State.State);
        Assert.Equal(["second", "first"], restoreOrder);
        Assert.Equal(1, first.ApplyCount);
        Assert.Equal(1, second.ApplyCount);
        Assert.Empty(await workspace.Store.GetArtifactsAsync(leaseId, CancellationToken.None));
        Assert.False(await workspace.Store.HasActiveLeaseAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Failed_restore_stays_release_pending_and_next_run_completes()
    {
        using var workspace = new TestWorkspace();
        var adapter = new ScriptedEnforcementAdapter("retryable", restoreResults: [false, true]);
        var time = new MutableTimeAuthority(TestData.Now);
        var runtime = new LeaseRuntimeCoordinator(workspace.Store, [adapter], time);
        var leaseId = Guid.NewGuid();
        await workspace.Store.CreateCapsuleAsync(
            TestData.Manifest(leaseId),
            TestData.State(leaseId, LeaseState.Activating),
            CancellationToken.None);
        _ = await runtime.ActivateAsync(leaseId, CancellationToken.None);

        var pending = await runtime.ReleaseAsync(leaseId, CancellationToken.None);
        var completed = await runtime.ReleaseAsync(leaseId, CancellationToken.None);

        Assert.Equal(LeaseState.Releasing, pending.State);
        Assert.Equal(LeaseHealth.ReleasePending, pending.Health);
        Assert.Equal(LeaseState.Completed, completed.State);
        Assert.Equal(2, adapter.RestoreCount);
        Assert.Empty(await workspace.Store.GetArtifactsAsync(leaseId, CancellationToken.None));
    }

    [Fact]
    public async Task Active_reconciliation_verifies_existing_artifact_and_updates_heartbeat()
    {
        using var workspace = new TestWorkspace();
        var adapter = new ScriptedEnforcementAdapter("stable");
        var time = new MutableTimeAuthority(TestData.Now);
        var runtime = new LeaseRuntimeCoordinator(workspace.Store, [adapter], time);
        var leaseId = Guid.NewGuid();
        await workspace.Store.CreateCapsuleAsync(
            TestData.Manifest(leaseId),
            TestData.State(leaseId, LeaseState.Activating),
            CancellationToken.None);
        var activated = await runtime.ActivateAsync(leaseId, CancellationToken.None);
        time.Advance(TimeSpan.FromSeconds(10));

        var reconciled = await runtime.ReconcileAsync(leaseId, CancellationToken.None);

        Assert.Equal(1, adapter.ApplyCount);
        Assert.True(reconciled.Sequence > activated.Sequence);
        Assert.Equal(TestData.Now.AddSeconds(10), reconciled.LastHeartbeatUtc);
        Assert.Equal(LeaseHealth.Healthy, reconciled.Health);
    }

    [Fact]
    public async Task Failed_verification_uses_optional_reconciliation_with_existing_artifact()
    {
        using var workspace = new TestWorkspace();
        var adapter = new ReconciliationEnforcementAdapter();
        var time = new MutableTimeAuthority(TestData.Now);
        var runtime = new LeaseRuntimeCoordinator(workspace.Store, [adapter], time);
        var leaseId = Guid.NewGuid();
        await workspace.Store.CreateCapsuleAsync(
            TestData.Manifest(leaseId),
            TestData.State(leaseId, LeaseState.Activating),
            CancellationToken.None);
        _ = await runtime.ActivateAsync(leaseId, CancellationToken.None);
        var original = Assert.Single(
            await workspace.Store.GetArtifactsAsync(leaseId, CancellationToken.None));
        adapter.RequireReconciliation();

        var state = await runtime.ReconcileAsync(leaseId, CancellationToken.None);

        Assert.Equal(LeaseState.Active, state.State);
        Assert.Equal(LeaseHealth.Healthy, state.Health);
        Assert.Equal(1, adapter.ApplyCount);
        Assert.Equal(1, adapter.ReconcileCount);
        var input = Assert.IsType<EnforcementArtifact>(adapter.ReconciliationInput);
        Assert.Equal(original.AdapterId, input.AdapterId);
        Assert.Equal(original.SchemaVersion, input.SchemaVersion);
        Assert.Equal(original.OwnedResourceIds, input.OwnedResourceIds);
        Assert.Equal(original.Properties, input.Properties);
        Assert.Equal("initial", input.Properties["generation"]);
        var persisted = Assert.Single(
            await workspace.Store.GetArtifactsAsync(leaseId, CancellationToken.None));
        Assert.Equal("reconciled", persisted.Properties["generation"]);
    }

    [Fact]
    public async Task Existing_artifact_is_retained_when_adapter_cannot_reconcile()
    {
        using var workspace = new TestWorkspace();
        var adapter = new ScriptedEnforcementAdapter("legacy");
        var time = new MutableTimeAuthority(TestData.Now);
        var runtime = new LeaseRuntimeCoordinator(workspace.Store, [adapter], time);
        var leaseId = Guid.NewGuid();
        await workspace.Store.CreateCapsuleAsync(
            TestData.Manifest(leaseId),
            TestData.State(leaseId, LeaseState.Activating),
            CancellationToken.None);
        _ = await runtime.ActivateAsync(leaseId, CancellationToken.None);
        var original = Assert.Single(
            await workspace.Store.GetArtifactsAsync(leaseId, CancellationToken.None));
        adapter.VerificationSucceeds = false;

        var state = await runtime.ReconcileAsync(leaseId, CancellationToken.None);

        Assert.Equal(LeaseState.Active, state.State);
        Assert.Equal(LeaseHealth.Degraded, state.Health);
        Assert.Equal(1, adapter.ApplyCount);
        var retained = Assert.Single(
            await workspace.Store.GetArtifactsAsync(leaseId, CancellationToken.None));
        Assert.Equal(original.AdapterId, retained.AdapterId);
        Assert.Equal(original.OwnedResourceIds, retained.OwnedResourceIds);
        Assert.Equal(original.Properties, retained.Properties);
    }
}
