using DistractionFirewall.ActivationService;
using DistractionFirewall.Contracts;
using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Core.Leases;

namespace DistractionFirewall.LeaseLifecycleTests;

public sealed class LeaseActivationCoordinatorTests
{
    [Fact]
    public async Task Prepare_is_idempotent_and_persists_only_nonce_hash()
    {
        using var harness = new ActivationHarness();
        var request = PrepareRequest(Guid.NewGuid());

        var first = await harness.Coordinator.PrepareAsync(request, CancellationToken.None);
        var second = await harness.Coordinator.PrepareAsync(request, CancellationToken.None);

        Assert.Equal(first.PreparationId, second.PreparationId);
        Assert.Equal(first.Nonce, second.Nonce);
        Assert.Equal(first.RuleHash, second.RuleHash);
        Assert.Equal(first.Targets, second.Targets);
        var preparationPath = Path.Combine(
            harness.Workspace.RootPath,
            "preparations",
            $"{first.PreparationId:N}.json");
        var persistedJson = await File.ReadAllTextAsync(preparationPath, CancellationToken.None);
        Assert.DoesNotContain(first.Nonce, persistedJson, StringComparison.Ordinal);
        Assert.Contains(LeaseNonceService.HashNonce(first.Nonce), persistedJson, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Prepare_request_id_cannot_be_reused_with_changed_payload()
    {
        using var harness = new ActivationHarness();
        var requestId = Guid.NewGuid();
        _ = await harness.Coordinator.PrepareAsync(PrepareRequest(requestId), CancellationToken.None);

        var exception = await Assert.ThrowsAsync<LeaseOperationException>(() =>
            harness.Coordinator.PrepareAsync(PrepareRequest(requestId, durationMinutes: 61), CancellationToken.None));

        Assert.Equal(LeaseErrorCode.RequestReplayMismatch, exception.ErrorCode);
    }

    [Theory]
    [InlineData(0, LeaseErrorCode.DurationOutOfRange)]
    [InlineData(721, LeaseErrorCode.DurationOutOfRange)]
    public async Task Prepare_rejects_duration_outside_contract(int minutes, LeaseErrorCode expected)
    {
        using var harness = new ActivationHarness();

        var exception = await Assert.ThrowsAsync<LeaseOperationException>(() =>
            harness.Coordinator.PrepareAsync(
                PrepareRequest(Guid.NewGuid(), minutes),
                CancellationToken.None));

        Assert.Equal(expected, exception.ErrorCode);
    }

    [Fact]
    public async Task Prepare_fails_closed_when_worker_handoff_is_unhealthy()
    {
        using var harness = new ActivationHarness { LauncherHealthy = false };

        var exception = await Assert.ThrowsAsync<LeaseOperationException>(() =>
            harness.Coordinator.PrepareAsync(PrepareRequest(Guid.NewGuid()), CancellationToken.None));

        Assert.Equal(LeaseErrorCode.BackendUnavailable, exception.ErrorCode);
        Assert.True(exception.Retryable);
    }

    [Fact]
    public async Task Commit_activates_once_and_same_request_returns_original_result()
    {
        using var harness = new ActivationHarness();
        var prepare = await harness.Coordinator.PrepareAsync(
            PrepareRequest(Guid.NewGuid()),
            CancellationToken.None);
        var request = new CommitLeaseRequest(
            ProtocolConstants.CurrentVersion,
            Guid.NewGuid(),
            prepare.PreparationId,
            prepare.Nonce);

        var first = await harness.Coordinator.CommitAsync(request, CancellationToken.None);
        var second = await harness.Coordinator.CommitAsync(request, CancellationToken.None);

        Assert.Equal(first.LeaseId, second.LeaseId);
        Assert.Equal(first.State, second.State);
        Assert.Equal(first.Health, second.Health);
        Assert.Equal(first.Targets, second.Targets);
        Assert.Equal(LeaseState.Active, first.State);
        Assert.Equal([first.LeaseId], harness.LaunchedLeaseIds);
        Assert.Equal(1, Assert.IsType<InProcessEnforcementAdapter>(harness.Adapter).ApplyCount);
        Assert.Equal(first.LeaseId, await harness.Workspace.Store.GetActiveLeaseIdAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Commit_rejects_invalid_nonce_and_expired_preparation()
    {
        using var harness = new ActivationHarness();
        var prepare = await harness.Coordinator.PrepareAsync(
            PrepareRequest(Guid.NewGuid()),
            CancellationToken.None);
        var invalidNonce = new CommitLeaseRequest(
            ProtocolConstants.CurrentVersion,
            Guid.NewGuid(),
            prepare.PreparationId,
            "invalid");
        var mismatch = await Assert.ThrowsAsync<LeaseOperationException>(() =>
            harness.Coordinator.CommitAsync(invalidNonce, CancellationToken.None));
        Assert.Equal(LeaseErrorCode.PreparationMismatch, mismatch.ErrorCode);

        harness.Time.Advance(TimeSpan.FromMinutes(3));
        var expired = await Assert.ThrowsAsync<LeaseOperationException>(() =>
            harness.Coordinator.CommitAsync(
                invalidNonce with { RequestId = Guid.NewGuid(), Nonce = prepare.Nonce },
                CancellationToken.None));
        Assert.Equal(LeaseErrorCode.PreparationExpired, expired.ErrorCode);
    }

    [Fact]
    public async Task Commit_enforces_single_active_lease_across_preparations()
    {
        using var harness = new ActivationHarness();
        var firstPrepare = await harness.Coordinator.PrepareAsync(
            PrepareRequest(Guid.NewGuid()),
            CancellationToken.None);
        var secondPrepare = await harness.Coordinator.PrepareAsync(
            PrepareRequest(Guid.NewGuid()),
            CancellationToken.None);
        _ = await harness.Coordinator.CommitAsync(
            CommitRequest(firstPrepare),
            CancellationToken.None);

        var exception = await Assert.ThrowsAsync<LeaseOperationException>(() =>
            harness.Coordinator.CommitAsync(CommitRequest(secondPrepare), CancellationToken.None));

        Assert.Equal(LeaseErrorCode.ActiveLeaseExists, exception.ErrorCode);
    }

    [Fact]
    public async Task Worker_handoff_failure_releases_applied_enforcement()
    {
        using var harness = new ActivationHarness { LaunchSucceeds = false };
        var prepare = await harness.Coordinator.PrepareAsync(
            PrepareRequest(Guid.NewGuid()),
            CancellationToken.None);

        var exception = await Assert.ThrowsAsync<LeaseOperationException>(() =>
            harness.Coordinator.CommitAsync(CommitRequest(prepare), CancellationToken.None));

        Assert.Equal(LeaseErrorCode.ActivationFailed, exception.ErrorCode);
        var adapter = Assert.IsType<InProcessEnforcementAdapter>(harness.Adapter);
        Assert.Equal(1, adapter.RestoreCount);
        Assert.False(await harness.Workspace.Store.HasActiveLeaseAsync(CancellationToken.None));
        var state = await harness.Workspace.Store.GetStateAsync(
            Assert.Single(harness.LaunchedLeaseIds),
            CancellationToken.None);
        Assert.Equal(LeaseState.Completed, Assert.IsType<DistractionFirewall.Core.Leases.LeaseRuntimeState>(state).State);
    }

    [Fact]
    public async Task Commit_retry_resumes_interrupted_worker_handoff_without_reapplying_rules()
    {
        using var harness = new ActivationHarness { CancelLaunch = true };
        var prepare = await harness.Coordinator.PrepareAsync(
            PrepareRequest(Guid.NewGuid()),
            CancellationToken.None);
        var request = CommitRequest(prepare);
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            harness.Coordinator.CommitAsync(request, CancellationToken.None));
        harness.CancelLaunch = false;

        var response = await harness.Coordinator.CommitAsync(request, CancellationToken.None);

        Assert.Equal(LeaseState.Active, response.State);
        Assert.Equal(2, harness.LaunchedLeaseIds.Count);
        Assert.Equal(1, Assert.IsType<InProcessEnforcementAdapter>(harness.Adapter).ApplyCount);
        var state = await harness.Workspace.Store.GetStateAsync(response.LeaseId, CancellationToken.None);
        Assert.True(Assert.IsType<DistractionFirewall.Core.Leases.LeaseRuntimeState>(state).WorkerHandoffCompleted);
    }

    [Fact]
    public async Task Startup_recovery_closes_active_before_worker_handoff_crash_window()
    {
        using var harness = new ActivationHarness { CancelLaunch = true };
        var prepare = await harness.Coordinator.PrepareAsync(
            PrepareRequest(Guid.NewGuid()),
            CancellationToken.None);
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            harness.Coordinator.CommitAsync(CommitRequest(prepare), CancellationToken.None));
        var leaseId = Assert.Single(harness.LaunchedLeaseIds);
        var interrupted = Assert.IsType<LeaseRuntimeState>(
            await harness.Workspace.Store.GetStateAsync(leaseId, CancellationToken.None));
        Assert.Equal(LeaseState.Active, interrupted.State);
        Assert.False(interrupted.WorkerHandoffCompleted);
        harness.CancelLaunch = false;

        var recovered = await harness.Coordinator.RecoverOnStartupAsync(CancellationToken.None);

        var state = Assert.IsType<LeaseRuntimeState>(recovered);
        Assert.Equal(LeaseState.Active, state.State);
        Assert.True(state.WorkerHandoffCompleted);
        Assert.Equal([leaseId, leaseId], harness.LaunchedLeaseIds);
        Assert.Equal(1, Assert.IsType<InProcessEnforcementAdapter>(harness.Adapter).ApplyCount);
    }

    [Fact]
    public async Task Startup_recovery_restarts_worker_even_after_completed_handoff()
    {
        using var harness = new ActivationHarness();
        var prepare = await harness.Coordinator.PrepareAsync(
            PrepareRequest(Guid.NewGuid()),
            CancellationToken.None);
        var committed = await harness.Coordinator.CommitAsync(
            CommitRequest(prepare),
            CancellationToken.None);
        harness.LaunchSucceeds = false;

        var recovered = await harness.Coordinator.RecoverOnStartupAsync(CancellationToken.None);

        var state = Assert.IsType<LeaseRuntimeState>(recovered);
        Assert.Equal(LeaseState.Active, state.State);
        Assert.Equal(LeaseHealth.Degraded, state.Health);
        Assert.Equal("handoff_failed", state.LastErrorCode);
        Assert.True(state.WorkerHandoffCompleted);
        Assert.Equal([committed.LeaseId, committed.LeaseId], harness.LaunchedLeaseIds);
        var adapter = Assert.IsType<InProcessEnforcementAdapter>(harness.Adapter);
        Assert.Equal(0, adapter.RestoreCount);
        Assert.Equal(committed.LeaseId, await harness.Workspace.Store.GetActiveLeaseIdAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Startup_recovery_with_no_active_capsule_is_a_no_op()
    {
        using var harness = new ActivationHarness();

        var recovered = await harness.Coordinator.RecoverOnStartupAsync(CancellationToken.None);

        Assert.Null(recovered);
        Assert.Empty(harness.LaunchedLeaseIds);
    }

    [Fact]
    public async Task Startup_recovery_finalizes_a_releasing_capsule_without_restarting_worker()
    {
        var adapter = new ScriptedEnforcementAdapter("release");
        using var harness = new ActivationHarness(adapter);
        var prepare = await harness.Coordinator.PrepareAsync(
            PrepareRequest(Guid.NewGuid()),
            CancellationToken.None);
        var committed = await harness.Coordinator.CommitAsync(
            CommitRequest(prepare),
            CancellationToken.None);
        var active = Assert.IsType<LeaseRuntimeState>(
            await harness.Workspace.Store.GetStateAsync(committed.LeaseId, CancellationToken.None));
        harness.Time.Advance(TimeSpan.FromSeconds(1));
        var releasing = LeaseStateMachine.Transition(
            active,
            LeaseState.Releasing,
            harness.Time.Capture().UtcNow,
            LeaseHealth.ReleasePending,
            "release_pending");
        await harness.Workspace.Store.SaveStateAsync(releasing, CancellationToken.None);

        var recovered = await harness.Coordinator.RecoverOnStartupAsync(CancellationToken.None);

        var completed = Assert.IsType<LeaseRuntimeState>(recovered);
        Assert.Equal(LeaseState.Completed, completed.State);
        Assert.Equal(1, adapter.RestoreCount);
        Assert.Equal([committed.LeaseId], harness.LaunchedLeaseIds);
        Assert.Null(await harness.Workspace.Store.GetActiveLeaseIdAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Worker_heartbeat_race_is_merged_before_handoff_marker_is_persisted()
    {
        using var workspace = new TestWorkspace();
        var time = new MutableTimeAuthority(TestData.Now);
        var adapter = new InProcessEnforcementAdapter();
        var runtime = new LeaseRuntimeCoordinator(workspace.Store, [adapter], time);
        var launcher = new DelegateLeaseWorkerLauncher(async (leaseId, cancellationToken) =>
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
            return new LeaseWorkerLaunchResult(Started: true, "heartbeat persisted");
        });
        var coordinator = new LeaseActivationCoordinator(
            TestData.Catalog(),
            workspace.Store,
            runtime,
            time,
            new LeaseNonceService(Enumerable.Range(1, 32).Select(value => (byte)value).ToArray()),
            launcher);
        var preparation = await coordinator.PrepareAsync(
            PrepareRequest(Guid.NewGuid()),
            CancellationToken.None);

        var response = await coordinator.CommitAsync(CommitRequest(preparation), CancellationToken.None);

        var state = await workspace.Store.GetStateAsync(response.LeaseId, CancellationToken.None);
        var persisted = Assert.IsType<LeaseRuntimeState>(state);
        Assert.True(persisted.WorkerHandoffCompleted);
        Assert.True(persisted.Sequence >= 4);
        Assert.Equal(TestData.Now.AddSeconds(1), persisted.LastHeartbeatUtc);
    }

    private static PrepareLeaseRequest PrepareRequest(Guid requestId, int durationMinutes = 60) => new(
        ProtocolConstants.CurrentVersion,
        requestId,
        ["youtube"],
        new LeaseEndRequest(LeaseEndMode.Duration, durationMinutes, UntilUtc: null));

    private static CommitLeaseRequest CommitRequest(PrepareLeaseResponse preparation) => new(
        ProtocolConstants.CurrentVersion,
        Guid.NewGuid(),
        preparation.PreparationId,
        preparation.Nonce);
}
