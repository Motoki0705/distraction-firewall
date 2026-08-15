using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Enforcement.Windows.Mutation;
using DistractionFirewall.Enforcement.Windows.Ownership;

namespace DistractionFirewall.Enforcement.Windows.Tasks;

public sealed class TaskSchedulerEnforcementAdapter : IEnforcementAdapter
{
    private readonly ITaskSchedulerStore _taskStore;
    private readonly OwnedMutationCoordinator _coordinator;
    private readonly WindowsMutationGate _mutationGate;
    private readonly string _workerPath;
    private readonly string _productInstanceId;

    internal TaskSchedulerEnforcementAdapter(
        ITaskSchedulerStore taskStore,
        OwnedMutationCoordinator coordinator,
        WindowsMutationGate mutationGate,
        string workerPath,
        string productInstanceId)
    {
        _taskStore = taskStore ?? throw new ArgumentNullException(nameof(taskStore));
        _coordinator = coordinator ?? throw new ArgumentNullException(nameof(coordinator));
        _mutationGate = mutationGate ?? throw new ArgumentNullException(nameof(mutationGate));
        TaskDefinitionBuilder.ValidateWorkerPath(workerPath);
        _workerPath = Path.GetFullPath(workerPath);
        _productInstanceId = string.IsNullOrWhiteSpace(productInstanceId)
            ? throw new ArgumentException("Product instance ID is required.", nameof(productInstanceId))
            : productInstanceId;
    }

    public string AdapterId => "windows-task-scheduler";

    public Task<EnforcementHealth> CheckHealthAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_mutationGate.IsEnabled)
        {
            return Task.FromResult(new EnforcementHealth(
                AdapterId,
                Available: false,
                Healthy: false,
                "Live Windows mutation was not explicitly enabled."));
        }

        var schedulerAvailable = _taskStore.CheckAvailable(out var summary);
        var workerExists = File.Exists(_workerPath);
        return Task.FromResult(new EnforcementHealth(
            AdapterId,
            Available: schedulerAvailable,
            Healthy: schedulerAvailable && workerExists,
            workerExists ? summary : summary + " The fixed worker executable is missing."));
    }

    public async Task<EnforcementArtifact> ApplyAsync(
        EnforcementContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        _mutationGate.Demand();

        var recoveryResourceId = WindowsTaskSchedulerStore.ResourceId(TaskDefinitionBuilder.RecoveryTaskName);
        var deadlineResourceId = WindowsTaskSchedulerStore.ResourceId(
            TaskDefinitionBuilder.DeadlineTaskName(context.LeaseId));
        var recoveryState = TaskStateCodec.Encode(
            TaskDefinitionBuilder.BuildRecoveryTask(_workerPath, _productInstanceId));
        var deadlineState = TaskStateCodec.Encode(
            TaskDefinitionBuilder.BuildDeadlineTask(
                _workerPath,
                _productInstanceId,
                context.LeaseId,
                context.ExpiresAtUtc));

        await PreflightAbsentOrMatchingAsync(recoveryResourceId, recoveryState, cancellationToken)
            .ConfigureAwait(false);
        await PreflightAbsentOrMatchingAsync(deadlineResourceId, deadlineState, cancellationToken)
            .ConfigureAwait(false);

        var recovery = await _coordinator.ApplyAsync(
            _taskStore,
            AdapterId,
            Guid.Empty,
            recoveryResourceId,
            recoveryState,
            failIfPresent: true,
            cancellationToken).ConfigureAwait(false);
        OwnedApplyResult? deadline = null;
        try
        {
            deadline = await _coordinator.ApplyAsync(
                _taskStore,
                AdapterId,
                context.LeaseId,
                deadlineResourceId,
                deadlineState,
                failIfPresent: true,
                cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            if (deadline?.RecordId is not null)
            {
                _ = await _coordinator.RestoreAsync(_taskStore, deadline.RecordId, cancellationToken)
                    .ConfigureAwait(false);
            }

            throw;
        }

        var ownedDeadlineRecords = deadline.RecordId is null ? [] : new[] { deadline.RecordId };
        return new EnforcementArtifact(
            AdapterId,
            SchemaVersion: 1,
            ownedDeadlineRecords,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["recovery_task"] = recoveryResourceId,
                ["deadline_task"] = deadlineResourceId,
                ["persistent_recovery_record"] = recovery.RecordId ?? string.Empty,
                ["worker_path"] = _workerPath,
                ["deadline_utc"] = context.ExpiresAtUtc.ToUniversalTime().ToString("O"),
            });
    }

    public async Task<EnforcementVerification> VerifyAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ValidateArtifact(artifact);

        var recoveryResourceId = artifact.Properties["recovery_task"];
        var deadlineResourceId = artifact.Properties["deadline_task"];
        var recoveryExpected = TaskStateCodec.Encode(
            TaskDefinitionBuilder.BuildRecoveryTask(_workerPath, _productInstanceId));
        var deadlineExpected = TaskStateCodec.Encode(
            TaskDefinitionBuilder.BuildDeadlineTask(
                _workerPath,
                _productInstanceId,
                context.LeaseId,
                context.ExpiresAtUtc));
        var recoveryCurrent = await _taskStore.ReadAsync(recoveryResourceId, cancellationToken).ConfigureAwait(false);
        var deadlineCurrent = await _taskStore.ReadAsync(deadlineResourceId, cancellationToken).ConfigureAwait(false);
        var verified = _taskStore.StatesEqual(recoveryCurrent, recoveryExpected)
            && _taskStore.StatesEqual(deadlineCurrent, deadlineExpected);

        return new EnforcementVerification(
            AdapterId,
            TargetBlocked: verified,
            GeneralConnectivityAvailable: true,
            verified
                ? "SYSTEM recovery and UTC deadline reconciliation tasks are present."
                : "A SYSTEM recovery or deadline task is missing or altered.");
    }

    public async Task<RestoreResult> RestoreAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ValidateArtifact(artifact);
        _mutationGate.Demand();

        var failures = 0;
        foreach (var recordId in artifact.OwnedResourceIds.Reverse())
        {
            var result = await _coordinator.RestoreAsync(_taskStore, recordId, cancellationToken)
                .ConfigureAwait(false);
            failures += result.Restored ? 0 : 1;
        }

        return new RestoreResult(
            AdapterId,
            Restored: failures == 0,
            Retryable: failures != 0,
            failures == 0
                ? "Owned deadline task removed; persistent SYSTEM recovery task retained."
                : $"{failures} deadline tasks were retained because CAS restore did not succeed.");
    }

    private async Task PreflightAbsentOrMatchingAsync(
        string resourceId,
        OwnedResourceState desired,
        CancellationToken cancellationToken)
    {
        var current = await _taskStore.ReadAsync(resourceId, cancellationToken).ConfigureAwait(false);
        if (current.Exists && !_taskStore.StatesEqual(current, desired))
        {
            throw new OwnershipConflictException(resourceId, "A conflicting scheduled task already exists.");
        }
    }

    private void ValidateArtifact(EnforcementArtifact artifact)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        if (!string.Equals(artifact.AdapterId, AdapterId, StringComparison.Ordinal)
            || artifact.SchemaVersion != 1
            || !artifact.Properties.ContainsKey("recovery_task")
            || !artifact.Properties.ContainsKey("deadline_task"))
        {
            throw new ArgumentException("The enforcement artifact does not belong to this adapter.", nameof(artifact));
        }
    }
}
