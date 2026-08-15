using DistractionFirewall.Contracts;
using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Core.Leases;
using DistractionFirewall.Core.Persistence;
using DistractionFirewall.Core.Targets;
using DistractionFirewall.Core.Time;

namespace DistractionFirewall.ActivationService;

public sealed class LeaseActivationCoordinator
{
    private const string HandoffFailedCode = "handoff_failed";
    private readonly TargetCatalog _catalog;
    private readonly ILeaseLifecycleStore _store;
    private readonly LeaseRuntimeCoordinator _runtime;
    private readonly ITimeAuthority _timeAuthority;
    private readonly LeaseNonceService _nonceService;
    private readonly ILeaseWorkerLauncher _workerLauncher;
    private readonly TimeSpan _preparationLifetime;

    public LeaseActivationCoordinator(
        TargetCatalog catalog,
        ILeaseLifecycleStore store,
        LeaseRuntimeCoordinator runtime,
        ITimeAuthority timeAuthority,
        LeaseNonceService nonceService,
        ILeaseWorkerLauncher workerLauncher,
        TimeSpan? preparationLifetime = null)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(runtime);
        ArgumentNullException.ThrowIfNull(timeAuthority);
        ArgumentNullException.ThrowIfNull(nonceService);
        ArgumentNullException.ThrowIfNull(workerLauncher);
        _catalog = catalog;
        _store = store;
        _runtime = runtime;
        _timeAuthority = timeAuthority;
        _nonceService = nonceService;
        _workerLauncher = workerLauncher;
        _preparationLifetime = preparationLifetime ?? TimeSpan.FromMinutes(2);
        if (_preparationLifetime <= TimeSpan.Zero || _preparationLifetime > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentOutOfRangeException(
                nameof(preparationLifetime),
                "Preparation lifetime must be positive and no more than five minutes.");
        }
    }

    public async Task<LeaseRuntimeState?> RecoverOnStartupAsync(
        CancellationToken cancellationToken)
    {
        var leaseId = await _store.GetActiveLeaseIdAsync(cancellationToken).ConfigureAwait(false);
        if (leaseId is null)
        {
            return null;
        }

        var manifest = await _store.GetManifestAsync(leaseId.Value, cancellationToken).ConfigureAwait(false)
            ?? throw new LeaseOperationException(
                LeaseErrorCode.StateConflict,
                $"Active lease '{leaseId}' has no manifest.");
        var state = await _store.GetStateAsync(leaseId.Value, cancellationToken).ConfigureAwait(false)
            ?? throw new LeaseOperationException(
                LeaseErrorCode.StateConflict,
                $"Active lease '{leaseId}' has no runtime state.");
        if (state.State is not (LeaseState.Activating or LeaseState.Active or LeaseState.Releasing))
        {
            throw new LeaseOperationException(
                LeaseErrorCode.StateConflict,
                $"Active lease '{leaseId}' has unexpected state {state.State}.");
        }

        state = await ReconcileAsync(leaseId.Value, cancellationToken).ConfigureAwait(false);
        if (state.State != LeaseState.Active)
        {
            return state;
        }

        var handoff = await LaunchWorkerAndMergeHeartbeatAsync(
            manifest.LeaseId,
            state.Sequence,
            cancellationToken).ConfigureAwait(false);
        if (!handoff.Started)
        {
            // Startup recovery must fail closed. Existing enforcement stays active and
            // the fixed recovery task can try again on its next trigger or at reboot.
            return await UpdateStateWithRetryAsync(
                manifest.LeaseId,
                current => current.State != LeaseState.Active
                    ? current
                    : current with
                    {
                        Sequence = checked(current.Sequence + 1),
                        UpdatedAtUtc = _timeAuthority.Capture().UtcNow,
                        Health = LeaseHealth.Degraded,
                        LastErrorCode = HandoffFailedCode,
                    }).ConfigureAwait(false);
        }

        return await UpdateStateWithRetryAsync(
            manifest.LeaseId,
            current => current.State != LeaseState.Active || current.WorkerHandoffCompleted
                ? current
                : current with
                {
                    Sequence = checked(current.Sequence + 1),
                    UpdatedAtUtc = _timeAuthority.Capture().UtcNow,
                    WorkerHandoffCompleted = true,
                }).ConfigureAwait(false);
    }

    public async Task<PrepareLeaseResponse> PrepareAsync(
        PrepareLeaseRequest request,
        CancellationToken cancellationToken)
    {
        ValidatePrepareRequest(request);
        var fingerprint = LeaseRequestFingerprint.ForPrepare(request);
        var preparationId = _nonceService.GetPreparationId(request.RequestId);
        var existing = await _store.GetPreparationAsync(preparationId, cancellationToken).ConfigureAwait(false);
        if (existing is not null)
        {
            if (existing.RequestId != request.RequestId ||
                !string.Equals(existing.RequestFingerprint, fingerprint, StringComparison.Ordinal))
            {
                throw new LeaseOperationException(
                    LeaseErrorCode.RequestReplayMismatch,
                    "The prepare request ID was already used with a different payload.");
            }

            if (_timeAuthority.Capture().UtcNow >= existing.PreparationExpiresAtUtc)
            {
                throw new LeaseOperationException(
                    LeaseErrorCode.PreparationExpired,
                    "The existing preparation has expired; submit a new request ID.");
            }

            return CreatePrepareResponse(existing);
        }

        if (await _store.HasActiveLeaseAsync(cancellationToken).ConfigureAwait(false))
        {
            throw new LeaseOperationException(
                LeaseErrorCode.ActiveLeaseExists,
                "Another lease is already active.");
        }

        var targets = ResolveTargets(request.TargetIds);
        var snapshot = _timeAuthority.Capture();
        ResolvedLeaseDeadline deadline;
        try
        {
            deadline = LeaseDeadlineResolver.Resolve(request.End, snapshot.UtcNow);
        }
        catch (LeaseValidationException exception)
        {
            throw new LeaseOperationException(exception.ErrorCode, exception.Message, exception);
        }

        await EnsureBackendsReadyAsync(cancellationToken).ConfigureAwait(false);
        var preparationExpiry = Min(
            snapshot.UtcNow.Add(_preparationLifetime),
            deadline.ExpiresAtUtc);
        var nonce = _nonceService.CreateNonce(request.RequestId, fingerprint);
        var preparation = new PreparedLease
        {
            PreparationId = preparationId,
            RequestId = request.RequestId,
            RequestFingerprint = fingerprint,
            NonceHash = LeaseNonceService.HashNonce(nonce),
            PreparedAtUtc = snapshot.UtcNow,
            PreparationExpiresAtUtc = preparationExpiry,
            ResolvedExpiresAtUtc = deadline.ExpiresAtUtc,
            RequestedDuration = deadline.RequestedDuration,
            TargetSnapshot = targets,
            RuleHash = TargetCatalog.ComputeDefinitionHash(targets),
        };
        await _store.SavePreparationAsync(preparation, cancellationToken).ConfigureAwait(false);
        return CreatePrepareResponse(preparation);
    }

    public async Task<CommitLeaseResponse> CommitAsync(
        CommitLeaseRequest request,
        CancellationToken cancellationToken)
    {
        ValidateCommitRequest(request);
        var leaseId = _nonceService.GetLeaseId(request.RequestId);
        var commitFingerprint = LeaseRequestFingerprint.ForCommit(request);
        var existingManifest = await _store.GetManifestAsync(leaseId, cancellationToken).ConfigureAwait(false);
        if (existingManifest is not null)
        {
            if (existingManifest.CommitRequestId != request.RequestId ||
                !string.Equals(
                    existingManifest.CommitRequestFingerprint,
                    commitFingerprint,
                    StringComparison.Ordinal))
            {
                throw new LeaseOperationException(
                    LeaseErrorCode.RequestReplayMismatch,
                    "The commit request ID was already used with a different payload.");
            }

            var existingState = await _store.GetStateAsync(leaseId, cancellationToken).ConfigureAwait(false);
            if (existingState is null)
            {
                existingState = CreateInitialState(existingManifest);
                try
                {
                    await _store.CreateCapsuleAsync(
                        existingManifest,
                        existingState,
                        cancellationToken).ConfigureAwait(false);
                }
                catch (LeaseStoreConflictException exception)
                {
                    throw new LeaseOperationException(
                        LeaseErrorCode.StateConflict,
                        exception.Message,
                        exception,
                        retryable: true);
                }
            }

            if (existingState.State is LeaseState.Completed or LeaseState.Releasing &&
                !string.IsNullOrEmpty(existingState.LastErrorCode))
            {
                throw new LeaseOperationException(
                    LeaseErrorCode.ActivationFailed,
                    $"The original commit failed with '{existingState.LastErrorCode}'.",
                    retryable: existingState.State == LeaseState.Releasing);
            }

            if (existingState.State is LeaseState.Activating or LeaseState.Active or LeaseState.Releasing)
            {
                existingState = await ReconcileAsync(leaseId, cancellationToken).ConfigureAwait(false);
            }

            if (existingState.State == LeaseState.Active && !existingState.WorkerHandoffCompleted)
            {
                existingState = await CompleteWorkerHandoffAsync(
                    existingManifest,
                    existingState,
                    cancellationToken).ConfigureAwait(false);
            }

            return CreateCommitResponse(existingManifest, existingState);
        }

        var preparation = await _store.GetPreparationAsync(
            request.PreparationId,
            cancellationToken).ConfigureAwait(false)
            ?? throw new LeaseOperationException(
                LeaseErrorCode.PreparationMismatch,
                "The preparation does not exist.");
        if (!LeaseNonceService.VerifyNonce(request.Nonce, preparation.NonceHash))
        {
            throw new LeaseOperationException(
                LeaseErrorCode.PreparationMismatch,
                "The preparation nonce is invalid.");
        }

        var snapshot = _timeAuthority.Capture();
        if (snapshot.UtcNow >= preparation.PreparationExpiresAtUtc ||
            snapshot.UtcNow >= preparation.ResolvedExpiresAtUtc)
        {
            throw new LeaseOperationException(
                LeaseErrorCode.PreparationExpired,
                "The preparation has expired.");
        }

        if (await _store.HasActiveLeaseAsync(cancellationToken).ConfigureAwait(false))
        {
            throw new LeaseOperationException(
                LeaseErrorCode.ActiveLeaseExists,
                "Another lease is already active.");
        }

        await EnsureBackendsReadyAsync(cancellationToken).ConfigureAwait(false);
        var remainingDuration = preparation.ResolvedExpiresAtUtc - snapshot.UtcNow;
        var manifest = new LeaseManifest
        {
            SchemaVersion = LeaseManifest.CurrentSchemaVersion,
            LeaseId = leaseId,
            TargetSnapshot = preparation.TargetSnapshot,
            RuleHash = preparation.RuleHash,
            CreatedAtUtc = preparation.PreparedAtUtc,
            ActivatedAtUtc = snapshot.UtcNow,
            ExpiresAtUtc = preparation.ResolvedExpiresAtUtc,
            RequestedDuration = remainingDuration,
            BootId = snapshot.BootId,
            MonotonicAnchorTicks = snapshot.MonotonicTicks,
            MonotonicFrequency = snapshot.MonotonicFrequency,
            InstallIntent = RuntimeInstallIntent.Keep,
            PreparationId = preparation.PreparationId,
            PrepareRequestId = preparation.RequestId,
            CommitRequestId = request.RequestId,
            CommitRequestFingerprint = commitFingerprint,
        };
        var state = CreateInitialState(manifest);

        try
        {
            await _store.CreateCapsuleAsync(manifest, state, cancellationToken).ConfigureAwait(false);
        }
        catch (LeaseStoreConflictException exception)
        {
            throw new LeaseOperationException(
                LeaseErrorCode.ActiveLeaseExists,
                exception.Message,
                exception);
        }

        state = await ActivateAsync(leaseId, cancellationToken).ConfigureAwait(false);

        return CreateCommitResponse(
            manifest,
            await CompleteWorkerHandoffAsync(manifest, state, cancellationToken).ConfigureAwait(false));
    }

    private static LeaseRuntimeState CreateInitialState(LeaseManifest manifest) => new()
    {
        LeaseId = manifest.LeaseId,
        State = LeaseState.Activating,
        Sequence = 0,
        UpdatedAtUtc = manifest.ActivatedAtUtc,
        LastHeartbeatUtc = manifest.ActivatedAtUtc,
        Health = LeaseHealth.Unknown,
        AppInstallState = AppInstallState.Installed,
        RuntimeInstallIntent = manifest.InstallIntent,
        RuntimeInstallState = RuntimeInstallState.Installed,
    };

    private async Task<LeaseRuntimeState> ActivateAsync(
        Guid leaseId,
        CancellationToken cancellationToken)
    {
        try
        {
            return await _runtime.ActivateAsync(leaseId, cancellationToken).ConfigureAwait(false);
        }
        catch (LeaseRuntimeException exception)
        {
            throw new LeaseOperationException(
                LeaseErrorCode.ActivationFailed,
                exception.Message,
                exception,
                retryable: exception.State.State == LeaseState.Releasing);
        }
    }

    private async Task<LeaseRuntimeState> ReconcileAsync(
        Guid leaseId,
        CancellationToken cancellationToken)
    {
        try
        {
            return await _runtime.ReconcileAsync(leaseId, cancellationToken).ConfigureAwait(false);
        }
        catch (LeaseRuntimeException exception)
        {
            throw new LeaseOperationException(
                LeaseErrorCode.ActivationFailed,
                exception.Message,
                exception,
                retryable: exception.State.State == LeaseState.Releasing);
        }
    }

    private async Task<LeaseRuntimeState> CompleteWorkerHandoffAsync(
        LeaseManifest manifest,
        LeaseRuntimeState state,
        CancellationToken cancellationToken)
    {
        if (state.WorkerHandoffCompleted)
        {
            return state;
        }

        var handoff = await LaunchWorkerAndMergeHeartbeatAsync(
            manifest.LeaseId,
            state.Sequence,
            cancellationToken).ConfigureAwait(false);

        if (!handoff.Started)
        {
            state = await UpdateStateWithRetryAsync(
                manifest.LeaseId,
                current => current.State != LeaseState.Active || current.WorkerHandoffCompleted
                    ? current
                    : current with
                    {
                        Sequence = checked(current.Sequence + 1),
                        UpdatedAtUtc = _timeAuthority.Capture().UtcNow,
                        Health = LeaseHealth.Degraded,
                        LastErrorCode = HandoffFailedCode,
                    }).ConfigureAwait(false);
            if (state.WorkerHandoffCompleted)
            {
                return state;
            }

            state = await _runtime.ReleaseAsync(
                manifest.LeaseId,
                CancellationToken.None).ConfigureAwait(false);
            throw new LeaseOperationException(
                LeaseErrorCode.ActivationFailed,
                $"Lease worker handoff failed and the lease entered {state.State}: {handoff.Summary}",
                retryable: state.State == LeaseState.Releasing);
        }

        return await UpdateStateWithRetryAsync(
            manifest.LeaseId,
            current => current.State != LeaseState.Active || current.WorkerHandoffCompleted
                ? current
                : current with
                {
                    Sequence = checked(current.Sequence + 1),
                    UpdatedAtUtc = _timeAuthority.Capture().UtcNow,
                    WorkerHandoffCompleted = true,
                }).ConfigureAwait(false);
    }

    private async Task<LeaseWorkerLaunchResult> LaunchWorkerAndMergeHeartbeatAsync(
        Guid leaseId,
        long handoffStartSequence,
        CancellationToken cancellationToken)
    {
        LeaseWorkerLaunchResult handoff;
        try
        {
            handoff = await _workerLauncher.LaunchAsync(
                leaseId,
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            handoff = new LeaseWorkerLaunchResult(
                Started: false,
                $"Worker handoff threw {exception.GetType().Name}.");
        }

        var latest = await _store.GetStateAsync(
            leaseId,
            CancellationToken.None).ConfigureAwait(false)
            ?? throw new LeaseOperationException(
                LeaseErrorCode.StateConflict,
                "The active lease lost its runtime state during Worker handoff.");
        if (!handoff.Started &&
            latest.State == LeaseState.Active &&
            latest.Sequence > handoffStartSequence &&
            latest.LastHeartbeatUtc is not null)
        {
            return new LeaseWorkerLaunchResult(
                Started: true,
                "Worker heartbeat arrived while the handoff result was being finalized.");
        }

        return handoff;
    }

    private async Task<LeaseRuntimeState> UpdateStateWithRetryAsync(
        Guid leaseId,
        Func<LeaseRuntimeState, LeaseRuntimeState> update)
    {
        const int maximumAttempts = 20;
        for (var attempt = 0; attempt < maximumAttempts; attempt++)
        {
            var current = await _store.GetStateAsync(leaseId, CancellationToken.None).ConfigureAwait(false)
                ?? throw new LeaseOperationException(
                    LeaseErrorCode.StateConflict,
                    $"Lease '{leaseId}' lost its runtime state.");
            var desired = update(current);
            if (desired.Sequence == current.Sequence)
            {
                return current;
            }

            try
            {
                await _store.SaveStateAsync(desired, CancellationToken.None).ConfigureAwait(false);
                return desired;
            }
            catch (LeaseStoreConflictException) when (attempt + 1 < maximumAttempts)
            {
                await Task.Yield();
            }
        }

        throw new LeaseOperationException(
            LeaseErrorCode.StateConflict,
            $"Lease '{leaseId}' state kept changing during Worker handoff.",
            retryable: true);
    }

    public async Task<LeaseStatusResponse> GetStatusAsync(CancellationToken cancellationToken)
    {
        var leaseId = await _store.GetActiveLeaseIdAsync(cancellationToken).ConfigureAwait(false);
        if (leaseId is null)
        {
            return new LeaseStatusResponse(
                ProtocolConstants.CurrentVersion,
                LeaseState.Idle,
                LeaseId: null,
                ActivatedAtUtc: null,
                ExpiresAtUtc: null,
                Array.Empty<TargetSnapshotDto>(),
                LeaseHealth.Unknown,
                AppInstallState.Installed,
                RuntimeInstallIntent.Keep,
                RuntimeInstallState.Installed,
                Sequence: 0);
        }

        var manifest = await _store.GetManifestAsync(leaseId.Value, cancellationToken).ConfigureAwait(false)
            ?? throw new LeaseOperationException(
                LeaseErrorCode.StateConflict,
                $"Active lease '{leaseId}' has no manifest.");
        var state = await _store.GetStateAsync(leaseId.Value, cancellationToken).ConfigureAwait(false)
            ?? throw new LeaseOperationException(
                LeaseErrorCode.StateConflict,
                $"Active lease '{leaseId}' has no state.");
        return new LeaseStatusResponse(
            ProtocolConstants.CurrentVersion,
            state.State,
            leaseId,
            manifest.ActivatedAtUtc,
            manifest.ExpiresAtUtc,
            CreateTargetSnapshots(manifest.TargetSnapshot),
            state.Health,
            state.AppInstallState,
            state.RuntimeInstallIntent,
            state.RuntimeInstallState,
            state.Sequence);
    }

    public GetTargetCatalogResponse GetTargetCatalog() => new(
        ProtocolConstants.CurrentVersion,
        _catalog.Targets
            .OrderBy(target => target.StableId, StringComparer.Ordinal)
            .Select(target => new TargetDescriptor(
                target.StableId,
                target.DisplayName,
                target.Description,
                target.CatalogVersion,
                target.Coverage,
                target.KnownCollateral.Select(collateral =>
                    $"[{collateral.Severity}] {collateral.Purpose}: {collateral.Risk}").ToArray()))
            .ToArray());

    public static CapabilitiesResponse GetCapabilities() => new(
        ProtocolConstants.CurrentVersion,
        LeaseDeadlineResolver.MinimumDurationMinutes,
        LeaseDeadlineResolver.MaximumDurationMinutes,
        MaximumActiveLeases: 1,
        SupportsAbsoluteDeadline: true,
        RpcMethods.Supported.Order(StringComparer.Ordinal).ToArray());

    public async Task<DiagnosticsResponse> GetDiagnosticsAsync(CancellationToken cancellationToken)
    {
        var checks = new List<DiagnosticCheck>();
        try
        {
            _ = await _store.GetActiveLeaseIdAsync(cancellationToken).ConfigureAwait(false);
            checks.Add(new DiagnosticCheck(
                "capsule_store",
                "Lease capsule store",
                DiagnosticSeverity.Information,
                IsHealthy: true,
                "The fixed-root capsule store is readable and writable by the service process."));
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            checks.Add(new DiagnosticCheck(
                "capsule_store",
                "Lease capsule store",
                DiagnosticSeverity.Error,
                IsHealthy: false,
                $"Capsule store check failed: {exception.GetType().Name}."));
        }

        var health = await _runtime.CheckHealthAsync(cancellationToken).ConfigureAwait(false);
        if (health.Count == 0)
        {
            checks.Add(new DiagnosticCheck(
                "enforcement:none",
                "Enforcement adapters",
                DiagnosticSeverity.Error,
                IsHealthy: false,
                "No enforcement adapters are configured."));
        }

        checks.AddRange(health.Select(item => new DiagnosticCheck(
            $"enforcement:{item.AdapterId}",
            item.AdapterId,
            item.Healthy ? DiagnosticSeverity.Information : DiagnosticSeverity.Error,
            item.Available && item.Healthy,
            item.Summary)));

        var launcher = await _workerLauncher.CheckHealthAsync(cancellationToken).ConfigureAwait(false);
        checks.Add(new DiagnosticCheck(
            "lease_worker_handoff",
            "Lease worker handoff",
            launcher.Started ? DiagnosticSeverity.Information : DiagnosticSeverity.Error,
            launcher.Started,
            launcher.Summary));
        return new DiagnosticsResponse(ProtocolConstants.CurrentVersion, _timeAuthority.Capture().UtcNow, checks);
    }

    private async Task EnsureBackendsReadyAsync(CancellationToken cancellationToken)
    {
        var health = await _runtime.CheckHealthAsync(cancellationToken).ConfigureAwait(false);
        if (_runtime.AdapterCount == 0 || health.Any(item => !item.Available || !item.Healthy))
        {
            var summary = health.Count == 0
                ? "No enforcement adapters are configured."
                : string.Join("; ", health.Where(item => !item.Available || !item.Healthy).Select(item => item.Summary));
            throw new LeaseOperationException(LeaseErrorCode.BackendUnavailable, summary, retryable: true);
        }

        var launcher = await _workerLauncher.CheckHealthAsync(cancellationToken).ConfigureAwait(false);
        if (!launcher.Started)
        {
            throw new LeaseOperationException(
                LeaseErrorCode.BackendUnavailable,
                $"Lease worker handoff is unavailable: {launcher.Summary}",
                retryable: true);
        }
    }

    private static void ValidatePrepareRequest(PrepareLeaseRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateProtocol(request.ProtocolVersion);
        if (request.RequestId == Guid.Empty || request.End is null || request.TargetIds is null ||
            request.TargetIds.Count == 0 ||
            request.TargetIds.Any(string.IsNullOrWhiteSpace) ||
            request.TargetIds.Distinct(StringComparer.Ordinal).Count() != request.TargetIds.Count)
        {
            throw new LeaseOperationException(
                LeaseErrorCode.InvalidRequest,
                "Prepare requires a non-empty request ID, unique target IDs, and an end condition.");
        }
    }

    private static void ValidateCommitRequest(CommitLeaseRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateProtocol(request.ProtocolVersion);
        if (request.RequestId == Guid.Empty || request.PreparationId == Guid.Empty ||
            string.IsNullOrWhiteSpace(request.Nonce) || request.Nonce.Length > 512)
        {
            throw new LeaseOperationException(
                LeaseErrorCode.InvalidRequest,
                "Commit requires non-empty request and preparation IDs and a bounded nonce.");
        }
    }

    private static void ValidateProtocol(int protocolVersion)
    {
        if (protocolVersion != ProtocolConstants.CurrentVersion)
        {
            throw new LeaseOperationException(
                LeaseErrorCode.UnsupportedProtocol,
                $"Protocol version {protocolVersion} is not supported.");
        }
    }

    private IReadOnlyList<TargetDefinition> ResolveTargets(IReadOnlyList<string> targetIds)
    {
        try
        {
            return _catalog.Resolve(targetIds);
        }
        catch (KeyNotFoundException exception)
        {
            throw new LeaseOperationException(LeaseErrorCode.TargetNotFound, exception.Message, exception);
        }
        catch (InvalidDataException exception)
        {
            throw new LeaseOperationException(LeaseErrorCode.InvalidRequest, exception.Message, exception);
        }
    }

    private PrepareLeaseResponse CreatePrepareResponse(PreparedLease preparation)
    {
        var nonce = _nonceService.CreateNonce(preparation.RequestId, preparation.RequestFingerprint);
        var warnings = preparation.TargetSnapshot
            .SelectMany(target => target.KnownCollateral.Select(collateral => new LeaseWarning(
                $"collateral:{target.StableId}:{collateral.RuleField}:{collateral.RuleValue}",
                $"[{collateral.Severity}] {collateral.Purpose}: {collateral.Risk}")))
            .ToArray();
        return new PrepareLeaseResponse(
            ProtocolConstants.CurrentVersion,
            preparation.PreparationId,
            nonce,
            preparation.PreparedAtUtc,
            preparation.PreparationExpiresAtUtc,
            preparation.ResolvedExpiresAtUtc,
            preparation.RequestedDuration,
            CreateTargetSnapshots(preparation.TargetSnapshot),
            preparation.RuleHash,
            warnings);
    }

    private static CommitLeaseResponse CreateCommitResponse(
        LeaseManifest manifest,
        LeaseRuntimeState state) => new(
            ProtocolConstants.CurrentVersion,
            manifest.LeaseId,
            state.State,
            manifest.ActivatedAtUtc,
            manifest.ExpiresAtUtc,
            CreateTargetSnapshots(manifest.TargetSnapshot),
            state.Health);

    private static TargetSnapshotDto[] CreateTargetSnapshots(
        IReadOnlyList<TargetDefinition> targets) => targets
        .OrderBy(target => target.StableId, StringComparer.Ordinal)
        .Select(target => new TargetSnapshotDto(
            target.StableId,
            target.DisplayName,
            target.CatalogVersion,
            TargetCatalog.ComputeDefinitionHash([target])))
        .ToArray();

    private static DateTimeOffset Min(DateTimeOffset left, DateTimeOffset right) =>
        left <= right ? left : right;
}
