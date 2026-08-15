namespace DistractionFirewall.Contracts;

public enum LeaseState
{
    Idle,
    Prepared,
    Activating,
    Active,
    Releasing,
    Completed,
}

public enum LeaseEndMode
{
    Duration,
    Until,
}

public enum LeaseHealth
{
    Unknown,
    Healthy,
    Degraded,
    ReleasePending,
    RepairRequired,
}

public enum AppInstallState
{
    Installed,
    Removed,
}

public enum RuntimeInstallIntent
{
    Keep,
    RemoveAfterCompletion,
}

public enum RuntimeInstallState
{
    Installed,
    Uninstalling,
    UninstallPending,
    Uninstalled,
}

public enum DiagnosticSeverity
{
    Information,
    Warning,
    Error,
}

public enum LeaseErrorCode
{
    None,
    UnsupportedProtocol,
    InvalidRequest,
    UnauthorizedCaller,
    TargetNotFound,
    DurationOutOfRange,
    DeadlineOutOfRange,
    ActiveLeaseExists,
    PreparationExpired,
    PreparationMismatch,
    RequestReplayMismatch,
    BackendUnavailable,
    ActivationFailed,
    StateConflict,
    InternalError,
}
