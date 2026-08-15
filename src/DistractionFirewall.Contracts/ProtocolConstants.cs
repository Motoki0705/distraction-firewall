namespace DistractionFirewall.Contracts;

public static class ProtocolConstants
{
    public const int CurrentVersion = 1;

    public const int MaximumFrameBytes = 1024 * 1024;

    public const string ActivationPipeName = "DistractionFirewall.Activation.v1";
}

public static class RpcMethods
{
    public const string GetCapabilities = nameof(GetCapabilities);

    public const string GetStatus = nameof(GetStatus);

    public const string GetTargetCatalog = nameof(GetTargetCatalog);

    public const string PrepareLease = nameof(PrepareLease);

    public const string CommitLease = nameof(CommitLease);

    public const string WatchStatus = nameof(WatchStatus);

    public const string GetDiagnostics = nameof(GetDiagnostics);

    public static IReadOnlySet<string> Supported { get; } = new HashSet<string>(StringComparer.Ordinal)
    {
        GetCapabilities,
        GetStatus,
        GetTargetCatalog,
        PrepareLease,
        CommitLease,
        WatchStatus,
        GetDiagnostics,
    };
}
