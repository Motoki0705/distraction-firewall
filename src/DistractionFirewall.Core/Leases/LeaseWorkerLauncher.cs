namespace DistractionFirewall.Core.Leases;

public sealed record LeaseWorkerLaunchResult(bool Started, string Summary);

public interface ILeaseWorkerLauncher
{
    Task<LeaseWorkerLaunchResult> CheckHealthAsync(CancellationToken cancellationToken);

    Task<LeaseWorkerLaunchResult> LaunchAsync(Guid leaseId, CancellationToken cancellationToken);
}

public sealed class DelegateLeaseWorkerLauncher : ILeaseWorkerLauncher
{
    private readonly Func<Guid, CancellationToken, Task<LeaseWorkerLaunchResult>> _launcher;
    private readonly Func<CancellationToken, Task<LeaseWorkerLaunchResult>> _healthCheck;

    public DelegateLeaseWorkerLauncher(
        Func<Guid, CancellationToken, Task<LeaseWorkerLaunchResult>> launcher,
        Func<CancellationToken, Task<LeaseWorkerLaunchResult>>? healthCheck = null)
    {
        ArgumentNullException.ThrowIfNull(launcher);
        _launcher = launcher;
        _healthCheck = healthCheck ?? (_ => Task.FromResult(
            new LeaseWorkerLaunchResult(Started: true, "Delegate launcher is available.")));
    }

    public Task<LeaseWorkerLaunchResult> CheckHealthAsync(CancellationToken cancellationToken) =>
        _healthCheck(cancellationToken);

    public Task<LeaseWorkerLaunchResult> LaunchAsync(Guid leaseId, CancellationToken cancellationToken) =>
        _launcher(leaseId, cancellationToken);
}

public sealed class UnavailableLeaseWorkerLauncher : ILeaseWorkerLauncher
{
    private readonly string _summary;

    public UnavailableLeaseWorkerLauncher(string summary)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(summary);
        _summary = summary;
    }

    public Task<LeaseWorkerLaunchResult> CheckHealthAsync(CancellationToken cancellationToken) =>
        Task.FromResult(new LeaseWorkerLaunchResult(Started: false, _summary));

    public Task<LeaseWorkerLaunchResult> LaunchAsync(Guid leaseId, CancellationToken cancellationToken) =>
        Task.FromResult(new LeaseWorkerLaunchResult(Started: false, _summary));
}
