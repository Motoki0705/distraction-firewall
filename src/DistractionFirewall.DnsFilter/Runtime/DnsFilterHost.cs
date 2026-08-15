using DistractionFirewall.Core.Targets;

namespace DistractionFirewall.DnsFilter.Runtime;

public sealed class DnsFilterHost
{
    private readonly ITargetAddressObserverFactory _observerFactory;
    private readonly IDnsFilterServerFactory _serverFactory;
    private readonly TimeProvider _timeProvider;

    public DnsFilterHost(
        ITargetAddressObserverFactory observerFactory,
        IDnsFilterServerFactory serverFactory,
        TimeProvider timeProvider)
    {
        _observerFactory = observerFactory ?? throw new ArgumentNullException(nameof(observerFactory));
        _serverFactory = serverFactory ?? throw new ArgumentNullException(nameof(serverFactory));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    public async Task RunAsync(DnsFilterOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (IsExpired(options))
        {
            return;
        }

        var catalog = await TargetCatalog
            .LoadAsync(options.TargetSnapshotPath, cancellationToken)
            .ConfigureAwait(false);
        if (IsExpired(options))
        {
            return;
        }

        var context = new DnsObservationContext(
            options.LeaseId,
            options.LeaseExpiresUtc,
            options.ObservationStorePath);
        var observer = _observerFactory.Create(context);
        var processor = new DnsQueryProcessor(
            new TargetMatcher(catalog.Targets),
            options.Upstreams,
            observer,
            TimeSpan.FromSeconds(3),
            new DnsUpstreamClient(new SocketDnsUpstreamTransport()),
            new DnsReadinessResponder(options.ReadyToken.Span));

        await using var server = _serverFactory.Create(processor);
        if (IsExpired(options))
        {
            return;
        }

        server.Start();
        Console.WriteLine("DNS filter is ready. Query names and readiness tokens are not logged.");
        var remaining = options.LeaseExpiresUtc - _timeProvider.GetUtcNow();
        if (remaining > TimeSpan.Zero)
        {
            await Task.Delay(remaining, _timeProvider, cancellationToken).ConfigureAwait(false);
        }
    }

    private bool IsExpired(DnsFilterOptions options) =>
        options.LeaseExpiresUtc <= _timeProvider.GetUtcNow();
}
