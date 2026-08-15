using DistractionFirewall.DnsFilter.DnsProtocol;

namespace DistractionFirewall.DnsFilter.Runtime;

public sealed record DnsObservationContext(
    Guid LeaseId,
    DateTimeOffset LeaseExpiresUtc,
    string ObservationStorePath);

public interface IDnsObservationStore
{
    ValueTask AppendAsync(
        DnsObservationContext context,
        IReadOnlyList<DnsObservedAddress> addresses,
        CancellationToken cancellationToken);
}

public interface ITargetAddressObserverFactory
{
    ITargetAddressObserver Create(DnsObservationContext context);
}

public sealed class ObservationStoreTargetAddressObserverFactory(
    IDnsObservationStore observationStore) : ITargetAddressObserverFactory
{
    private readonly IDnsObservationStore _observationStore =
        observationStore ?? throw new ArgumentNullException(nameof(observationStore));

    public ITargetAddressObserver Create(DnsObservationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return new ObservationStoreTargetAddressObserver(_observationStore, context);
    }
}

public sealed class ObservationStoreTargetAddressObserver : ITargetAddressObserver
{
    private readonly IDnsObservationStore _observationStore;
    private readonly DnsObservationContext _context;

    public ObservationStoreTargetAddressObserver(
        IDnsObservationStore observationStore,
        DnsObservationContext context)
    {
        _observationStore = observationStore ?? throw new ArgumentNullException(nameof(observationStore));
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public ValueTask ObserveAsync(
        IReadOnlyList<DnsObservedAddress> addresses,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(addresses);
        return _observationStore.AppendAsync(_context, addresses, cancellationToken);
    }
}
