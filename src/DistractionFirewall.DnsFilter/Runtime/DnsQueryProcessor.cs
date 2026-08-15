using System.Net;
using System.Net.Sockets;
using DistractionFirewall.Core.Targets;
using DistractionFirewall.DnsFilter.DnsProtocol;

namespace DistractionFirewall.DnsFilter.Runtime;

public interface ITargetAddressObserver
{
    ValueTask ObserveAsync(
        IReadOnlyList<DnsObservedAddress> addresses,
        CancellationToken cancellationToken);
}

public sealed class NullTargetAddressObserver : ITargetAddressObserver
{
    public ValueTask ObserveAsync(
        IReadOnlyList<DnsObservedAddress> addresses,
        CancellationToken cancellationToken) => ValueTask.CompletedTask;
}

public sealed class DnsQueryProcessor
{
    private readonly TargetMatcher _matcher;
    private readonly IPEndPoint[] _upstreams;
    private readonly ITargetAddressObserver _addressObserver;
    private readonly IDnsUpstreamClient _upstreamClient;
    private readonly DnsReadinessResponder? _readinessResponder;
    private readonly TimeSpan _timeout;

    public DnsQueryProcessor(
        TargetMatcher matcher,
        IEnumerable<IPEndPoint> upstreams,
        ITargetAddressObserver addressObserver,
        TimeSpan timeout)
        : this(
            matcher,
            upstreams,
            addressObserver,
            timeout,
            new DnsUpstreamClient(new SocketDnsUpstreamTransport()),
            readinessResponder: null)
    {
    }

    public DnsQueryProcessor(
        TargetMatcher matcher,
        IEnumerable<IPEndPoint> upstreams,
        ITargetAddressObserver addressObserver,
        TimeSpan timeout,
        IDnsUpstreamClient upstreamClient)
        : this(matcher, upstreams, addressObserver, timeout, upstreamClient, readinessResponder: null)
    {
    }

    public DnsQueryProcessor(
        TargetMatcher matcher,
        IEnumerable<IPEndPoint> upstreams,
        ITargetAddressObserver addressObserver,
        TimeSpan timeout,
        IDnsUpstreamClient upstreamClient,
        DnsReadinessResponder? readinessResponder)
    {
        ArgumentNullException.ThrowIfNull(matcher);
        ArgumentNullException.ThrowIfNull(upstreams);
        ArgumentNullException.ThrowIfNull(addressObserver);
        ArgumentNullException.ThrowIfNull(upstreamClient);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(timeout, TimeSpan.Zero);

        _matcher = matcher;
        _upstreams = upstreams.Distinct().ToArray();
        if (_upstreams.Length == 0 || _upstreams.Any(endpoint => IPAddress.IsLoopback(endpoint.Address)))
        {
            throw new ArgumentException("At least one non-loopback upstream DNS endpoint is required.", nameof(upstreams));
        }

        _addressObserver = addressObserver;
        _upstreamClient = upstreamClient;
        _readinessResponder = readinessResponder;
        _timeout = timeout;
    }

    public async Task<byte[]> ProcessAsync(byte[] query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        DnsQuestion question;
        try
        {
            question = DnsMessageParser.ParseSingleQuestion(query);
        }
        catch (DnsProtocolException)
        {
            return DnsResponseFactory.CreateFormatError(query);
        }

        if (_readinessResponder is not null &&
            _readinessResponder.TryCreateResponse(query, question, out var readinessResponse))
        {
            return readinessResponse;
        }

        bool matchesTarget;
        try
        {
            matchesTarget = _matcher.MatchesHost(question.Name);
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            return DnsResponseFactory.CreateFormatError(query);
        }

        if (matchesTarget)
        {
            StartShadowObservation(query.ToArray());
            return DnsResponseFactory.CreateRefused(query);
        }

        var response = await QueryUpstreamsAsync(query, cancellationToken).ConfigureAwait(false);
        var inspection = DnsResponseInspector.Inspect(response, _matcher);
        if (!inspection.ContainsTargetCname)
        {
            return response;
        }

        await ObserveBestEffortAsync(inspection.TargetAddresses, cancellationToken).ConfigureAwait(false);
        return DnsResponseFactory.CreateRefused(query);
    }

    private async Task<byte[]> QueryUpstreamsAsync(
        byte[] query,
        CancellationToken cancellationToken)
    {
        Exception? lastException = null;
        foreach (var upstream in _upstreams)
        {
            try
            {
                return await _upstreamClient
                    .QueryAsync(query, upstream, _timeout, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is SocketException or IOException or OperationCanceledException)
            {
                lastException = exception;
                if (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
            }
        }

        throw new IOException("All configured upstream DNS resolvers failed.", lastException);
    }

    private void StartShadowObservation(byte[] query)
    {
        var observation = ObserveTargetQueryAsync(query);
        _ = observation.ContinueWith(
            static task => _ = task.Exception,
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously | TaskContinuationOptions.OnlyOnFaulted,
            TaskScheduler.Default);
    }

    private async Task ObserveTargetQueryAsync(byte[] query)
    {
        try
        {
            var response = await QueryUpstreamsAsync(query, CancellationToken.None).ConfigureAwait(false);
            var inspection = DnsResponseInspector.Inspect(response, _matcher);
            await ObserveBestEffortAsync(inspection.TargetAddresses, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is SocketException or
            IOException or
            OperationCanceledException or
            DnsProtocolException or
            ArgumentException or
            FormatException)
        {
        }
    }

    private async Task ObserveBestEffortAsync(
        IReadOnlyList<DnsObservedAddress> addresses,
        CancellationToken cancellationToken)
    {
        if (addresses.Count == 0)
        {
            return;
        }

        try
        {
            await _addressObserver.ObserveAsync(addresses, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is IOException or
            UnauthorizedAccessException or
            OperationCanceledException or
            InvalidOperationException)
        {
        }
    }
}
