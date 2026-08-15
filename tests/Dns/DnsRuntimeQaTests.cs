using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Text;
using DistractionFirewall.Core.Targets;
using DistractionFirewall.DnsFilter.DnsProtocol;
using DistractionFirewall.DnsFilter.Runtime;

namespace DistractionFirewall.DnsFilter.Tests;

public sealed class DnsRuntimeQaTests
{
    [Fact]
    public async Task Target_query_returns_refused_before_shadow_resolution_then_observes_ipv4_and_ipv6()
    {
        var upstream = new ControlledUpstreamClient();
        var observer = new RecordingObserver();
        var processor = CreateProcessor(upstream, observer);

        var processTask = processor.ProcessAsync(CreateQuery("m.youtube.com"), CancellationToken.None);
        var response = await processTask.WaitAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(true);
        await upstream.Started.WaitAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(true);

        Assert.Equal(5, ReadUInt16(response, 2) & 0x000F);
        Assert.True(processTask.IsCompletedSuccessfully);
        Assert.Equal(0, observer.ObservationCount);

        upstream.Complete(CreateResponse(
            "m.youtube.com",
            new AddressAnswer("m.youtube.com", IPAddress.Parse("192.0.2.40"), 40),
            new AddressAnswer("m.youtube.com", IPAddress.Parse("2001:db8::40"), 80)));
        var observed = await observer.WaitForFirstAsync().ConfigureAwait(true);

        Assert.Collection(
            observed,
            address =>
            {
                Assert.Equal(IPAddress.Parse("192.0.2.40"), address.Address);
                Assert.Equal(40U, address.TtlSeconds);
            },
            address =>
            {
                Assert.Equal(IPAddress.Parse("2001:db8::40"), address.Address);
                Assert.Equal(80U, address.TtlSeconds);
            });
    }

    [Fact]
    public async Task Cname_target_refuses_and_observes_only_addresses_connected_to_target_chain()
    {
        var upstreamResponse = CreateResponse(
            "alias.example",
            new CnameAnswer("alias.example", "edge.youtube.com", 60),
            new AddressAnswer("edge.youtube.com", IPAddress.Parse("192.0.2.44"), 45),
            new AddressAnswer("unrelated.example", IPAddress.Parse("198.51.100.9"), 90),
            new AddressAnswer("unrelated.example", IPAddress.Parse("2001:db8::99"), 120));
        var upstream = new ImmediateUpstreamClient(upstreamResponse);
        var observer = new RecordingObserver();
        var processor = CreateProcessor(upstream, observer);

        var response = await processor
            .ProcessAsync(CreateQuery("alias.example"), CancellationToken.None)
            .ConfigureAwait(true);

        Assert.Equal(5, ReadUInt16(response, 2) & 0x000F);
        var observation = Assert.Single(observer.Observations);
        var address = Assert.Single(observation);
        Assert.Equal(IPAddress.Parse("192.0.2.44"), address.Address);
        Assert.Equal(45U, address.TtlSeconds);
    }

    [Fact]
    public async Task General_query_returns_upstream_response_without_logging_or_observer_persistence()
    {
        const string queryName = "qa-general-private-name.example";
        var upstreamResponse = CreateResponse(
            queryName,
            new AddressAnswer(queryName, IPAddress.Parse("203.0.113.12"), 120));
        var upstream = new ImmediateUpstreamClient(upstreamResponse);
        var observer = new RecordingObserver();
        var processor = CreateProcessor(upstream, observer);
        var originalOutput = Console.Out;
        var originalError = Console.Error;
        using var capturedOutput = new StringWriter(CultureInfo.InvariantCulture);
        using var capturedError = new StringWriter(CultureInfo.InvariantCulture);
        byte[] response;

        try
        {
            Console.SetOut(capturedOutput);
            Console.SetError(capturedError);
            response = await processor
                .ProcessAsync(CreateQuery(queryName), CancellationToken.None)
                .ConfigureAwait(true);
        }
        finally
        {
            Console.SetOut(originalOutput);
            Console.SetError(originalError);
        }

        Assert.Equal(upstreamResponse, response);
        Assert.Equal(1, upstream.CallCount);
        Assert.Equal(0, observer.ObservationCount);
        Assert.DoesNotContain(queryName, capturedOutput.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(queryName, capturedError.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    private static DnsQueryProcessor CreateProcessor(
        IDnsUpstreamClient upstream,
        ITargetAddressObserver observer) => new(
            new TargetMatcher([CreateTarget()]),
            [new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53)],
            observer,
            TimeSpan.FromSeconds(1),
            upstream);

    private static TargetDefinition CreateTarget() => new()
    {
        StableId = "qa-target",
        DisplayName = "QA target",
        CatalogVersion = "1.0.0",
        ExactHosts = [],
        SuffixHosts = ["youtube.com"],
        CnameSuffixes = ["youtube.com"],
        BrowserUrlPatterns = ["*://*.youtube.com/*"],
        IpBlockPolicy = new IpBlockPolicyDefinition
        {
            Mode = IpBlockMode.DnsObserved,
            SourceFields = ["suffix_hosts"],
            AddressFamilies = ["ipv4", "ipv6"],
            TransportProtocols = ["tcp", "udp"],
            FollowCnameChain = true,
            MaxObservationTtlSeconds = 900,
            SharedAddressAction = SharedAddressAction.Block,
        },
    };

    private static byte[] CreateQuery(string name)
    {
        using var stream = new MemoryStream();
        var header = new byte[DnsMessageParser.HeaderLength];
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(0, 2), 0x1234);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(2, 2), 0x0100);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4, 2), 1);
        stream.Write(header);
        WriteName(stream, name);
        WriteQuestionTail(stream);
        return stream.ToArray();
    }

    private static byte[] CreateResponse(string questionName, params Answer[] answers)
    {
        using var stream = new MemoryStream();
        var header = new byte[DnsMessageParser.HeaderLength];
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(0, 2), 0x1234);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(2, 2), 0x8180);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4, 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(6, 2), checked((ushort)answers.Length));
        stream.Write(header);
        WriteName(stream, questionName);
        WriteQuestionTail(stream);
        foreach (var answer in answers)
        {
            WriteName(stream, answer.Owner);
            switch (answer)
            {
                case CnameAnswer cname:
                    using (var data = new MemoryStream())
                    {
                        WriteName(data, cname.Target);
                        WriteAnswerBody(stream, type: 5, cname.Ttl, data.ToArray());
                    }

                    break;
                case AddressAnswer address:
                    var bytes = address.Address.GetAddressBytes();
                    WriteAnswerBody(
                        stream,
                        bytes.Length == 4 ? (ushort)1 : (ushort)28,
                        address.Ttl,
                        bytes);
                    break;
            }
        }

        return stream.ToArray();
    }

    private static void WriteAnswerBody(Stream stream, ushort type, uint ttl, byte[] data)
    {
        Span<byte> body = stackalloc byte[10];
        BinaryPrimitives.WriteUInt16BigEndian(body[..2], type);
        BinaryPrimitives.WriteUInt16BigEndian(body[2..4], 1);
        BinaryPrimitives.WriteUInt32BigEndian(body[4..8], ttl);
        BinaryPrimitives.WriteUInt16BigEndian(body[8..10], checked((ushort)data.Length));
        stream.Write(body);
        stream.Write(data);
    }

    private static void WriteQuestionTail(Stream stream)
    {
        Span<byte> tail = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(tail[..2], 1);
        BinaryPrimitives.WriteUInt16BigEndian(tail[2..], 1);
        stream.Write(tail);
    }

    private static void WriteName(Stream stream, string name)
    {
        foreach (var label in name.Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            stream.WriteByte(checked((byte)bytes.Length));
            stream.Write(bytes);
        }

        stream.WriteByte(0);
    }

    private static ushort ReadUInt16(byte[] message, int offset) =>
        BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(offset, 2));

    private abstract record Answer(string Owner, uint Ttl);

    private sealed record CnameAnswer(string Owner, string Target, uint Ttl) : Answer(Owner, Ttl);

    private sealed record AddressAnswer(string Owner, IPAddress Address, uint Ttl) : Answer(Owner, Ttl);

    private sealed class ControlledUpstreamClient : IDnsUpstreamClient
    {
        private readonly TaskCompletionSource<byte[]> _response = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _started = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public Task Started => _started.Task;

        public Task<byte[]> QueryAsync(
            byte[] query,
            IPEndPoint upstream,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            _started.TrySetResult();
            return _response.Task;
        }

        public void Complete(byte[] response)
        {
            Assert.True(_response.TrySetResult(response));
        }
    }

    private sealed class ImmediateUpstreamClient(byte[] response) : IDnsUpstreamClient
    {
        public int CallCount { get; private set; }

        public Task<byte[]> QueryAsync(
            byte[] query,
            IPEndPoint upstream,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(response);
        }
    }

    private sealed class RecordingObserver : ITargetAddressObserver
    {
        private readonly ConcurrentQueue<IReadOnlyList<DnsObservedAddress>> _observations = new();
        private readonly TaskCompletionSource<IReadOnlyList<DnsObservedAddress>> _first = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public IReadOnlyList<IReadOnlyList<DnsObservedAddress>> Observations => _observations.ToArray();

        public int ObservationCount => _observations.Count;

        public ValueTask ObserveAsync(
            IReadOnlyList<DnsObservedAddress> addresses,
            CancellationToken cancellationToken)
        {
            var snapshot = addresses.ToArray();
            _observations.Enqueue(snapshot);
            _first.TrySetResult(snapshot);
            return ValueTask.CompletedTask;
        }

        public Task<IReadOnlyList<DnsObservedAddress>> WaitForFirstAsync() =>
            _first.Task.WaitAsync(TimeSpan.FromSeconds(2));
    }
}

public sealed class DnsUpstreamClientTests
{
    [Fact]
    public async Task Udp_tc_response_retries_the_same_upstream_over_tcp()
    {
        var query = CreateMessage(transactionId: 0x1234, flags: 0x0100);
        var udp = CreateMessage(transactionId: 0x1234, flags: 0x8380);
        var tcp = CreateMessage(transactionId: 0x1234, flags: 0x8180);
        var transport = new FakeTransport(udp, tcp);
        var client = new DnsUpstreamClient(transport);
        var endpoint = new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53);

        var response = await client
            .QueryAsync(query, endpoint, TimeSpan.FromSeconds(1), CancellationToken.None)
            .ConfigureAwait(true);

        Assert.Equal(tcp, response);
        Assert.Equal(["udp", "tcp"], transport.Protocols);
        Assert.All(transport.Endpoints, actual => Assert.Equal(endpoint, actual));
    }

    [Fact]
    public async Task Tcp_retry_rejects_a_mismatched_transaction_id()
    {
        var query = CreateMessage(transactionId: 0x1234, flags: 0x0100);
        var udp = CreateMessage(transactionId: 0x1234, flags: 0x8380);
        var tcp = CreateMessage(transactionId: 0x9999, flags: 0x8180);
        var client = new DnsUpstreamClient(new FakeTransport(udp, tcp));

        await Assert.ThrowsAsync<IOException>(() => client.QueryAsync(
            query,
            new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53),
            TimeSpan.FromSeconds(1),
            CancellationToken.None)).ConfigureAwait(true);
    }

    [Fact]
    public async Task Tcp_frame_rejects_a_declared_length_shorter_than_a_dns_header()
    {
        using var stream = new MemoryStream([0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        await Assert.ThrowsAsync<IOException>(() =>
            DnsTcpFrameCodec.ReadResponseAsync(stream, CancellationToken.None)).ConfigureAwait(true);
    }

    [Fact]
    public async Task Tcp_frame_rejects_a_payload_shorter_than_its_declared_length()
    {
        using var stream = new MemoryStream([0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        await Assert.ThrowsAsync<EndOfStreamException>(() =>
            DnsTcpFrameCodec.ReadResponseAsync(stream, CancellationToken.None)).ConfigureAwait(true);
    }

    private static byte[] CreateMessage(ushort transactionId, ushort flags)
    {
        var message = new byte[DnsMessageParser.HeaderLength];
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(0, 2), transactionId);
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2, 2), flags);
        return message;
    }

    private sealed class FakeTransport(byte[] udpResponse, byte[] tcpResponse) : IDnsUpstreamTransport
    {
        public List<string> Protocols { get; } = [];

        public List<IPEndPoint> Endpoints { get; } = [];

        public Task<byte[]> QueryUdpAsync(
            byte[] query,
            IPEndPoint upstream,
            CancellationToken cancellationToken)
        {
            Protocols.Add("udp");
            Endpoints.Add(upstream);
            return Task.FromResult(udpResponse);
        }

        public Task<byte[]> QueryTcpAsync(
            byte[] query,
            IPEndPoint upstream,
            CancellationToken cancellationToken)
        {
            Protocols.Add("tcp");
            Endpoints.Add(upstream);
            return Task.FromResult(tcpResponse);
        }
    }
}
