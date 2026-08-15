using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Text;
using DistractionFirewall.Core.Targets;
using DistractionFirewall.DnsFilter.DnsProtocol;
using DistractionFirewall.DnsFilter.Runtime;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace DistractionFirewall.DnsFilter.Tests;

public sealed class DnsIndependentQaTests
{
    private const string PrivateQueryMarker = "qa-private-marker/segment.example";

    public static IEnumerable<object[]> MalformedQueryCorpus()
    {
        yield return ["short header", new byte[DnsMessageParser.HeaderLength - 1]];
        yield return ["response instead of query", CreateQuery("example.test", flags: 0x8100)];
        yield return ["zero questions", CreateHeader(questionCount: 0)];
        yield return ["multiple questions", CreateHeader(questionCount: 2)];
        yield return ["truncated label", CreateRawQuestion([2, (byte)'x'])];
        yield return ["reserved label tag", CreateRawQuestion([0x40])];
        yield return ["truncated compression pointer", CreateRawQuestion([0xC0])];
        yield return ["out of bounds compression pointer", CreateRawQuestion([0xC0, 0xFF])];
        yield return ["non printable label", CreateRawQuestion([1, 0x20, 0])];
        yield return ["truncated question tail", CreateRawQuestion([0], questionTailBytes: 3)];
        yield return ["compression depth limit", CreateCompressionDepthQuery()];
    }

    [Fact]
    public void ReadName_resolves_a_valid_backward_compression_pointer()
    {
        using var stream = new MemoryStream();
        WriteName(stream, "youtube.com");
        var compressedNameOffset = checked((int)stream.Position);
        stream.WriteByte(3);
        stream.Write("www"u8);
        stream.WriteByte(0xC0);
        stream.WriteByte(0x00);
        var message = stream.ToArray();
        var offset = compressedNameOffset;

        var name = DnsMessageParser.ReadName(message, ref offset);

        Assert.Equal("www.youtube.com", name);
        Assert.Equal(message.Length, offset);
    }

    [Theory]
    [MemberData(nameof(MalformedQueryCorpus))]
    public void Parser_rejects_malformed_query_corpus(string caseName, byte[] query)
    {
        _ = caseName;

        Assert.Throws<DnsProtocolException>(() => DnsMessageParser.ParseSingleQuestion(query));
    }

    [Fact]
    public void Parser_rejects_an_expanded_name_beyond_the_dns_wire_limit()
    {
        var label = new string('a', 63);
        var query = CreateQuery(string.Join('.', label, label, label, label));

        Assert.Throws<DnsProtocolException>(() => DnsMessageParser.ParseSingleQuestion(query));
    }

    [Fact]
    public void Refused_response_sets_exact_safe_flags_and_clears_response_counts()
    {
        const ushort requestFlags = 0x111F;
        var query = CreateQuery("www.youtube.com", requestFlags);

        var response = DnsResponseFactory.CreateRefused(query);

        Assert.Equal(0x1234, ReadUInt16(response, 0));
        Assert.Equal(0x9185, ReadUInt16(response, 2));
        Assert.Equal(1, ReadUInt16(response, 4));
        Assert.Equal(0, ReadUInt16(response, 6));
        Assert.Equal(0, ReadUInt16(response, 8));
        Assert.Equal(0, ReadUInt16(response, 10));
    }

    [Fact]
    public void Format_error_preserves_only_transaction_opcode_and_recursion_request_flags()
    {
        var malformed = CreateHeader(flags: 0x111F, questionCount: 0);

        var response = DnsResponseFactory.CreateFormatError(malformed);

        Assert.Equal(DnsMessageParser.HeaderLength, response.Length);
        Assert.Equal(0x1234, ReadUInt16(response, 0));
        Assert.Equal(0x9181, ReadUInt16(response, 2));
        Assert.Equal(0, ReadUInt16(response, 4));
        Assert.Equal(0, ReadUInt16(response, 6));
        Assert.Equal(0, ReadUInt16(response, 8));
        Assert.Equal(0, ReadUInt16(response, 10));
    }

    [Fact]
    public void Inspector_reads_target_cname_ipv4_ipv6_and_each_ttl()
    {
        using var response = CreateResponseWithQuestion("alias.example", answerCount: 3);
        WriteCnameAnswer(response, "edge.youtube.com", ttl: 60);
        WriteAddressAnswer(response, IPAddress.Parse("192.0.2.10"), ttl: 30);
        WriteAddressAnswer(response, IPAddress.Parse("2001:db8::10"), ttl: 600);

        var inspection = DnsResponseInspector.Inspect(response.ToArray(), CreateMatcher());

        Assert.True(inspection.ContainsTargetCname);
        Assert.Equal(inspection.Addresses, inspection.TargetAddresses);
        Assert.Collection(
            inspection.Addresses,
            address =>
            {
                Assert.Equal(IPAddress.Parse("192.0.2.10"), address.Address);
                Assert.Equal(30U, address.TtlSeconds);
            },
            address =>
            {
                Assert.Equal(IPAddress.Parse("2001:db8::10"), address.Address);
                Assert.Equal(600U, address.TtlSeconds);
            });
    }

    [Fact]
    public void Inspector_rejects_a_cname_that_reads_beyond_its_rdata_boundary()
    {
        using var response = CreateResponseWithQuestion("alias.example", answerCount: 1);
        WriteAnswerPrefix(response, type: 5, ttl: 60, dataLength: 1);
        response.WriteByte(3);
        response.Write("bad"u8);
        response.WriteByte(0);

        Assert.Throws<DnsProtocolException>(() =>
            DnsResponseInspector.Inspect(response.ToArray(), CreateMatcher()));
    }

    [Theory]
    [InlineData("youtube.com", true)]
    [InlineData("WWW.YouTube.Com.", true)]
    [InlineData("media.youtube.com", true)]
    [InlineData("notyoutube.com", false)]
    [InlineData("youtube.com.example", false)]
    [InlineData("youtube-com.example", false)]
    public void Target_matching_respects_dns_label_boundaries(string host, bool expected)
    {
        var matcher = CreateMatcher();

        Assert.Equal(expected, matcher.MatchesHost(host));
        Assert.Equal(expected, matcher.MatchesCname(host));
    }

    [Fact]
    public async Task Processor_refuses_a_target_with_a_precancelled_token_without_upstream_io()
    {
        var processor = CreateProcessor();
        using var cancellationSource = new CancellationTokenSource();
        await cancellationSource.CancelAsync().ConfigureAwait(true);

        var response = await processor
            .ProcessAsync(CreateQuery("m.youtube.com"), cancellationSource.Token)
            .ConfigureAwait(true);

        Assert.Equal(5, ReadUInt16(response, 2) & 0x000F);
    }

    [Fact]
    public async Task Processor_treats_an_invalid_query_name_as_formerr_without_console_or_exception_disclosure()
    {
        var processor = CreateProcessor();
        var query = CreateQuery(PrivateQueryMarker);
        var originalOutput = Console.Out;
        var originalError = Console.Error;
        using var capturedOutput = new StringWriter(CultureInfo.InvariantCulture);
        using var capturedError = new StringWriter(CultureInfo.InvariantCulture);
        byte[]? response = null;
        Exception? escapedException;

        try
        {
            Console.SetOut(capturedOutput);
            Console.SetError(capturedError);
            escapedException = await Record.ExceptionAsync(async () =>
            {
                response = await processor.ProcessAsync(query, CancellationToken.None).ConfigureAwait(true);
            }).ConfigureAwait(true);
        }
        finally
        {
            Console.SetOut(originalOutput);
            Console.SetError(originalError);
        }

        var observableText = string.Join(
            Environment.NewLine,
            capturedOutput.ToString(),
            capturedError.ToString(),
            escapedException?.ToString() ?? string.Empty);
        Assert.DoesNotContain(PrivateQueryMarker, observableText, StringComparison.OrdinalIgnoreCase);
        Assert.Null(escapedException);
        Assert.NotNull(response);
        Assert.Equal(1, ReadUInt16(response, 2) & 0x000F);
    }

    private static DnsQueryProcessor CreateProcessor() => new(
        CreateMatcher(),
        [new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53)],
        new NullTargetAddressObserver(),
        TimeSpan.FromMilliseconds(25));

    private static TargetMatcher CreateMatcher() => new([CreateTarget()]);

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

    private static byte[] CreateQuery(string name, ushort flags = 0x0100)
    {
        using var stream = new MemoryStream();
        stream.Write(CreateHeader(flags));
        WriteName(stream, name);
        WriteQuestionTail(stream);
        return stream.ToArray();
    }

    private static byte[] CreateHeader(ushort flags = 0x0100, ushort questionCount = 1)
    {
        var header = new byte[DnsMessageParser.HeaderLength];
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(0, 2), 0x1234);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(2, 2), flags);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4, 2), questionCount);
        return header;
    }

    private static byte[] CreateRawQuestion(byte[] encodedName, int questionTailBytes = 4)
    {
        using var stream = new MemoryStream();
        stream.Write(CreateHeader());
        stream.Write(encodedName);
        stream.Write(new byte[questionTailBytes]);
        return stream.ToArray();
    }

    private static byte[] CreateCompressionDepthQuery()
    {
        var query = new byte[18 + (34 * 2) + 1];
        CreateHeader().CopyTo(query, 0);
        query[12] = 0xC0;
        query[13] = 18;
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(14, 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(16, 2), 1);
        for (var index = 0; index < 34; index++)
        {
            var pointerOffset = 18 + (index * 2);
            var destination = pointerOffset + 2;
            query[pointerOffset] = (byte)(0xC0 | (destination >> 8));
            query[pointerOffset + 1] = (byte)destination;
        }

        query[^1] = 0;
        return query;
    }

    private static MemoryStream CreateResponseWithQuestion(string questionName, ushort answerCount)
    {
        var stream = new MemoryStream();
        var header = CreateHeader(flags: 0x8180);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(6, 2), answerCount);
        stream.Write(header);
        WriteName(stream, questionName);
        WriteQuestionTail(stream);
        return stream;
    }

    private static void WriteCnameAnswer(Stream stream, string cname, uint ttl)
    {
        using var data = new MemoryStream();
        WriteName(data, cname);
        var bytes = data.ToArray();
        WriteAnswerPrefix(stream, type: 5, ttl, checked((ushort)bytes.Length));
        stream.Write(bytes);
    }

    private static void WriteAddressAnswer(Stream stream, IPAddress address, uint ttl)
    {
        var bytes = address.GetAddressBytes();
        var type = bytes.Length == 4 ? (ushort)1 : (ushort)28;
        WriteAnswerPrefix(stream, type, ttl, checked((ushort)bytes.Length));
        stream.Write(bytes);
    }

    private static void WriteAnswerPrefix(Stream stream, ushort type, uint ttl, ushort dataLength)
    {
        Span<byte> prefix = stackalloc byte[12];
        prefix[0] = 0xC0;
        prefix[1] = 0x0C;
        BinaryPrimitives.WriteUInt16BigEndian(prefix[2..4], type);
        BinaryPrimitives.WriteUInt16BigEndian(prefix[4..6], 1);
        BinaryPrimitives.WriteUInt32BigEndian(prefix[6..10], ttl);
        BinaryPrimitives.WriteUInt16BigEndian(prefix[10..12], dataLength);
        stream.Write(prefix);
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
}
