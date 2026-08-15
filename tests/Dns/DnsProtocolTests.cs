using System.Buffers.Binary;
using System.Net;
using System.Text;
using DistractionFirewall.Core.Targets;
using DistractionFirewall.DnsFilter.DnsProtocol;
using DistractionFirewall.DnsFilter.Runtime;

namespace DistractionFirewall.DnsFilter.Tests;

public sealed class DnsProtocolTests
{
    [Fact]
    public void Parser_reads_a_single_dns_question()
    {
        var query = CreateQuery("www.youtube.com");

        var question = DnsMessageParser.ParseSingleQuestion(query);

        Assert.Equal(0x1234, question.TransactionId);
        Assert.Equal("www.youtube.com", question.Name);
        Assert.Equal(1, question.Type);
        Assert.Equal(1, question.Class);
        Assert.Equal(query.Length, question.QuestionEndOffset);
    }

    [Fact]
    public void Parser_rejects_a_compression_pointer_loop()
    {
        var query = CreateQuery("a.example");
        query[12] = 0xC0;
        query[13] = 0x0C;

        Assert.Throws<DnsProtocolException>(() => DnsMessageParser.ParseSingleQuestion(query));
    }

    [Fact]
    public void Refused_response_preserves_question_and_has_no_answers()
    {
        var query = CreateQuery("www.youtube.com");

        var response = DnsResponseFactory.CreateRefused(query);

        Assert.Equal(query.Length, response.Length);
        Assert.Equal(0x1234, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(0, 2)));
        var flags = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2, 2));
        Assert.NotEqual(0, flags & 0x8000);
        Assert.Equal(5, flags & 0x000F);
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(4, 2)));
        Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(6, 2)));
    }

    [Fact]
    public void Response_inspector_detects_a_target_cname()
    {
        var response = CreateCnameResponse("alias.example", "www.youtube.com");
        var matcher = new TargetMatcher([CreateTarget()]);

        var inspection = DnsResponseInspector.Inspect(response, matcher);

        Assert.True(inspection.ContainsTargetCname);
        Assert.Empty(inspection.Addresses);
    }

    [Fact]
    public void Response_inspector_returns_address_and_ttl()
    {
        var response = CreateAddressResponse("edge.example", IPAddress.Parse("192.0.2.10"), 120);
        var matcher = new TargetMatcher([CreateTarget()]);

        var inspection = DnsResponseInspector.Inspect(response, matcher);

        var observed = Assert.Single(inspection.Addresses);
        Assert.Equal(IPAddress.Parse("192.0.2.10"), observed.Address);
        Assert.Equal(120U, observed.TtlSeconds);
    }

    [Fact]
    public async Task Processor_refuses_target_without_contacting_upstream()
    {
        var processor = new DnsQueryProcessor(
            new TargetMatcher([CreateTarget()]),
            [new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53)],
            new NullTargetAddressObserver(),
            TimeSpan.FromMilliseconds(100));

        var response = await processor.ProcessAsync(CreateQuery("m.youtube.com"), CancellationToken.None);

        Assert.Equal(5, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2, 2)) & 0x000F);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(11)]
    public async Task Processor_returns_format_error_for_truncated_input(int size)
    {
        var processor = new DnsQueryProcessor(
            new TargetMatcher([CreateTarget()]),
            [new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53)],
            new NullTargetAddressObserver(),
            TimeSpan.FromMilliseconds(100));

        var response = await processor.ProcessAsync(new byte[size], CancellationToken.None);

        Assert.Equal(12, response.Length);
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2, 2)) & 0x000F);
    }

    private static byte[] CreateQuery(string name)
    {
        using var stream = new MemoryStream();
        Span<byte> header = stackalloc byte[12];
        header.Clear();
        BinaryPrimitives.WriteUInt16BigEndian(header[..2], 0x1234);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..4], 0x0100);
        BinaryPrimitives.WriteUInt16BigEndian(header[4..6], 1);
        stream.Write(header);
        WriteName(stream, name);
        Span<byte> questionTail = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(questionTail[..2], 1);
        BinaryPrimitives.WriteUInt16BigEndian(questionTail[2..], 1);
        stream.Write(questionTail);
        return stream.ToArray();
    }

    private static byte[] CreateCnameResponse(string questionName, string cname)
    {
        using var stream = CreateResponseWithQuestion(questionName, answerCount: 1);
        WriteAnswerPrefix(stream, type: 5, ttl: 60);
        using var rdata = new MemoryStream();
        WriteName(rdata, cname);
        WriteResourceData(stream, rdata.ToArray());
        return stream.ToArray();
    }

    private static byte[] CreateAddressResponse(string questionName, IPAddress address, uint ttl)
    {
        using var stream = CreateResponseWithQuestion(questionName, answerCount: 1);
        WriteAnswerPrefix(stream, type: address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? (ushort)1 : (ushort)28, ttl);
        WriteResourceData(stream, address.GetAddressBytes());
        return stream.ToArray();
    }

    private static MemoryStream CreateResponseWithQuestion(string questionName, ushort answerCount)
    {
        var stream = new MemoryStream();
        Span<byte> header = stackalloc byte[12];
        header.Clear();
        BinaryPrimitives.WriteUInt16BigEndian(header[..2], 0x1234);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..4], 0x8180);
        BinaryPrimitives.WriteUInt16BigEndian(header[4..6], 1);
        BinaryPrimitives.WriteUInt16BigEndian(header[6..8], answerCount);
        stream.Write(header);
        WriteName(stream, questionName);
        Span<byte> questionTail = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(questionTail[..2], 1);
        BinaryPrimitives.WriteUInt16BigEndian(questionTail[2..], 1);
        stream.Write(questionTail);
        return stream;
    }

    private static void WriteAnswerPrefix(Stream stream, ushort type, uint ttl)
    {
        Span<byte> prefix = stackalloc byte[12];
        prefix[0] = 0xC0;
        prefix[1] = 0x0C;
        BinaryPrimitives.WriteUInt16BigEndian(prefix[2..4], type);
        BinaryPrimitives.WriteUInt16BigEndian(prefix[4..6], 1);
        BinaryPrimitives.WriteUInt32BigEndian(prefix[6..10], ttl);
        stream.Write(prefix[..10]);
    }

    private static void WriteResourceData(Stream stream, byte[] data)
    {
        Span<byte> length = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(length, checked((ushort)data.Length));
        stream.Write(length);
        stream.Write(data);
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

    private static TargetDefinition CreateTarget() => new()
    {
        StableId = "test-target",
        DisplayName = "Test target",
        CatalogVersion = "1.0.0",
        ExactHosts = Array.Empty<string>(),
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
}
