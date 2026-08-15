using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace DistractionFirewall.DnsFilter.DnsProtocol;

public static class DnsReadyProbeProtocol
{
    public const string QuestionName = "_df-ready.invalid";
    public const ushort QuestionType = 16;
    public const ushort QuestionClass = 1;
    public const int TokenByteLength = 32;

    private static ReadOnlySpan<byte> DomainSeparator => "distraction-firewall-ready-v1\0"u8;

    public static bool IsReadinessQuestion(ReadOnlySpan<byte> query, DnsQuestion question)
    {
        ArgumentNullException.ThrowIfNull(question);
        if (query.Length < DnsMessageParser.HeaderLength ||
            question.QuestionEndOffset != query.Length ||
            !string.Equals(question.Name, QuestionName, StringComparison.OrdinalIgnoreCase) ||
            question.Type != QuestionType ||
            question.Class != QuestionClass)
        {
            return false;
        }

        var flags = BinaryPrimitives.ReadUInt16BigEndian(query[2..4]);
        return (flags & 0x7800) == 0 &&
            BinaryPrimitives.ReadUInt16BigEndian(query[6..8]) == 0 &&
            BinaryPrimitives.ReadUInt16BigEndian(query[8..10]) == 0 &&
            BinaryPrimitives.ReadUInt16BigEndian(query[10..12]) == 0;
    }

    public static byte[] CreateResponse(ReadOnlySpan<byte> query, DnsQuestion question, ReadOnlySpan<byte> token)
    {
        ArgumentNullException.ThrowIfNull(question);
        if (!IsReadinessQuestion(query, question))
        {
            throw new ArgumentException("The DNS message is not the fixed readiness question.", nameof(query));
        }

        if (token.Length != TokenByteLength)
        {
            throw new ArgumentException("The readiness token must contain exactly 32 bytes.", nameof(token));
        }

        var responseText = ComputeResponseText(token);
        const int answerBytes = 2 + 2 + 2 + 4 + 2 + 1 + (SHA256.HashSizeInBytes * 2);
        var response = new byte[question.QuestionEndOffset + answerBytes];
        query[..question.QuestionEndOffset].CopyTo(response);

        var requestFlags = BinaryPrimitives.ReadUInt16BigEndian(query[2..4]);
        BinaryPrimitives.WriteUInt16BigEndian(
            response.AsSpan(2, 2),
            (ushort)(0x8000 | 0x0400 | (requestFlags & 0x0100)));
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(6, 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(8, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(10, 2), 0);

        var offset = question.QuestionEndOffset;
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), 0xC00C);
        offset += 2;
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), QuestionType);
        offset += 2;
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), QuestionClass);
        offset += 2;
        BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(offset, 4), 0);
        offset += 4;
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), checked((ushort)(responseText.Length + 1)));
        offset += 2;
        response[offset++] = checked((byte)responseText.Length);
        Encoding.ASCII.GetBytes(responseText, response.AsSpan(offset));
        return response;
    }

    public static string ComputeResponseText(ReadOnlySpan<byte> token)
    {
        if (token.Length != TokenByteLength)
        {
            throw new ArgumentException("The readiness token must contain exactly 32 bytes.", nameof(token));
        }

        Span<byte> input = stackalloc byte[DomainSeparator.Length + TokenByteLength];
        DomainSeparator.CopyTo(input);
        token.CopyTo(input[DomainSeparator.Length..]);
        return Convert.ToHexStringLower(SHA256.HashData(input));
    }
}
