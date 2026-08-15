using System.Buffers.Binary;

namespace DistractionFirewall.DnsFilter.DnsProtocol;

public static class DnsResponseFactory
{
    public static byte[] CreateRefused(ReadOnlySpan<byte> query)
    {
        var question = DnsMessageParser.ParseSingleQuestion(query);
        var response = query[..question.QuestionEndOffset].ToArray();
        var requestFlags = BinaryPrimitives.ReadUInt16BigEndian(query[2..4]);
        var responseFlags = (ushort)(0x8000 | (requestFlags & 0x7900) | 0x0080 | 0x0005);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2, 2), responseFlags);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(6, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(8, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(10, 2), 0);
        return response;
    }

    public static byte[] CreateFormatError(ReadOnlySpan<byte> query)
    {
        var response = new byte[DnsMessageParser.HeaderLength];
        if (query.Length >= 2)
        {
            query[..2].CopyTo(response);
        }

        ushort requestFlags = 0;
        if (query.Length >= 4)
        {
            requestFlags = BinaryPrimitives.ReadUInt16BigEndian(query[2..4]);
        }

        BinaryPrimitives.WriteUInt16BigEndian(
            response.AsSpan(2, 2),
            (ushort)(0x8000 | (requestFlags & 0x7900) | 0x0080 | 0x0001));
        return response;
    }
}
