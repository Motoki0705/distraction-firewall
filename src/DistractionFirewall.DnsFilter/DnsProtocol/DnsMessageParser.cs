using System.Buffers.Binary;
using System.Text;

namespace DistractionFirewall.DnsFilter.DnsProtocol;

public static class DnsMessageParser
{
    public const int HeaderLength = 12;
    private const int MaximumPointerDepth = 32;
    private const int MaximumExpandedWireNameBytes = 255;
    private const int MaximumPrintableNameCharacters = 253;

    public static DnsQuestion ParseSingleQuestion(ReadOnlySpan<byte> message)
    {
        if (message.Length < HeaderLength)
        {
            throw new DnsProtocolException("DNS message is shorter than its header.");
        }

        var flags = BinaryPrimitives.ReadUInt16BigEndian(message[2..4]);
        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(message[4..6]);
        if ((flags & 0x8000) != 0 || questionCount != 1)
        {
            throw new DnsProtocolException("Expected a DNS query containing exactly one question.");
        }

        var offset = HeaderLength;
        var name = ReadName(message, ref offset);
        if (offset + 4 > message.Length)
        {
            throw new DnsProtocolException("DNS question is truncated.");
        }

        var type = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset, 2));
        var queryClass = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset + 2, 2));
        offset += 4;
        return new DnsQuestion(
            BinaryPrimitives.ReadUInt16BigEndian(message[..2]),
            name,
            type,
            queryClass,
            offset);
    }

    public static string ReadName(ReadOnlySpan<byte> message, ref int offset) =>
        ReadName(message, ref offset, message.Length);

    internal static string ReadName(
        ReadOnlySpan<byte> message,
        ref int offset,
        int encodedEndOffset)
    {
        if ((uint)offset > (uint)message.Length ||
            (uint)encodedEndOffset > (uint)message.Length ||
            offset > encodedEndOffset)
        {
            throw new DnsProtocolException("DNS name boundary is invalid.");
        }

        var labels = new List<string>();
        var cursor = offset;
        var resumedOffset = -1;
        var visitedPointers = new HashSet<int>();
        var pointerDepth = 0;
        var expandedWireBytes = 0;
        var printableCharacters = 0;

        while (true)
        {
            var readableEnd = resumedOffset >= 0 ? message.Length : encodedEndOffset;
            if ((uint)cursor >= (uint)readableEnd)
            {
                throw new DnsProtocolException("DNS name extends past the message boundary.");
            }

            var length = message[cursor++];
            if (length == 0)
            {
                expandedWireBytes++;
                if (expandedWireBytes > MaximumExpandedWireNameBytes ||
                    printableCharacters > MaximumPrintableNameCharacters)
                {
                    throw new DnsProtocolException("DNS name exceeds the protocol length limit.");
                }

                offset = resumedOffset >= 0 ? resumedOffset : cursor;
                return string.Join('.', labels);
            }

            if ((length & 0xC0) == 0xC0)
            {
                if ((uint)cursor >= (uint)readableEnd)
                {
                    throw new DnsProtocolException("DNS compression pointer is truncated.");
                }

                var pointer = ((length & 0x3F) << 8) | message[cursor++];
                if ((uint)pointer >= (uint)message.Length)
                {
                    throw new DnsProtocolException("DNS compression pointer is outside the message.");
                }

                if (!visitedPointers.Add(pointer))
                {
                    throw new DnsProtocolException("DNS compression pointer loop detected.");
                }

                pointerDepth++;
                if (pointerDepth > MaximumPointerDepth)
                {
                    throw new DnsProtocolException("DNS name exceeded the compression depth limit.");
                }

                resumedOffset = resumedOffset >= 0 ? resumedOffset : cursor;
                cursor = pointer;
                continue;
            }

            if ((length & 0xC0) != 0 || length > 63 || cursor > readableEnd - length)
            {
                throw new DnsProtocolException("DNS label is invalid or truncated.");
            }

            var labelBytes = message.Slice(cursor, length);
            if (labelBytes.ContainsAnyExceptInRange((byte)0x21, (byte)0x7e))
            {
                throw new DnsProtocolException("DNS label contains non-printable bytes.");
            }

            expandedWireBytes += 1 + length;
            printableCharacters += length + (labels.Count == 0 ? 0 : 1);
            if (expandedWireBytes >= MaximumExpandedWireNameBytes ||
                printableCharacters > MaximumPrintableNameCharacters)
            {
                throw new DnsProtocolException("DNS name exceeds the protocol length limit.");
            }

            labels.Add(Encoding.ASCII.GetString(labelBytes));
            cursor += length;
        }
    }

    public static int SkipResourceRecord(ReadOnlySpan<byte> message, int offset)
    {
        ReadName(message, ref offset);
        if (offset + 10 > message.Length)
        {
            throw new DnsProtocolException("DNS resource record is truncated.");
        }

        var dataLength = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset + 8, 2));
        offset += 10;
        if (offset + dataLength > message.Length)
        {
            throw new DnsProtocolException("DNS resource record data is truncated.");
        }

        return offset + dataLength;
    }
}
