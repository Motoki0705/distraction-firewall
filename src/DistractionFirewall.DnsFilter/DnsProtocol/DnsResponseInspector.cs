using System.Buffers.Binary;
using System.Net;
using DistractionFirewall.Core.Targets;

namespace DistractionFirewall.DnsFilter.DnsProtocol;

public sealed record DnsObservedAddress(
    IPAddress Address,
    uint TtlSeconds);

public sealed record DnsInspectionResult(
    bool ContainsTargetCname,
    IReadOnlyList<DnsObservedAddress> Addresses,
    IReadOnlyList<DnsObservedAddress> TargetAddresses);

public static class DnsResponseInspector
{
    private const ushort TypeA = 1;
    private const ushort TypeCname = 5;
    private const ushort TypeAaaa = 28;

    public static DnsInspectionResult Inspect(ReadOnlySpan<byte> response, TargetMatcher matcher)
    {
        ArgumentNullException.ThrowIfNull(matcher);
        if (response.Length < DnsMessageParser.HeaderLength)
        {
            throw new DnsProtocolException("DNS response is shorter than its header.");
        }

        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(response[4..6]);
        var answerCount = BinaryPrimitives.ReadUInt16BigEndian(response[6..8]);
        var offset = DnsMessageParser.HeaderLength;
        var questionNames = new List<string>(questionCount);
        for (var index = 0; index < questionCount; index++)
        {
            questionNames.Add(Canonicalize(DnsMessageParser.ReadName(response, ref offset)));
            if (offset > response.Length - 4)
            {
                throw new DnsProtocolException("DNS response question is truncated.");
            }

            offset += 4;
        }

        var records = new List<AnswerRecord>(answerCount);
        for (var index = 0; index < answerCount; index++)
        {
            var owner = Canonicalize(DnsMessageParser.ReadName(response, ref offset));
            if (offset > response.Length - 10)
            {
                throw new DnsProtocolException("DNS answer is truncated.");
            }

            var type = BinaryPrimitives.ReadUInt16BigEndian(response.Slice(offset, 2));
            var ttl = BinaryPrimitives.ReadUInt32BigEndian(response.Slice(offset + 4, 4));
            var dataLength = BinaryPrimitives.ReadUInt16BigEndian(response.Slice(offset + 8, 2));
            var dataOffset = offset + 10;
            if (dataOffset > response.Length - dataLength)
            {
                throw new DnsProtocolException("DNS answer data is truncated.");
            }

            string? cname = null;
            IPAddress? address = null;
            if (type == TypeCname)
            {
                var cnameOffset = dataOffset;
                var dataEndOffset = dataOffset + dataLength;
                cname = Canonicalize(DnsMessageParser.ReadName(response, ref cnameOffset, dataEndOffset));
                if (cnameOffset != dataEndOffset)
                {
                    throw new DnsProtocolException("DNS CNAME data length does not match its encoded name.");
                }
            }
            else if (type == TypeA && dataLength == 4)
            {
                address = new IPAddress(response.Slice(dataOffset, dataLength));
            }
            else if (type == TypeAaaa && dataLength == 16)
            {
                address = new IPAddress(response.Slice(dataOffset, dataLength));
            }

            records.Add(new AnswerRecord(owner, type, ttl, cname, address));
            offset = dataOffset + dataLength;
        }

        var targetOwnedNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (var name in questionNames)
        {
            AddIfTarget(name, matcher, targetOwnedNames);
        }

        foreach (var record in records)
        {
            AddIfTarget(record.Owner, matcher, targetOwnedNames);
            if (record.Cname is not null)
            {
                AddIfTarget(record.Cname, matcher, targetOwnedNames);
            }
        }

        bool changed;
        do
        {
            changed = false;
            foreach (var record in records.Where(record => record.Cname is not null))
            {
                if (!targetOwnedNames.Contains(record.Owner) &&
                    !targetOwnedNames.Contains(record.Cname!))
                {
                    continue;
                }

                changed |= targetOwnedNames.Add(record.Owner);
                changed |= targetOwnedNames.Add(record.Cname!);
            }
        }
        while (changed);

        var containsTargetCname = records.Any(record =>
            record.Cname is not null &&
            targetOwnedNames.Contains(record.Owner) &&
            targetOwnedNames.Contains(record.Cname));
        var addresses = records
            .Where(record => record.Address is not null)
            .Select(record => new DnsObservedAddress(record.Address!, record.TtlSeconds))
            .ToArray();
        var targetAddresses = records
            .Where(record => record.Address is not null && targetOwnedNames.Contains(record.Owner))
            .Select(record => new DnsObservedAddress(record.Address!, record.TtlSeconds))
            .ToArray();

        return new DnsInspectionResult(containsTargetCname, addresses, targetAddresses);
    }

    private static void AddIfTarget(
        string name,
        TargetMatcher matcher,
        HashSet<string> targetOwnedNames)
    {
        try
        {
            if (matcher.MatchesHost(name) || matcher.MatchesCname(name))
            {
                targetOwnedNames.Add(name);
            }
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
        }
    }

    private static string Canonicalize(string name) => name.TrimEnd('.').ToLowerInvariant();

    private sealed record AnswerRecord(
        string Owner,
        ushort Type,
        uint TtlSeconds,
        string? Cname,
        IPAddress? Address);
}
