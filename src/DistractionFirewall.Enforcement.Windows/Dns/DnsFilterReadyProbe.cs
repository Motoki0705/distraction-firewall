using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace DistractionFirewall.Enforcement.Windows.Dns;

internal sealed record DnsFilterReadinessRequest(Guid LeaseId, string ReadyToken);

internal interface IDnsFilterReadyProbe
{
    Task WaitUntilReadyAsync(
        DnsFilterReadinessRequest request,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}

internal sealed class LeaseBoundDnsFilterReadyProbe : IDnsFilterReadyProbe
{
    private const string SentinelName = "_df-ready.invalid.";
    private const ushort TxtRecordType = 16;
    private const ushort InternetClass = 1;
    private static readonly byte[] HashDomainSeparator =
        Encoding.ASCII.GetBytes("distraction-firewall-ready-v1\0");
    private static readonly IPAddress[] LoopbackAddresses =
    [
        IPAddress.Loopback,
        IPAddress.IPv6Loopback,
    ];

    public async Task WaitUntilReadyAsync(
        DnsFilterReadinessRequest request,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        DnsFilterTaskDefinitionBuilder.ValidateReadyToken(request.ReadyToken);
        if (request.LeaseId == Guid.Empty)
        {
            throw new ArgumentException("DNS filter readiness lease ID must not be empty.", nameof(request));
        }

        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentOutOfRangeException(
                nameof(timeout),
                "DNS filter readiness timeout must be greater than zero and no more than one minute.");
        }

        var expectedTxt = ComputeExpectedTxt(request.ReadyToken);
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (await BothFamiliesReturnSentinelAsync(expectedTxt, cancellationToken).ConfigureAwait(false))
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken).ConfigureAwait(false);
        }

        throw new TimeoutException(
            "The lease-bound DNS readiness sentinel was not validated over both IPv4 and IPv6 before timeout.");
    }

    internal static byte[] CreateQuery(ushort transactionId)
    {
        var encodedName = EncodeName(SentinelName);
        var query = new byte[12 + encodedName.Length + 4];
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(0, 2), transactionId);
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(4, 2), 1);
        encodedName.CopyTo(query, 12);
        var offset = 12 + encodedName.Length;
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(offset, 2), TxtRecordType);
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(offset + 2, 2), InternetClass);
        return query;
    }

    internal static string ComputeExpectedTxt(string readyToken)
    {
        DnsFilterTaskDefinitionBuilder.ValidateReadyToken(readyToken);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(HashDomainSeparator);
        hash.AppendData(Convert.FromHexString(readyToken));
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    internal static bool IsExpectedResponse(
        ReadOnlySpan<byte> response,
        ushort transactionId,
        string expectedTxt)
    {
        try
        {
            if (response.Length < 12
                || BinaryPrimitives.ReadUInt16BigEndian(response) != transactionId)
            {
                return false;
            }

            var flags = BinaryPrimitives.ReadUInt16BigEndian(response[2..]);
            if ((flags & 0x8000) == 0
                || (flags & 0x0400) == 0
                || (flags & 0x000F) != 0
                || BinaryPrimitives.ReadUInt16BigEndian(response[4..]) != 1
                || BinaryPrimitives.ReadUInt16BigEndian(response[6..]) != 1
                || BinaryPrimitives.ReadUInt16BigEndian(response[8..]) != 0
                || BinaryPrimitives.ReadUInt16BigEndian(response[10..]) != 0)
            {
                return false;
            }

            var offset = 12;
            if (!string.Equals(ReadName(response, ref offset), SentinelName, StringComparison.OrdinalIgnoreCase)
                || ReadUInt16(response, ref offset) != TxtRecordType
                || ReadUInt16(response, ref offset) != InternetClass
                || !string.Equals(ReadName(response, ref offset), SentinelName, StringComparison.OrdinalIgnoreCase)
                || ReadUInt16(response, ref offset) != TxtRecordType
                || ReadUInt16(response, ref offset) != InternetClass
                || ReadUInt32(response, ref offset) != 0)
            {
                return false;
            }

            var dataLength = ReadUInt16(response, ref offset);
            if (dataLength != 65 || offset + dataLength != response.Length || response[offset] != 64)
            {
                return false;
            }

            var actualTxt = Encoding.ASCII.GetString(response.Slice(offset + 1, 64));
            return string.Equals(actualTxt, expectedTxt, StringComparison.Ordinal);
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }

    private static async Task<bool> BothFamiliesReturnSentinelAsync(
        string expectedTxt,
        CancellationToken cancellationToken)
    {
        foreach (var address in LoopbackAddresses)
        {
            var transactionId = (ushort)RandomNumberGenerator.GetInt32(ushort.MaxValue + 1);
            var query = CreateQuery(transactionId);
            using var client = new UdpClient(address.AddressFamily);
            client.Connect(address, 53);
            using var attempt = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            attempt.CancelAfter(TimeSpan.FromMilliseconds(300));
            try
            {
                _ = await client.SendAsync(query, attempt.Token).ConfigureAwait(false);
                var response = await client.ReceiveAsync(attempt.Token).ConfigureAwait(false);
                if (!response.RemoteEndPoint.Address.Equals(address)
                    || response.RemoteEndPoint.Port != 53
                    || !IsExpectedResponse(response.Buffer, transactionId, expectedTxt))
                {
                    return false;
                }
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return false;
            }
            catch (SocketException)
            {
                return false;
            }
        }

        return true;
    }

    private static byte[] EncodeName(string name)
    {
        var bytes = new List<byte>();
        foreach (var label in name.TrimEnd('.').Split('.'))
        {
            var encoded = Encoding.ASCII.GetBytes(label);
            if (encoded.Length is 0 or > 63)
            {
                throw new InvalidDataException("DNS readiness sentinel label is invalid.");
            }

            bytes.Add((byte)encoded.Length);
            bytes.AddRange(encoded);
        }

        bytes.Add(0);
        return bytes.ToArray();
    }

    private static string ReadName(ReadOnlySpan<byte> message, ref int offset)
    {
        var labels = new List<string>();
        var cursor = offset;
        var jumped = false;
        var visited = new HashSet<int>();
        while (true)
        {
            if ((uint)cursor >= (uint)message.Length || !visited.Add(cursor))
            {
                throw new InvalidDataException("DNS readiness response contains an invalid name.");
            }

            var length = message[cursor];
            if (length == 0)
            {
                if (!jumped)
                {
                    offset = cursor + 1;
                }

                return string.Join('.', labels) + ".";
            }

            if ((length & 0xC0) == 0xC0)
            {
                if (cursor + 1 >= message.Length)
                {
                    throw new InvalidDataException("DNS readiness response has a truncated compression pointer.");
                }

                var pointer = ((length & 0x3F) << 8) | message[cursor + 1];
                if (!jumped)
                {
                    offset = cursor + 2;
                    jumped = true;
                }

                cursor = pointer;
                continue;
            }

            if ((length & 0xC0) != 0 || length > 63 || cursor + 1 + length > message.Length)
            {
                throw new InvalidDataException("DNS readiness response contains an invalid label.");
            }

            labels.Add(Encoding.ASCII.GetString(message.Slice(cursor + 1, length)));
            cursor += 1 + length;
            if (!jumped)
            {
                offset = cursor;
            }
        }
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> value, ref int offset)
    {
        if (offset + 2 > value.Length)
        {
            throw new InvalidDataException("DNS readiness response is truncated.");
        }

        var result = BinaryPrimitives.ReadUInt16BigEndian(value[offset..]);
        offset += 2;
        return result;
    }

    private static uint ReadUInt32(ReadOnlySpan<byte> value, ref int offset)
    {
        if (offset + 4 > value.Length)
        {
            throw new InvalidDataException("DNS readiness response is truncated.");
        }

        var result = BinaryPrimitives.ReadUInt32BigEndian(value[offset..]);
        offset += 4;
        return result;
    }
}
