using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using DistractionFirewall.DnsFilter.DnsProtocol;

namespace DistractionFirewall.DnsFilter.Runtime;

public interface IDnsUpstreamClient
{
    Task<byte[]> QueryAsync(
        byte[] query,
        IPEndPoint upstream,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}

public interface IDnsUpstreamTransport
{
    Task<byte[]> QueryUdpAsync(
        byte[] query,
        IPEndPoint upstream,
        CancellationToken cancellationToken);

    Task<byte[]> QueryTcpAsync(
        byte[] query,
        IPEndPoint upstream,
        CancellationToken cancellationToken);
}

public sealed class DnsUpstreamClient(IDnsUpstreamTransport transport) : IDnsUpstreamClient
{
    public async Task<byte[]> QueryAsync(
        byte[] query,
        IPEndPoint upstream,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(upstream);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(timeout, TimeSpan.Zero);
        if (query.Length < DnsMessageParser.HeaderLength)
        {
            throw new IOException("DNS query is shorter than its header.");
        }

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        var udpResponse = await transport
            .QueryUdpAsync(query, upstream, timeoutSource.Token)
            .ConfigureAwait(false);
        ValidateResponse(query, udpResponse);
        var udpFlags = BinaryPrimitives.ReadUInt16BigEndian(udpResponse.AsSpan(2, 2));
        if ((udpFlags & 0x0200) == 0)
        {
            return udpResponse;
        }

        var tcpResponse = await transport
            .QueryTcpAsync(query, upstream, timeoutSource.Token)
            .ConfigureAwait(false);
        ValidateResponse(query, tcpResponse);
        return tcpResponse;
    }

    private static void ValidateResponse(byte[] query, byte[] response)
    {
        if (response.Length < DnsMessageParser.HeaderLength)
        {
            throw new IOException("Upstream DNS response is shorter than its header.");
        }

        if (!query.AsSpan(0, 2).SequenceEqual(response.AsSpan(0, 2)))
        {
            throw new IOException("Upstream DNS response transaction ID did not match.");
        }
    }
}

public sealed class SocketDnsUpstreamTransport : IDnsUpstreamTransport
{
    public async Task<byte[]> QueryUdpAsync(
        byte[] query,
        IPEndPoint upstream,
        CancellationToken cancellationToken)
    {
        using var client = new UdpClient(upstream.AddressFamily);
        client.Connect(upstream);
        await client.SendAsync(query, cancellationToken).ConfigureAwait(false);
        var result = await client.ReceiveAsync(cancellationToken).ConfigureAwait(false);
        return result.Buffer;
    }

    public async Task<byte[]> QueryTcpAsync(
        byte[] query,
        IPEndPoint upstream,
        CancellationToken cancellationToken)
    {
        using var client = new TcpClient(upstream.AddressFamily);
        await client
            .ConnectAsync(upstream.Address, upstream.Port, cancellationToken)
            .ConfigureAwait(false);
        var stream = client.GetStream();
        await DnsTcpFrameCodec.WriteQueryAsync(stream, query, cancellationToken).ConfigureAwait(false);
        return await DnsTcpFrameCodec.ReadResponseAsync(stream, cancellationToken).ConfigureAwait(false);
    }
}

public static class DnsTcpFrameCodec
{
    public static async Task WriteQueryAsync(
        Stream stream,
        ReadOnlyMemory<byte> query,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (query.Length is < DnsMessageParser.HeaderLength or > ushort.MaxValue)
        {
            throw new IOException("DNS-over-TCP query length is invalid.");
        }

        var lengthPrefix = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(lengthPrefix, checked((ushort)query.Length));
        await stream.WriteAsync(lengthPrefix, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(query, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public static async Task<byte[]> ReadResponseAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var lengthPrefix = new byte[2];
        await stream.ReadExactlyAsync(lengthPrefix, cancellationToken).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadUInt16BigEndian(lengthPrefix);
        if (length < DnsMessageParser.HeaderLength)
        {
            throw new IOException("DNS-over-TCP response length is shorter than a DNS header.");
        }

        var response = new byte[length];
        await stream.ReadExactlyAsync(response, cancellationToken).ConfigureAwait(false);
        return response;
    }
}
