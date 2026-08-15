using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using DistractionFirewall.DnsFilter.DnsProtocol;

namespace DistractionFirewall.DnsFilter.Runtime;

public sealed class LoopbackDnsServer : IDnsFilterServer
{
    private const int MaximumUdpMessageBytes = 4096;
    private const int MaximumTcpMessageBytes = ushort.MaxValue;
    private readonly DnsQueryProcessor _processor;
    private readonly int _port;
    private readonly List<UdpClient> _udpListeners = [];
    private readonly List<TcpListener> _tcpListeners = [];
    private readonly List<Task> _listenerTasks = [];
    private readonly CancellationTokenSource _shutdown = new();
    private bool _started;

    public LoopbackDnsServer(DnsQueryProcessor processor, int port = 53)
    {
        ArgumentNullException.ThrowIfNull(processor);
        if (port is < IPEndPoint.MinPort or > IPEndPoint.MaxPort)
        {
            throw new ArgumentOutOfRangeException(nameof(port));
        }

        _processor = processor;
        _port = port;
    }

    public void Start()
    {
        ObjectDisposedException.ThrowIf(_shutdown.IsCancellationRequested, this);
        if (_started)
        {
            throw new InvalidOperationException("DNS server has already been started.");
        }

        StartEndpoint(IPAddress.Loopback);
        if (Socket.OSSupportsIPv6)
        {
            StartEndpoint(IPAddress.IPv6Loopback);
        }

        _started = true;
    }

    public async ValueTask DisposeAsync()
    {
        await _shutdown.CancelAsync().ConfigureAwait(false);
        foreach (var listener in _udpListeners)
        {
            listener.Dispose();
        }

        foreach (var listener in _tcpListeners)
        {
            listener.Stop();
        }

        try
        {
            await Task.WhenAll(_listenerTasks).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is OperationCanceledException or SocketException or ObjectDisposedException)
        {
        }

        _shutdown.Dispose();
        GC.SuppressFinalize(this);
    }

    private void StartEndpoint(IPAddress address)
    {
        var endpoint = new IPEndPoint(address, _port);
        var udp = new UdpClient(endpoint);
        _udpListeners.Add(udp);
        _listenerTasks.Add(RunUdpAsync(udp, _shutdown.Token));

        var tcp = new TcpListener(endpoint);
        tcp.Start();
        _tcpListeners.Add(tcp);
        _listenerTasks.Add(RunTcpAsync(tcp, _shutdown.Token));
    }

    private async Task RunUdpAsync(UdpClient listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            UdpReceiveResult request;
            try
            {
                request = await listener.ReceiveAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            if (request.Buffer.Length > MaximumUdpMessageBytes)
            {
                continue;
            }

            _ = RespondUdpAsync(listener, request, cancellationToken);
        }
    }

    private async Task RespondUdpAsync(
        UdpClient listener,
        UdpReceiveResult request,
        CancellationToken cancellationToken)
    {
        try
        {
            var response = await _processor.ProcessAsync(request.Buffer, cancellationToken).ConfigureAwait(false);
            await listener.SendAsync(response, request.RemoteEndPoint, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or SocketException or DnsProtocolException)
        {
            var response = DnsResponseFactory.CreateFormatError(request.Buffer);
            await listener.SendAsync(response, request.RemoteEndPoint, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task RunTcpAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            _ = RespondTcpAsync(client, cancellationToken);
        }
    }

    private async Task RespondTcpAsync(TcpClient client, CancellationToken cancellationToken)
    {
        using (client)
        {
            var stream = client.GetStream();
            var header = new byte[2];
            await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
            var length = BinaryPrimitives.ReadUInt16BigEndian(header);
            if (length is 0 or > MaximumTcpMessageBytes)
            {
                return;
            }

            var query = new byte[length];
            await stream.ReadExactlyAsync(query, cancellationToken).ConfigureAwait(false);
            var response = await _processor.ProcessAsync(query, cancellationToken).ConfigureAwait(false);
            BinaryPrimitives.WriteUInt16BigEndian(header, checked((ushort)response.Length));
            await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
            await stream.WriteAsync(response, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}
