namespace DistractionFirewall.DnsFilter.Runtime;

public interface IDnsFilterServer : IAsyncDisposable
{
    void Start();
}

public interface IDnsFilterServerFactory
{
    IDnsFilterServer Create(DnsQueryProcessor processor);
}

public sealed class LoopbackDnsServerFactory(int port = 53) : IDnsFilterServerFactory
{
    private readonly int _port = ValidatePort(port);

    public IDnsFilterServer Create(DnsQueryProcessor processor)
    {
        ArgumentNullException.ThrowIfNull(processor);
        return new LoopbackDnsServer(processor, _port);
    }

    private static int ValidatePort(int port)
    {
        if (port is < System.Net.IPEndPoint.MinPort or > System.Net.IPEndPoint.MaxPort)
        {
            throw new ArgumentOutOfRangeException(nameof(port));
        }

        return port;
    }
}
