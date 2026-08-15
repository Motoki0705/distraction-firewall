using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Core.Targets;
using DistractionFirewall.Enforcement.Windows.Dns;
using DistractionFirewall.Enforcement.Windows.Wfp;

namespace DistractionFirewall.Runtime.Windows;

public sealed class WindowsObservedAddressSource(
    IDnsObservedAddressStore store) : IWindowsObservedAddressSource
{
    private readonly IDnsObservedAddressStore _store =
        store ?? throw new ArgumentNullException(nameof(store));

    public async ValueTask<IReadOnlyCollection<IPAddress>> GetObservedAddressesAsync(
        EnforcementContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var active = await _store.ReadActiveAsync(context.LeaseId, cancellationToken)
            .ConfigureAwait(false);
        return active.Select(item => item.Address).Distinct().ToArray();
    }
}

public enum DnsSeedRecordType : ushort
{
    A = 1,
    Aaaa = 28,
}

public sealed record DnsSeedCnameLink(
    string Owner,
    string CanonicalName,
    uint TtlSeconds);

public sealed record DnsSeedAddressRecord(
    string Owner,
    IPAddress Address,
    uint TtlSeconds);

public sealed record DnsSeedResolution(
    string QueryName,
    DnsSeedRecordType RecordType,
    IReadOnlyList<DnsSeedCnameLink> CnameChain,
    IReadOnlyList<DnsSeedAddressRecord> Addresses);

public interface IExplicitDnsSeedResolver
{
    Task<DnsSeedResolution> ResolveAsync(
        string queryName,
        DnsSeedRecordType recordType,
        IPAddress upstream,
        CancellationToken cancellationToken);
}

public interface IExplicitDnsQueryTransport
{
    Task<byte[]> QueryAsync(
        ReadOnlyMemory<byte> query,
        IPAddress upstream,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}

public sealed class WindowsDnsUpstreamObservationSeeder : IWindowsDnsUpstreamObservationSeeder
{
    private const int MaximumCnameDepth = 16;
    private readonly FileDnsObservedAddressStore _store;
    private readonly IExplicitDnsSeedResolver _resolver;

    public WindowsDnsUpstreamObservationSeeder(
        FileDnsObservedAddressStore store,
        IExplicitDnsSeedResolver resolver)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
    }

    public async Task SeedAsync(
        WindowsDnsObservationSeedRequest request,
        CancellationToken cancellationToken)
    {
        ValidateRequest(request);
        var catalog = await TargetCatalog.LoadAsync(
            request.TargetSnapshotPath,
            cancellationToken).ConfigureAwait(false);
        var upstreams = NormalizeUpstreams(request.UpstreamServers);
        if (upstreams.Length == 0)
        {
            throw new InvalidDataException("No explicit non-loopback DNS upstream is available for observation seeding.");
        }

        var plans = CreatePlans(catalog);
        foreach (var plan in plans)
        {
            var resolution = await ResolveWithFallbackAsync(
                plan,
                upstreams,
                cancellationToken).ConfigureAwait(false);
            var candidates = ValidateResolution(plan, resolution);
            await _store.AppendAsync(
                new DnsObservationAppendContext(
                    request.LeaseId,
                    request.ExpiresAtUtc,
                    plan.MaximumTtlSeconds),
                candidates,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private void ValidateRequest(WindowsDnsObservationSeedRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.LeaseId == Guid.Empty || request.ExpiresAtUtc == default ||
            string.IsNullOrWhiteSpace(request.TargetSnapshotPath) ||
            string.IsNullOrWhiteSpace(request.ObservationStorePath) ||
            request.UpstreamServers is null)
        {
            throw new ArgumentException("The DNS observation seed request is invalid.", nameof(request));
        }

        if (!PathsEqual(Path.GetFullPath(request.ObservationStorePath), _store.StorePath))
        {
            throw new InvalidDataException("The DNS observation seed request substituted the protected store path.");
        }
    }

    private async Task<DnsSeedResolution> ResolveWithFallbackAsync(
        QueryPlan plan,
        IReadOnlyList<IPAddress> upstreams,
        CancellationToken cancellationToken)
    {
        Exception? lastFailure = null;
        foreach (var upstream in upstreams)
        {
            try
            {
                return await _resolver.ResolveAsync(
                    plan.Host,
                    plan.RecordType,
                    upstream,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (
                exception is IOException or SocketException or InvalidDataException or TimeoutException)
            {
                lastFailure = exception;
            }
        }

        throw new IOException(
            "Every explicit DNS upstream failed during protected observation seeding.",
            lastFailure);
    }

    private static List<DnsObservedAddressCandidate> ValidateResolution(
        QueryPlan plan,
        DnsSeedResolution resolution)
    {
        ArgumentNullException.ThrowIfNull(resolution);
        var queryName = CanonicalizeHost(resolution.QueryName);
        if (!string.Equals(queryName, plan.Host, StringComparison.Ordinal) ||
            resolution.RecordType != plan.RecordType ||
            resolution.CnameChain is null || resolution.Addresses is null ||
            resolution.CnameChain.Count > MaximumCnameDepth)
        {
            throw new InvalidDataException("An explicit DNS seed response did not match its request.");
        }

        if (!plan.FollowCnameChain && resolution.CnameChain.Count != 0)
        {
            throw new InvalidDataException("A DNS seed response used a disallowed CNAME chain.");
        }

        var links = new Dictionary<string, DnsSeedCnameLink>(StringComparer.Ordinal);
        foreach (var link in resolution.CnameChain)
        {
            ArgumentNullException.ThrowIfNull(link);
            var owner = CanonicalizeHost(link.Owner);
            var canonicalName = CanonicalizeHost(link.CanonicalName);
            if (!links.TryAdd(
                    owner,
                    link with { Owner = owner, CanonicalName = canonicalName }))
            {
                throw new InvalidDataException("A DNS seed response contains an invalid CNAME chain.");
            }
        }

        var current = queryName;
        var minimumCnameTtl = uint.MaxValue;
        var visited = new HashSet<string>(StringComparer.Ordinal) { current };
        var traversed = 0;
        while (links.TryGetValue(current, out var link))
        {
            traversed++;
            minimumCnameTtl = Math.Min(minimumCnameTtl, link.TtlSeconds);
            current = link.CanonicalName;
            if (!visited.Add(current) || traversed > MaximumCnameDepth)
            {
                throw new InvalidDataException("A DNS seed response contains a CNAME loop.");
            }
        }

        if (traversed != links.Count)
        {
            throw new InvalidDataException("A DNS seed response contains an unrelated CNAME link.");
        }

        var candidates = new List<DnsObservedAddressCandidate>(resolution.Addresses.Count);
        foreach (var record in resolution.Addresses)
        {
            ArgumentNullException.ThrowIfNull(record);
            if (!string.Equals(CanonicalizeHost(record.Owner), current, StringComparison.Ordinal) ||
                plan.RecordType == DnsSeedRecordType.A &&
                    record.Address.AddressFamily != AddressFamily.InterNetwork ||
                plan.RecordType == DnsSeedRecordType.Aaaa &&
                    record.Address.AddressFamily != AddressFamily.InterNetworkV6)
            {
                throw new InvalidDataException("A DNS seed response contains an unrelated address record.");
            }

            var effectiveTtl = minimumCnameTtl == uint.MaxValue
                ? record.TtlSeconds
                : Math.Min(record.TtlSeconds, minimumCnameTtl);
            candidates.Add(new DnsObservedAddressCandidate(record.Address, effectiveTtl));
        }

        return candidates;
    }

    private static QueryPlan[] CreatePlans(TargetCatalog catalog)
    {
        return catalog.Targets
            .Where(target => target.IpBlockPolicy.Mode == IpBlockMode.DnsObserved)
            .SelectMany(target => GetSeedQueryHosts(target).SelectMany(host =>
                target.IpBlockPolicy.AddressFamilies.Select(family => new QueryPlan(
                    CanonicalizeHost(host),
                    string.Equals(family, "ipv4", StringComparison.Ordinal)
                        ? DnsSeedRecordType.A
                        : DnsSeedRecordType.Aaaa,
                    target.IpBlockPolicy.MaxObservationTtlSeconds,
                    target.IpBlockPolicy.FollowCnameChain))))
            .Distinct()
            .OrderBy(plan => plan.Host, StringComparer.Ordinal)
            .ThenBy(plan => plan.RecordType)
            .ThenBy(plan => plan.MaximumTtlSeconds)
            .ToArray();
    }

    private static IEnumerable<string> GetSeedQueryHosts(TargetDefinition target)
    {
        if (target.IpBlockPolicy.SourceFields.Contains("exact_hosts", StringComparer.Ordinal))
        {
            foreach (var host in target.ExactHosts)
            {
                yield return host;
            }
        }

        if (target.IpBlockPolicy.SourceFields.Contains("seed_hosts", StringComparer.Ordinal))
        {
            foreach (var host in target.SeedHosts)
            {
                yield return host;
            }
        }
    }

    private static IPAddress[] NormalizeUpstreams(
        IReadOnlyList<WindowsDnsUpstreamServerSet> serverSets)
    {
        var upstreams = new Dictionary<string, IPAddress>(StringComparer.OrdinalIgnoreCase);
        foreach (var serverSet in serverSets)
        {
            ArgumentNullException.ThrowIfNull(serverSet);
            var expectedFamily = serverSet.AddressFamily switch
            {
                "ipv4" => AddressFamily.InterNetwork,
                "ipv6" => AddressFamily.InterNetworkV6,
                _ => throw new InvalidDataException("A DNS upstream has an invalid address-family marker."),
            };
            foreach (var text in serverSet.NameServers)
            {
                if (!IPAddress.TryParse(text, out var address) ||
                    address.AddressFamily != expectedFamily ||
                    IPAddress.IsLoopback(address) ||
                    address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) ||
                    address.IsIPv6Multicast)
                {
                    throw new InvalidDataException("A DNS upstream address is invalid.");
                }

                upstreams[address.ToString()] = address;
            }
        }

        return upstreams.Values
            .OrderBy(address => address.AddressFamily)
            .ThenBy(address => address.ToString(), StringComparer.Ordinal)
            .ToArray();
    }

    internal static string CanonicalizeHost(string host)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        var canonical = host.TrimEnd('.').ToLowerInvariant();
        if (canonical.Length is < 1 or > 253)
        {
            throw new InvalidDataException("A DNS name has an invalid length.");
        }

        foreach (var label in canonical.Split('.'))
        {
            if (label.Length is < 1 or > 63 || label[0] == '-' || label[^1] == '-' ||
                label.Any(character =>
                    character is not (>= 'a' and <= 'z') and
                    not (>= '0' and <= '9') and
                    not '-'))
            {
                throw new InvalidDataException("A DNS name contains an invalid label.");
            }
        }

        return canonical;
    }

    private static bool PathsEqual(string left, string right) => string.Equals(
        left,
        right,
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    private sealed record QueryPlan(
        string Host,
        DnsSeedRecordType RecordType,
        int MaximumTtlSeconds,
        bool FollowCnameChain);
}

public sealed class ExplicitDnsSeedResolver(
    IExplicitDnsQueryTransport transport,
    TimeSpan? timeout = null) : IExplicitDnsSeedResolver
{
    private readonly IExplicitDnsQueryTransport _transport =
        transport ?? throw new ArgumentNullException(nameof(transport));
    private readonly TimeSpan _timeout = ValidateTimeout(timeout ?? TimeSpan.FromSeconds(3));

    public async Task<DnsSeedResolution> ResolveAsync(
        string queryName,
        DnsSeedRecordType recordType,
        IPAddress upstream,
        CancellationToken cancellationToken)
    {
        var canonicalName = WindowsDnsUpstreamObservationSeeder.CanonicalizeHost(queryName);
        ArgumentNullException.ThrowIfNull(upstream);
        if (recordType is not (DnsSeedRecordType.A or DnsSeedRecordType.Aaaa))
        {
            throw new ArgumentOutOfRangeException(nameof(recordType));
        }

        var queryId = (ushort)RandomNumberGenerator.GetInt32(ushort.MaxValue + 1);
        var query = BuildQuery(queryId, canonicalName, recordType);
        var response = await _transport.QueryAsync(
            query,
            upstream,
            _timeout,
            cancellationToken).ConfigureAwait(false);
        return ParseResponse(response, queryId, canonicalName, recordType);
    }

    private static byte[] BuildQuery(ushort queryId, string queryName, DnsSeedRecordType recordType)
    {
        using var stream = new MemoryStream(capacity: 512);
        Span<byte> header = stackalloc byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(header, queryId);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..], 0x0100);
        BinaryPrimitives.WriteUInt16BigEndian(header[4..], 1);
        stream.Write(header);
        foreach (var label in queryName.Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            stream.WriteByte((byte)bytes.Length);
            stream.Write(bytes);
        }

        stream.WriteByte(0);
        Span<byte> question = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(question, (ushort)recordType);
        BinaryPrimitives.WriteUInt16BigEndian(question[2..], 1);
        stream.Write(question);
        return stream.ToArray();
    }

    private static DnsSeedResolution ParseResponse(
        ReadOnlySpan<byte> response,
        ushort queryId,
        string queryName,
        DnsSeedRecordType recordType)
    {
        if (response.Length < 12 || BinaryPrimitives.ReadUInt16BigEndian(response) != queryId)
        {
            throw new InvalidDataException("An explicit DNS response has an invalid header.");
        }

        var flags = BinaryPrimitives.ReadUInt16BigEndian(response[2..]);
        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(response[4..]);
        var answerCount = BinaryPrimitives.ReadUInt16BigEndian(response[6..]);
        if ((flags & 0x8000) == 0 || (flags & 0x7800) != 0 || (flags & 0x000f) != 0 ||
            (flags & 0x0200) != 0 || questionCount != 1)
        {
            throw new InvalidDataException("An explicit DNS response is truncated or unsuccessful.");
        }

        var offset = 12;
        var responseQuestion = ReadName(response, ref offset, response.Length);
        if (offset > response.Length - 4 ||
            !string.Equals(responseQuestion, queryName, StringComparison.Ordinal) ||
            BinaryPrimitives.ReadUInt16BigEndian(response[offset..]) != (ushort)recordType ||
            BinaryPrimitives.ReadUInt16BigEndian(response[(offset + 2)..]) != 1)
        {
            throw new InvalidDataException("An explicit DNS response substituted its question.");
        }

        offset += 4;
        var links = new List<DnsSeedCnameLink>();
        var addresses = new List<DnsSeedAddressRecord>();
        for (var index = 0; index < answerCount; index++)
        {
            var owner = ReadName(response, ref offset, response.Length);
            if (offset > response.Length - 10)
            {
                throw new InvalidDataException("An explicit DNS answer is truncated.");
            }

            var type = BinaryPrimitives.ReadUInt16BigEndian(response[offset..]);
            var recordClass = BinaryPrimitives.ReadUInt16BigEndian(response[(offset + 2)..]);
            var ttl = BinaryPrimitives.ReadUInt32BigEndian(response[(offset + 4)..]);
            var dataLength = BinaryPrimitives.ReadUInt16BigEndian(response[(offset + 8)..]);
            offset += 10;
            var dataEnd = checked(offset + dataLength);
            if (recordClass != 1 || dataEnd > response.Length)
            {
                throw new InvalidDataException("An explicit DNS answer has invalid bounds.");
            }

            if (type == 5)
            {
                var cnameOffset = offset;
                var target = ReadName(response, ref cnameOffset, dataEnd);
                if (cnameOffset != dataEnd)
                {
                    throw new InvalidDataException("An explicit DNS CNAME record is malformed.");
                }

                links.Add(new DnsSeedCnameLink(owner, target, ttl));
            }
            else if (type == (ushort)recordType)
            {
                var expectedLength = recordType == DnsSeedRecordType.A ? 4 : 16;
                if (dataLength != expectedLength)
                {
                    throw new InvalidDataException("An explicit DNS address record is malformed.");
                }

                addresses.Add(new DnsSeedAddressRecord(
                    owner,
                    new IPAddress(response.Slice(offset, dataLength)),
                    ttl));
            }

            offset = dataEnd;
        }

        return new DnsSeedResolution(queryName, recordType, links, addresses);
    }

    private static string ReadName(ReadOnlySpan<byte> message, ref int offset, int encodedEnd)
    {
        var labels = new List<string>();
        var cursor = offset;
        var resumedOffset = -1;
        var visited = new HashSet<int>();
        for (var depth = 0; depth <= 32; depth++)
        {
            var readableEnd = resumedOffset >= 0 ? message.Length : encodedEnd;
            if ((uint)cursor >= (uint)readableEnd)
            {
                throw new InvalidDataException("An explicit DNS name is truncated.");
            }

            var length = message[cursor++];
            if (length == 0)
            {
                offset = resumedOffset >= 0 ? resumedOffset : cursor;
                return WindowsDnsUpstreamObservationSeeder.CanonicalizeHost(string.Join('.', labels));
            }

            if ((length & 0xc0) == 0xc0)
            {
                if (cursor >= readableEnd)
                {
                    throw new InvalidDataException("An explicit DNS compression pointer is truncated.");
                }

                var pointer = ((length & 0x3f) << 8) | message[cursor++];
                if ((uint)pointer >= (uint)message.Length || !visited.Add(pointer))
                {
                    throw new InvalidDataException("An explicit DNS compression pointer is invalid.");
                }

                resumedOffset = resumedOffset >= 0 ? resumedOffset : cursor;
                cursor = pointer;
                continue;
            }

            if ((length & 0xc0) != 0 || length > 63 || cursor > readableEnd - length)
            {
                throw new InvalidDataException("An explicit DNS label is invalid.");
            }

            labels.Add(Encoding.ASCII.GetString(message.Slice(cursor, length)));
            cursor += length;
        }

        throw new InvalidDataException("An explicit DNS name exceeded its compression-depth limit.");
    }

    private static TimeSpan ValidateTimeout(TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(30))
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        return timeout;
    }
}

public sealed class SocketExplicitDnsQueryTransport : IExplicitDnsQueryTransport
{
    private const int MaximumDnsMessageLength = ushort.MaxValue;

    public async Task<byte[]> QueryAsync(
        ReadOnlyMemory<byte> query,
        IPAddress upstream,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(upstream);
        if (query.Length is < 12 or > MaximumDnsMessageLength)
        {
            throw new ArgumentException("The DNS seed query has an invalid length.", nameof(query));
        }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        try
        {
            var response = await QueryUdpAsync(query, upstream, deadline.Token).ConfigureAwait(false);
            var flags = response.Length >= 4
                ? BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2, 2))
                : (ushort)0;
            return (flags & 0x0200) == 0
                ? response
                : await QueryTcpAsync(query, upstream, deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("The explicit DNS upstream timed out.", exception);
        }
    }

    private static async Task<byte[]> QueryUdpAsync(
        ReadOnlyMemory<byte> query,
        IPAddress upstream,
        CancellationToken cancellationToken)
    {
        using var socket = new Socket(upstream.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        await socket.ConnectAsync(new IPEndPoint(upstream, 53), cancellationToken).ConfigureAwait(false);
        _ = await socket.SendAsync(query, SocketFlags.None, cancellationToken).ConfigureAwait(false);
        var buffer = new byte[MaximumDnsMessageLength];
        var received = await socket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken)
            .ConfigureAwait(false);
        return buffer[..received];
    }

    private static async Task<byte[]> QueryTcpAsync(
        ReadOnlyMemory<byte> query,
        IPAddress upstream,
        CancellationToken cancellationToken)
    {
        using var socket = new Socket(upstream.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(new IPEndPoint(upstream, 53), cancellationToken).ConfigureAwait(false);
        await using var stream = new NetworkStream(socket, ownsSocket: false);
        var prefix = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(prefix, checked((ushort)query.Length));
        await stream.WriteAsync(prefix, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(query, cancellationToken).ConfigureAwait(false);
        await stream.ReadExactlyAsync(prefix, cancellationToken).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadUInt16BigEndian(prefix);
        if (length < 12)
        {
            throw new InvalidDataException("The explicit DNS TCP response has an invalid length.");
        }

        var response = new byte[length];
        await stream.ReadExactlyAsync(response, cancellationToken).ConfigureAwait(false);
        return response;
    }
}
