using System.Buffers.Binary;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Core.Targets;
using DistractionFirewall.Enforcement.Windows.Dns;
using DistractionFirewall.Runtime.Windows;

namespace DistractionFirewall.LeaseLifecycleTests;

public sealed class DnsObservationRuntimeTests
{
    [Fact]
    public async Task Wfp_source_returns_only_active_addresses_for_the_requested_lease()
    {
        using var workspace = new RuntimeObservationWorkspace();
        var time = new ManualTimeProvider(TestData.Now);
        var store = workspace.CreateObservationStore(time);
        var leaseId = Guid.NewGuid();
        await store.AppendAsync(
            new DnsObservationAppendContext(leaseId, TestData.Now.AddHours(1), 900),
            [new(IPAddress.Parse("8.8.8.8"), 30)],
            CancellationToken.None);
        var source = new WindowsObservedAddressSource(store);
        var context = new EnforcementContext(
            leaseId,
            "rule-hash",
            TestData.Now.AddHours(1),
            [TestData.Target()]);

        Assert.Equal(
            [IPAddress.Parse("8.8.8.8")],
            await source.GetObservedAddressesAsync(context, CancellationToken.None));
        Assert.Empty(await source.GetObservedAddressesAsync(
            context with { LeaseId = Guid.NewGuid() },
            CancellationToken.None));
        time.Advance(TimeSpan.FromSeconds(31));
        Assert.Empty(await source.GetObservedAddressesAsync(context, CancellationToken.None));
    }

    [Fact]
    public async Task Seeder_queries_exact_and_representative_seed_hosts_and_caps_address_ttl()
    {
        using var workspace = new RuntimeObservationWorkspace();
        var time = new ManualTimeProvider(TestData.Now);
        var store = workspace.CreateObservationStore(time);
        await store.EnsureCreatedAsync(CancellationToken.None);
        await workspace.WriteCatalogAsync(ObservedTarget());
        var resolver = new FakeSeedResolver((query, type, _) => type == DnsSeedRecordType.A
            ? new DnsSeedResolution(
                query,
                type,
                [new DnsSeedCnameLink(query, "edge.youtube-ui.l.google.com", 300)],
                [new DnsSeedAddressRecord(
                    "edge.youtube-ui.l.google.com",
                    IPAddress.Parse("8.8.4.4"),
                    1200)])
            : new DnsSeedResolution(query, type, [], []));
        var seeder = new WindowsDnsUpstreamObservationSeeder(store, resolver);
        var leaseId = Guid.NewGuid();

        await seeder.SeedAsync(
            workspace.CreateSeedRequest(leaseId, TestData.Now.AddHours(1)),
            CancellationToken.None);

        Assert.Equal(4, resolver.Calls.Count);
        Assert.Equal(
            ["www.youtube.com", "www.youtube.com", "youtu.be", "youtu.be"],
            resolver.Calls.Select(call => call.QueryName));
        var observed = Assert.Single(await store.ReadActiveAsync(leaseId, CancellationToken.None));
        Assert.Equal(IPAddress.Parse("8.8.4.4"), observed.Address);
        Assert.Equal(TestData.Now.AddSeconds(300), observed.ExpiresAtUtc);
        var persisted = await File.ReadAllTextAsync(workspace.ObservationPath, CancellationToken.None);
        Assert.DoesNotContain("youtu.be", persisted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("youtube", persisted, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Seeder_rejects_unrelated_cname_data_without_persisting_it()
    {
        using var workspace = new RuntimeObservationWorkspace();
        var store = workspace.CreateObservationStore(new ManualTimeProvider(TestData.Now));
        await store.EnsureCreatedAsync(CancellationToken.None);
        await workspace.WriteCatalogAsync(ObservedTarget());
        var resolver = new FakeSeedResolver((query, type, _) => new DnsSeedResolution(
            query,
            type,
            [new DnsSeedCnameLink("unrelated.example", "other.example", 60)],
            []));
        var seeder = new WindowsDnsUpstreamObservationSeeder(store, resolver);
        var leaseId = Guid.NewGuid();

        await Assert.ThrowsAsync<InvalidDataException>(() => seeder.SeedAsync(
            workspace.CreateSeedRequest(leaseId, TestData.Now.AddHours(1)),
            CancellationToken.None));

        Assert.Empty(await store.ReadActiveAsync(leaseId, CancellationToken.None));
    }

    [Fact]
    public async Task Protected_target_snapshot_is_context_exact_and_recovery_rewrites_tampering()
    {
        using var workspace = new RuntimeObservationWorkspace();
        var snapshotStore = new ProtectedLeaseTargetSnapshotStore(
            workspace.RootPath,
            workspace.TargetSnapshotPath);
        snapshotStore.EnsureInactivePlaceholder();
        Assert.Equal("[]", await File.ReadAllTextAsync(
            workspace.TargetSnapshotPath,
            CancellationToken.None));
        var targets = new[]
        {
            TestData.Target("disabled-target"),
            ObservedTarget(),
        };
        var context = new EnforcementContext(
            Guid.NewGuid(),
            TargetCatalog.ComputeDefinitionHash(targets),
            TestData.Now.AddHours(1),
            targets);

        await snapshotStore.WriteAsync(context, CancellationToken.None);
        using (var snapshot = JsonDocument.Parse(await File.ReadAllTextAsync(
                   workspace.TargetSnapshotPath,
                   CancellationToken.None)))
        {
            var serializedTargets = snapshot.RootElement.EnumerateArray().ToArray();
            var disabledPolicy = serializedTargets.Single(target =>
                    target.GetProperty("stable_id").GetString() == "disabled-target")
                .GetProperty("ip_block_policy");
            var observedPolicy = serializedTargets.Single(target =>
                    target.GetProperty("stable_id").GetString() == "youtube")
                .GetProperty("ip_block_policy");

            Assert.Equal(["mode"], disabledPolicy.EnumerateObject().Select(property => property.Name));
            Assert.Equal(
                [
                    "address_families",
                    "follow_cname_chain",
                    "max_observation_ttl_seconds",
                    "mode",
                    "shared_address_action",
                    "source_fields",
                    "transport_protocols",
                ],
                observedPolicy.EnumerateObject()
                    .Select(property => property.Name)
                    .Order(StringComparer.Ordinal));
        }

        var persisted = await TargetCatalog.LoadAsync(
            workspace.TargetSnapshotPath,
            CancellationToken.None);
        Assert.Equal(context.RuleHash, TargetCatalog.ComputeDefinitionHash(persisted.Targets));
        await File.WriteAllTextAsync(workspace.TargetSnapshotPath, "[]", CancellationToken.None);

        await snapshotStore.WriteAsync(context, CancellationToken.None);

        persisted = await TargetCatalog.LoadAsync(workspace.TargetSnapshotPath, CancellationToken.None);
        Assert.Equal(context.RuleHash, TargetCatalog.ComputeDefinitionHash(persisted.Targets));
        await Assert.ThrowsAsync<InvalidDataException>(() => snapshotStore.WriteAsync(
            context with { RuleHash = "substituted" },
            CancellationToken.None));
        await snapshotStore.ClearAsync(CancellationToken.None);
        Assert.Equal("[]", await File.ReadAllTextAsync(
            workspace.TargetSnapshotPath,
            CancellationToken.None));
    }

    [Fact]
    public async Task Explicit_resolver_parses_cname_and_ttl_from_fake_wire_response()
    {
        var resolver = new ExplicitDnsSeedResolver(
            new FakeQueryTransport(CreateCnameResponse),
            TimeSpan.FromSeconds(1));

        var resolution = await resolver.ResolveAsync(
            "youtu.be",
            DnsSeedRecordType.A,
            IPAddress.Parse("1.1.1.1"),
            CancellationToken.None);

        var link = Assert.Single(resolution.CnameChain);
        Assert.Equal("youtu.be", link.Owner);
        Assert.Equal("edge.example", link.CanonicalName);
        Assert.Equal(200u, link.TtlSeconds);
        var address = Assert.Single(resolution.Addresses);
        Assert.Equal("edge.example", address.Owner);
        Assert.Equal(IPAddress.Parse("8.8.8.8"), address.Address);
        Assert.Equal(600u, address.TtlSeconds);
    }

    private sealed class FakeSeedResolver(
        Func<string, DnsSeedRecordType, IPAddress, DnsSeedResolution> resolve) : IExplicitDnsSeedResolver
    {
        private readonly Func<string, DnsSeedRecordType, IPAddress, DnsSeedResolution> _resolve = resolve;

        public List<ResolveCall> Calls { get; } = [];

        public Task<DnsSeedResolution> ResolveAsync(
            string queryName,
            DnsSeedRecordType recordType,
            IPAddress upstream,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls.Add(new ResolveCall(queryName, recordType, upstream));
            return Task.FromResult(_resolve(queryName, recordType, upstream));
        }
    }

    private sealed record ResolveCall(
        string QueryName,
        DnsSeedRecordType RecordType,
        IPAddress Upstream);

    private sealed class FakeQueryTransport(
        Func<ReadOnlyMemory<byte>, byte[]> responseFactory) : IExplicitDnsQueryTransport
    {
        private readonly Func<ReadOnlyMemory<byte>, byte[]> _responseFactory = responseFactory;

        public Task<byte[]> QueryAsync(
            ReadOnlyMemory<byte> query,
            IPAddress upstream,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(_responseFactory(query));
        }
    }

    private static byte[] CreateCnameResponse(ReadOnlyMemory<byte> query)
    {
        using var stream = new MemoryStream();
        Span<byte> header = stackalloc byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(
            header,
            BinaryPrimitives.ReadUInt16BigEndian(query.Span));
        BinaryPrimitives.WriteUInt16BigEndian(header[2..], 0x8180);
        BinaryPrimitives.WriteUInt16BigEndian(header[4..], 1);
        BinaryPrimitives.WriteUInt16BigEndian(header[6..], 2);
        stream.Write(header);
        stream.Write(query.Span[12..]);

        stream.Write([0xc0, 0x0c]);
        WriteRecordHeader(stream, type: 5, ttl: 200, dataLength: 14);
        WriteName(stream, "edge.example");
        WriteName(stream, "edge.example");
        WriteRecordHeader(stream, type: 1, ttl: 600, dataLength: 4);
        stream.Write([8, 8, 8, 8]);
        return stream.ToArray();
    }

    private static void WriteRecordHeader(
        Stream stream,
        ushort type,
        uint ttl,
        ushort dataLength)
    {
        Span<byte> header = stackalloc byte[10];
        BinaryPrimitives.WriteUInt16BigEndian(header, type);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..], 1);
        BinaryPrimitives.WriteUInt32BigEndian(header[4..], ttl);
        BinaryPrimitives.WriteUInt16BigEndian(header[8..], dataLength);
        stream.Write(header);
    }

    private static void WriteName(Stream stream, string name)
    {
        foreach (var label in name.Split('.'))
        {
            stream.WriteByte((byte)label.Length);
            stream.Write(System.Text.Encoding.ASCII.GetBytes(label));
        }

        stream.WriteByte(0);
    }

    private static TargetDefinition ObservedTarget() => TestData.Target() with
    {
        SeedHosts = ["www.youtube.com"],
        IpBlockPolicy = new IpBlockPolicyDefinition
        {
            Mode = IpBlockMode.DnsObserved,
            SourceFields = ["exact_hosts", "seed_hosts"],
            AddressFamilies = ["ipv4", "ipv6"],
            TransportProtocols = ["tcp", "udp"],
            FollowCnameChain = true,
            MaxObservationTtlSeconds = 900,
            SharedAddressAction = SharedAddressAction.Block,
        },
    };

    private sealed class ManualTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = utcNow;

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan duration) => _utcNow = _utcNow.Add(duration);
    }

    private sealed class RuntimeObservationWorkspace : IDisposable
    {
        private static readonly JsonSerializerOptions CatalogSerializerOptions = CreateCatalogOptions();

        public RuntimeObservationWorkspace()
        {
            RootPath = Path.Combine(
                Path.GetTempPath(),
                "distraction-firewall-runtime-observation-tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(RootPath);
            ObservationPath = Path.Combine(RootPath, "observed-addresses.json");
            TargetSnapshotPath = Path.Combine(RootPath, "target-snapshot.json");
        }

        public string RootPath { get; }

        public string ObservationPath { get; }

        public string TargetSnapshotPath { get; }

        public FileDnsObservedAddressStore CreateObservationStore(TimeProvider timeProvider) =>
            new(RootPath, ObservationPath, timeProvider);

        public WindowsDnsObservationSeedRequest CreateSeedRequest(
            Guid leaseId,
            DateTimeOffset expiresAtUtc) => new(
            leaseId,
            expiresAtUtc,
            TargetSnapshotPath,
            ObservationPath,
            [new WindowsDnsUpstreamServerSet(
                Guid.NewGuid(),
                "ipv4",
                ["1.1.1.1"])]);

        public Task WriteCatalogAsync(params TargetDefinition[] targets) => File.WriteAllTextAsync(
            TargetSnapshotPath,
            JsonSerializer.Serialize(targets, CatalogSerializerOptions),
            CancellationToken.None);

        public void Dispose()
        {
            var allowedRoot = Path.GetFullPath(Path.Combine(
                Path.GetTempPath(),
                "distraction-firewall-runtime-observation-tests")) + Path.DirectorySeparatorChar;
            var resolved = Path.GetFullPath(RootPath);
            if (!resolved.StartsWith(allowedRoot, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException($"Refusing to remove unexpected path '{resolved}'.");
            }

            if (Directory.Exists(resolved))
            {
                Directory.Delete(resolved, recursive: true);
            }
        }

        private static JsonSerializerOptions CreateCatalogOptions()
        {
            var options = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            };
            options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower));
            return options;
        }
    }
}
