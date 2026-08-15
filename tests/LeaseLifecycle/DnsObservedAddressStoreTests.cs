using System.Net;
using System.Text.Json;
using DistractionFirewall.Core.Enforcement;

namespace DistractionFirewall.LeaseLifecycleTests;

public sealed class DnsObservedAddressStoreTests
{
    [Fact]
    public async Task Append_normalizes_merges_caps_and_prunes_without_names()
    {
        using var workspace = new ObservationWorkspace();
        var time = new ManualTimeProvider(TestData.Now);
        var store = workspace.CreateStore(time);
        var leaseId = Guid.NewGuid();
        var context = new DnsObservationAppendContext(
            leaseId,
            TestData.Now.AddHours(1),
            MaximumTtlSeconds: 900);

        await store.AppendAsync(
            context,
            [
                new(IPAddress.Parse("8.8.8.8"), 1800),
                new(IPAddress.Parse("::ffff:1.1.1.1"), 30),
                new(IPAddress.Parse("1.1.1.1"), 60),
            ],
            CancellationToken.None);

        var active = await store.ReadActiveAsync(leaseId, CancellationToken.None);
        Assert.Equal(2, active.Count);
        Assert.Equal(TestData.Now.AddSeconds(60),
            Assert.Single(active, item => item.Address.Equals(IPAddress.Parse("1.1.1.1"))).ExpiresAtUtc);
        Assert.Equal(TestData.Now.AddSeconds(900),
            Assert.Single(active, item => item.Address.Equals(IPAddress.Parse("8.8.8.8"))).ExpiresAtUtc);
        Assert.Equal(2, active.Select(item => item.Sequence).Distinct().Count());

        var json = await File.ReadAllTextAsync(workspace.StorePath, CancellationToken.None);
        Assert.DoesNotContain("hostname", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("query", json, StringComparison.OrdinalIgnoreCase);
        using (var document = JsonDocument.Parse(json))
        {
            Assert.Equal(1, document.RootElement.GetProperty("schema_version").GetInt32());
            var observations = document.RootElement.GetProperty("observations").EnumerateArray().ToArray();
            Assert.All(observations, observation => Assert.Equal(
                ["address", "expires_at_utc", "lease_id", "sequence"],
                observation.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal)));
        }

        time.Advance(TimeSpan.FromSeconds(61));
        Assert.Equal(
            IPAddress.Parse("8.8.8.8"),
            Assert.Single(await store.ReadActiveAsync(leaseId, CancellationToken.None)).Address);
        time.Advance(TimeSpan.FromSeconds(840));
        Assert.Empty(await store.ReadActiveAsync(leaseId, CancellationToken.None));
    }

    [Theory]
    [InlineData("0.1.2.3")]
    [InlineData("10.0.0.1")]
    [InlineData("100.64.0.1")]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.1.1")]
    [InlineData("172.16.0.1")]
    [InlineData("192.0.2.1")]
    [InlineData("192.168.0.1")]
    [InlineData("198.18.0.1")]
    [InlineData("198.51.100.1")]
    [InlineData("203.0.113.1")]
    [InlineData("224.0.0.1")]
    [InlineData("255.255.255.255")]
    [InlineData("::")]
    [InlineData("::1")]
    [InlineData("::ffff:192.168.1.1")]
    [InlineData("100::1")]
    [InlineData("2001:db8::1")]
    [InlineData("3fff::1")]
    [InlineData("fc00::1")]
    [InlineData("fe80::1")]
    [InlineData("ff02::1")]
    public void Non_public_addresses_are_rejected(string text)
    {
        Assert.Throws<ArgumentException>(() =>
            FileDnsObservedAddressStore.NormalizePublicAddress(IPAddress.Parse(text)));
    }

    [Theory]
    [InlineData("1.1.1.1", "1.1.1.1")]
    [InlineData("::ffff:8.8.8.8", "8.8.8.8")]
    [InlineData("2606:4700:4700::1111", "2606:4700:4700::1111")]
    [InlineData("64:ff9b::0808:0808", "64:ff9b::808:808")]
    public void Public_addresses_are_accepted_and_mapped_addresses_are_normalized(
        string text,
        string expected)
    {
        Assert.Equal(
            IPAddress.Parse(expected),
            FileDnsObservedAddressStore.NormalizePublicAddress(IPAddress.Parse(text)));
    }

    [Fact]
    public async Task Separate_store_instances_serialize_concurrent_appends()
    {
        using var workspace = new ObservationWorkspace();
        var time = new ManualTimeProvider(TestData.Now);
        var first = workspace.CreateStore(time);
        var second = workspace.CreateStore(time);
        var leaseId = Guid.NewGuid();
        var context = new DnsObservationAppendContext(
            leaseId,
            TestData.Now.AddHours(1),
            MaximumTtlSeconds: 900);

        var writes = Enumerable.Range(1, 24).Select(index =>
        {
            var store = index % 2 == 0 ? first : second;
            return store.AppendAsync(
                context,
                [new DnsObservedAddressCandidate(IPAddress.Parse($"8.8.0.{index}"), 120)],
                CancellationToken.None).AsTask();
        });
        await Task.WhenAll(writes);

        Assert.Equal(24, (await first.ReadActiveAsync(leaseId, CancellationToken.None)).Count);
    }

    [Fact]
    public async Task Lease_deadline_caps_ttl_and_oversized_append_is_rejected()
    {
        using var workspace = new ObservationWorkspace();
        var time = new ManualTimeProvider(TestData.Now);
        var store = workspace.CreateStore(time);
        var leaseId = Guid.NewGuid();
        await store.AppendAsync(
            new DnsObservationAppendContext(
                leaseId,
                TestData.Now.AddSeconds(15),
                MaximumTtlSeconds: 900),
            [new(IPAddress.Parse("8.8.8.8"), 600)],
            CancellationToken.None);

        Assert.Equal(
            TestData.Now.AddSeconds(15),
            Assert.Single(await store.ReadActiveAsync(leaseId, CancellationToken.None)).ExpiresAtUtc);
        var oversized = Enumerable.Range(0, FileDnsObservedAddressStore.MaximumObservationCount + 1)
            .Select(_ => new DnsObservedAddressCandidate(IPAddress.Parse("8.8.4.4"), 60))
            .ToArray();
        await Assert.ThrowsAsync<ArgumentException>(() => store.AppendAsync(
            new DnsObservationAppendContext(
                leaseId,
                TestData.Now.AddHours(1),
                MaximumTtlSeconds: 900),
            oversized,
            CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task Unknown_schema_fields_and_path_escape_are_rejected()
    {
        using var workspace = new ObservationWorkspace();
        Assert.Throws<ArgumentException>(() => new FileDnsObservedAddressStore(
            workspace.RootPath,
            Path.Combine(workspace.RootPath, "..", "escaped.json")));
        await File.WriteAllTextAsync(
            workspace.StorePath,
            """
            { "schema_version": 1, "observations": [], "query_name": "forbidden.example" }
            """,
            CancellationToken.None);
        var store = workspace.CreateStore(new ManualTimeProvider(TestData.Now));

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            store.ReadActiveAsync(Guid.NewGuid(), CancellationToken.None).AsTask());
    }

    private sealed class ManualTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = utcNow;

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan duration) => _utcNow = _utcNow.Add(duration);
    }

    private sealed class ObservationWorkspace : IDisposable
    {
        public ObservationWorkspace()
        {
            RootPath = Path.Combine(
                Path.GetTempPath(),
                "distraction-firewall-observation-tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(RootPath);
            StorePath = Path.Combine(RootPath, "observed-addresses.json");
        }

        public string RootPath { get; }

        public string StorePath { get; }

        public FileDnsObservedAddressStore CreateStore(TimeProvider timeProvider) =>
            new(RootPath, StorePath, timeProvider);

        public void Dispose()
        {
            var allowedRoot = Path.GetFullPath(Path.Combine(
                Path.GetTempPath(),
                "distraction-firewall-observation-tests")) + Path.DirectorySeparatorChar;
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
    }
}
