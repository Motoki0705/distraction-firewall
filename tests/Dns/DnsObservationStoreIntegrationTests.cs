using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Core.Targets;
using DistractionFirewall.DnsFilter.DnsProtocol;
using DistractionFirewall.DnsFilter.Runtime;

namespace DistractionFirewall.DnsFilter.Tests;

public sealed class DnsObservationStoreIntegrationTests
{
    [Fact]
    public async Task Production_adapter_uses_strictest_policy_and_persists_no_query_name()
    {
        using var workspace = new AdapterWorkspace();
        var time = new ManualTimeProvider(ReferenceTime);
        await workspace.WriteCatalogAsync(Target("first", 900), Target("second", 120));
        var adapter = await FileDnsObservationStoreAdapter.CreateAsync(
            workspace.TargetPath,
            workspace.ObservationPath,
            time,
            CancellationToken.None);
        var leaseId = Guid.NewGuid();

        await adapter.AppendAsync(
            new DnsObservationContext(
                leaseId,
                ReferenceTime.AddHours(1),
                workspace.ObservationPath),
            [new DnsObservedAddress(IPAddress.Parse("8.8.8.8"), 3600)],
            CancellationToken.None);

        var coreStore = new FileDnsObservedAddressStore(
            workspace.RootPath,
            workspace.ObservationPath,
            time);
        var active = Assert.Single(await coreStore.ReadActiveAsync(leaseId, CancellationToken.None));
        Assert.Equal(ReferenceTime.AddSeconds(120), active.ExpiresAtUtc);
        var persisted = await File.ReadAllTextAsync(workspace.ObservationPath, CancellationToken.None);
        Assert.DoesNotContain("first.example", persisted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("second.example", persisted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("query", persisted, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Production_adapter_rejects_substituted_store_path()
    {
        using var workspace = new AdapterWorkspace();
        await workspace.WriteCatalogAsync(Target("first", 900));
        var adapter = await FileDnsObservationStoreAdapter.CreateAsync(
            workspace.TargetPath,
            workspace.ObservationPath,
            new ManualTimeProvider(ReferenceTime),
            CancellationToken.None);

        await Assert.ThrowsAsync<InvalidDataException>(() => adapter.AppendAsync(
            new DnsObservationContext(
                Guid.NewGuid(),
                ReferenceTime.AddHours(1),
                Path.Combine(workspace.RootPath, "substituted.json")),
            [new DnsObservedAddress(IPAddress.Parse("8.8.8.8"), 60)],
            CancellationToken.None).AsTask());
    }

    private static readonly DateTimeOffset ReferenceTime =
        new(2030, 1, 2, 3, 4, 5, TimeSpan.Zero);

    private static TargetDefinition Target(string stableId, int ttlSeconds) => new()
    {
        StableId = stableId,
        DisplayName = stableId,
        CatalogVersion = "1.0.0",
        ExactHosts = [$"{stableId}.example"],
        SuffixHosts = [],
        CnameSuffixes = [],
        BrowserUrlPatterns = [$"*://{stableId}.example/*"],
        IpBlockPolicy = new IpBlockPolicyDefinition
        {
            Mode = IpBlockMode.DnsObserved,
            SourceFields = ["exact_hosts"],
            AddressFamilies = ["ipv4", "ipv6"],
            TransportProtocols = ["tcp", "udp"],
            FollowCnameChain = true,
            MaxObservationTtlSeconds = ttlSeconds,
            SharedAddressAction = SharedAddressAction.Block,
        },
        KnownCollateral = [],
        Coverage = ["web"],
    };

    private sealed class ManualTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }

    private sealed class AdapterWorkspace : IDisposable
    {
        private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();

        public AdapterWorkspace()
        {
            RootPath = Path.Combine(
                Path.GetTempPath(),
                "distraction-firewall-dns-adapter-tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(RootPath);
            TargetPath = Path.Combine(RootPath, "target-snapshot.json");
            ObservationPath = Path.Combine(RootPath, "observed-addresses.json");
        }

        public string RootPath { get; }

        public string TargetPath { get; }

        public string ObservationPath { get; }

        public Task WriteCatalogAsync(params TargetDefinition[] targets) => File.WriteAllTextAsync(
            TargetPath,
            JsonSerializer.Serialize(targets, JsonOptions),
            CancellationToken.None);

        public void Dispose()
        {
            var allowedRoot = Path.GetFullPath(Path.Combine(
                Path.GetTempPath(),
                "distraction-firewall-dns-adapter-tests")) + Path.DirectorySeparatorChar;
            var resolved = Path.GetFullPath(RootPath);
            if (!resolved.StartsWith(allowedRoot, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException($"Refusing to delete unexpected path '{resolved}'.");
            }

            if (Directory.Exists(resolved))
            {
                Directory.Delete(resolved, recursive: true);
            }
        }

        private static JsonSerializerOptions CreateJsonOptions()
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
