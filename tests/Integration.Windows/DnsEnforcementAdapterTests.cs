using System.Text.Json;
using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Enforcement.Windows.Dns;
using DistractionFirewall.Enforcement.Windows.Mutation;
using DistractionFirewall.Enforcement.Windows.Ownership;

namespace DistractionFirewall.Integration.Windows.Tests;

public sealed class DnsEnforcementAdapterTests
{
    private static readonly Guid PrimaryInterfaceId =
        Guid.Parse("79439f70-bfad-440d-891e-1c28da49da0d");

    [Fact]
    public async Task ApplyWaitsForReadyAndUpstreamSeedBeforeAnyLoopbackWriteThenRestores()
    {
        using var fixture = new DnsAdapterFixture();
        var ipv4Resource = fixture.DnsStore.Seed(CreateStatic(
            PrimaryInterfaceId,
            DnsAddressFamily.IPv4,
            "1.1.1.1",
            "8.8.8.8"));
        var ipv6Resource = fixture.DnsStore.Seed(CreateStatic(
            PrimaryInterfaceId,
            DnsAddressFamily.IPv6,
            "2606:4700:4700::1111"));

        var artifact = await fixture.Adapter.ApplyAsync(TestContextFactory.Create("*://*.youtube.com/*"), CancellationToken.None);

        Assert.Equal(2, artifact.OwnedResourceIds.Count);
        Assert.Equal("127.0.0.1", Assert.Single(fixture.DnsStore.ReadState(ipv4Resource).NameServers));
        Assert.Equal("::1", Assert.Single(fixture.DnsStore.ReadState(ipv6Resource).NameServers));
        Assert.Equal(2, Assert.Single(fixture.Seeder.Requests).UpstreamServers.Count);
        var launch = Assert.Single(fixture.Launcher.Requests);
        Assert.Equal(["1.1.1.1", "2606:4700:4700::1111", "8.8.8.8"], launch.UpstreamNameServers);
        Assert.Equal(64, launch.ReadyToken.Length);
        Assert.Equal(launch.ReadyToken, Assert.Single(fixture.ReadyProbe.Requests).ReadyToken);
        AssertOrdered(
            fixture.Events,
            "dns:enumerate",
            "launcher:start",
            "probe:ready",
            "dns:enumerate",
            "seed:upstream",
            "dns:write:");

        var restored = await fixture.Adapter.RestoreAsync(
            TestContextFactory.Create("*://*.youtube.com/*"),
            artifact,
            CancellationToken.None);

        Assert.True(restored.Restored);
        Assert.Equal(["1.1.1.1", "8.8.8.8"], fixture.DnsStore.ReadState(ipv4Resource).NameServers);
        Assert.Equal("2606:4700:4700::1111", Assert.Single(fixture.DnsStore.ReadState(ipv6Resource).NameServers));
    }

    [Fact]
    public async Task ReadinessFailureLeavesEveryDnsSettingUntouched()
    {
        using var fixture = new DnsAdapterFixture();
        var resourceId = fixture.DnsStore.Seed(CreateStatic(
            PrimaryInterfaceId,
            DnsAddressFamily.IPv4,
            "1.1.1.1"));
        fixture.ReadyProbe.ThrowTimeout = true;

        await Assert.ThrowsAsync<TimeoutException>(() => fixture.Adapter.ApplyAsync(
            TestContextFactory.Create(),
            CancellationToken.None));

        Assert.Equal(0, fixture.DnsStore.MutationCount);
        Assert.Equal("1.1.1.1", Assert.Single(fixture.DnsStore.ReadState(resourceId).NameServers));
        Assert.Empty(fixture.Seeder.Requests);
    }

    [Fact]
    public async Task ObservationSeedFailureLeavesEveryDnsSettingUntouched()
    {
        using var fixture = new DnsAdapterFixture();
        fixture.DnsStore.Seed(CreateStatic(
            PrimaryInterfaceId,
            DnsAddressFamily.IPv4,
            "1.1.1.1"));
        fixture.Seeder.ThrowOnSeed = true;

        await Assert.ThrowsAsync<IOException>(() => fixture.Adapter.ApplyAsync(
            TestContextFactory.Create(),
            CancellationToken.None));

        Assert.Equal(0, fixture.DnsStore.MutationCount);
        _ = Assert.Single(fixture.Seeder.Requests);
    }

    [Fact]
    public async Task UnknownOriginFailsClosedBeforeFilterLaunch()
    {
        using var fixture = new DnsAdapterFixture();
        fixture.DnsStore.Seed(DnsSettingsCodecTests.CreateState(
            PrimaryInterfaceId,
            DnsAddressFamily.IPv4,
            DnsConfigurationOrigin.Unknown,
            "192.0.2.53"));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Adapter.ApplyAsync(
            TestContextFactory.Create(),
            CancellationToken.None));

        Assert.Contains("fail-closed", exception.Message, StringComparison.Ordinal);
        Assert.Equal(0, fixture.Launcher.StartCount);
        Assert.Equal(0, fixture.DnsStore.MutationCount);
    }

    [Fact]
    public async Task MixedDhcpAndStaticFamiliesApplyVerifyAndRestoreExactOrigins()
    {
        using var fixture = new DnsAdapterFixture();
        var ipv4Resource = fixture.DnsStore.Seed(DnsSettingsCodecTests.CreateState(
            PrimaryInterfaceId,
            DnsAddressFamily.IPv4,
            DnsConfigurationOrigin.Dhcp,
            "192.0.2.53"));
        var ipv6Resource = fixture.DnsStore.Seed(CreateStatic(
            PrimaryInterfaceId,
            DnsAddressFamily.IPv6,
            "2001:db8::53"));
        var context = TestContextFactory.Create();

        var artifact = await fixture.Adapter.ApplyAsync(context, CancellationToken.None);
        var verification = await fixture.Adapter.VerifyAsync(context, artifact, CancellationToken.None);

        Assert.True(verification.TargetBlocked);
        Assert.Equal("127.0.0.1", Assert.Single(fixture.DnsStore.ReadState(ipv4Resource).NameServers));
        Assert.Equal("::1", Assert.Single(fixture.DnsStore.ReadState(ipv6Resource).NameServers));
        Assert.Equal(["192.0.2.53", "2001:db8::53"], Assert.Single(fixture.Launcher.Requests).UpstreamNameServers);

        var restored = await fixture.Adapter.RestoreAsync(context, artifact, CancellationToken.None);

        Assert.True(restored.Restored);
        var ipv4 = fixture.DnsStore.ReadState(ipv4Resource);
        var ipv6 = fixture.DnsStore.ReadState(ipv6Resource);
        Assert.Equal(DnsConfigurationOrigin.Dhcp, ipv4.Origin);
        Assert.Equal("192.0.2.53", Assert.Single(ipv4.NameServers));
        Assert.Equal(DnsConfigurationOrigin.Static, ipv6.Origin);
        Assert.Equal("2001:db8::53", Assert.Single(ipv6.NameServers));
        Assert.Equal("initial-or-new-interface-snapshot-only", artifact.Properties["dhcp_upstream_refresh"]);
    }

    [Fact]
    public async Task DhcpEffectiveResolverChangeBeforeCasIsNotOverwritten()
    {
        using var fixture = new DnsAdapterFixture();
        var resourceId = fixture.DnsStore.Seed(DnsSettingsCodecTests.CreateState(
            PrimaryInterfaceId,
            DnsAddressFamily.IPv4,
            DnsConfigurationOrigin.Dhcp,
            "192.0.2.53"));
        fixture.Seeder.OnSeed = _ => fixture.DnsStore.SetExternal(
            resourceId,
            DnsSettingsCodecTests.CreateState(
                PrimaryInterfaceId,
                DnsAddressFamily.IPv4,
                DnsConfigurationOrigin.Dhcp,
                "192.0.2.54"));

        await Assert.ThrowsAsync<OwnershipConflictException>(() => fixture.Adapter.ApplyAsync(
            TestContextFactory.Create(),
            CancellationToken.None));

        Assert.Equal(0, fixture.DnsStore.MutationCount);
        Assert.Equal("192.0.2.54", Assert.Single(fixture.DnsStore.ReadState(resourceId).NameServers));
    }

    [Fact]
    public async Task DhcpRestoreAcceptsNewLeaseResolverOnlyAfterOwnedLoopbackCas()
    {
        using var fixture = new DnsAdapterFixture();
        var resourceId = fixture.DnsStore.Seed(DnsSettingsCodecTests.CreateState(
            PrimaryInterfaceId,
            DnsAddressFamily.IPv4,
            DnsConfigurationOrigin.Dhcp,
            "192.0.2.53"));
        var context = TestContextFactory.Create();
        var artifact = await fixture.Adapter.ApplyAsync(context, CancellationToken.None);
        fixture.DnsStore.TransformReplacement = replacement =>
            replacement.Origin == DnsConfigurationOrigin.Dhcp
                ? replacement with { NameServers = ["192.0.2.54"] }
                : replacement;

        var restored = await fixture.Adapter.RestoreAsync(context, artifact, CancellationToken.None);

        Assert.True(restored.Restored);
        var current = fixture.DnsStore.ReadState(resourceId);
        Assert.Equal(DnsConfigurationOrigin.Dhcp, current.Origin);
        Assert.Equal("192.0.2.54", Assert.Single(current.NameServers));
    }

    [Fact]
    public async Task AdapterAppearingDuringStartupIsIncludedBeforeFirstMutation()
    {
        using var fixture = new DnsAdapterFixture();
        fixture.DnsStore.Seed(CreateStatic(
            PrimaryInterfaceId,
            DnsAddressFamily.IPv4,
            "1.1.1.1"));
        var newInterfaceId = Guid.Parse("4f6a7cf5-5169-4c58-9e54-7703beef50ab");
        fixture.DnsStore.BeforeEnumeration = count =>
        {
            if (count == 2)
            {
                fixture.DnsStore.Seed(CreateStatic(
                    newInterfaceId,
                    DnsAddressFamily.IPv4,
                    "9.9.9.9"));
            }
        };

        var artifact = await fixture.Adapter.ApplyAsync(TestContextFactory.Create(), CancellationToken.None);

        Assert.Equal(2, artifact.OwnedResourceIds.Count);
        Assert.Equal(2, fixture.DnsStore.MutationCount);
        Assert.Equal(2, Assert.Single(fixture.Seeder.Requests).UpstreamServers.Count);
    }

    [Fact]
    public async Task SnapshotChangeBeforeCasIsNotOverwritten()
    {
        using var fixture = new DnsAdapterFixture();
        var resourceId = fixture.DnsStore.Seed(CreateStatic(
            PrimaryInterfaceId,
            DnsAddressFamily.IPv4,
            "1.1.1.1"));
        fixture.Seeder.OnSeed = _ => fixture.DnsStore.SetExternal(
            resourceId,
            CreateStatic(PrimaryInterfaceId, DnsAddressFamily.IPv4, "9.9.9.9"));

        await Assert.ThrowsAsync<OwnershipConflictException>(() => fixture.Adapter.ApplyAsync(
            TestContextFactory.Create(),
            CancellationToken.None));

        Assert.Equal(0, fixture.DnsStore.MutationCount);
        Assert.Equal("9.9.9.9", Assert.Single(fixture.DnsStore.ReadState(resourceId).NameServers));
    }

    [Fact]
    public async Task ReconcileOwnsNewlyActiveAdapterAndSeedsOnlyItsNonLoopbackUpstream()
    {
        using var fixture = new DnsAdapterFixture();
        fixture.DnsStore.Seed(CreateStatic(
            PrimaryInterfaceId,
            DnsAddressFamily.IPv4,
            "1.1.1.1"));
        var context = TestContextFactory.Create();
        var artifact = await fixture.Adapter.ApplyAsync(context, CancellationToken.None);
        var originalReadyToken = Assert.Single(fixture.Launcher.Requests).ReadyToken;
        fixture.Seeder.Requests.Clear();
        fixture.Launcher.Requests.Clear();
        var newInterfaceId = Guid.Parse("b996e7ac-b0e4-4145-82fb-6572818cc44b");
        var newResource = fixture.DnsStore.Seed(DnsSettingsCodecTests.CreateState(
            newInterfaceId,
            DnsAddressFamily.IPv4,
            DnsConfigurationOrigin.Dhcp,
            "208.67.222.222"));

        var reconciled = await fixture.Adapter.ReconcileAsync(context, artifact, CancellationToken.None);

        Assert.Equal(2, reconciled.OwnedResourceIds.Count);
        Assert.Equal("1", reconciled.Properties["reconcile_generation"]);
        var seeded = Assert.Single(Assert.Single(fixture.Seeder.Requests).UpstreamServers);
        Assert.Equal(newInterfaceId, seeded.InterfaceId);
        Assert.Equal("208.67.222.222", Assert.Single(seeded.NameServers));
        Assert.Equal("127.0.0.1", Assert.Single(fixture.DnsStore.ReadState(newResource).NameServers));
        Assert.All(fixture.Launcher.Requests, request => Assert.Equal(originalReadyToken, request.ReadyToken));
    }

    [Fact]
    public async Task ReconcileRetainsOwnedDhcpSnapshotWithoutInventingFallbackUpstreams()
    {
        using var fixture = new DnsAdapterFixture();
        fixture.DnsStore.Seed(DnsSettingsCodecTests.CreateState(
            PrimaryInterfaceId,
            DnsAddressFamily.IPv4,
            DnsConfigurationOrigin.Dhcp,
            "192.0.2.53"));
        var context = TestContextFactory.Create();
        var artifact = await fixture.Adapter.ApplyAsync(context, CancellationToken.None);
        fixture.Launcher.Requests.Clear();

        var reconciled = await fixture.Adapter.ReconcileAsync(context, artifact, CancellationToken.None);

        Assert.Equal(artifact.OwnedResourceIds, reconciled.OwnedResourceIds);
        Assert.Equal(["192.0.2.53"], Assert.Single(fixture.Launcher.Requests).UpstreamNameServers);
        Assert.DoesNotContain(
            fixture.Launcher.Requests.SelectMany(request => request.UpstreamNameServers),
            address => address is "1.1.1.1" or "8.8.8.8" or "9.9.9.9");
    }

    [Fact]
    public async Task RestorePreservesForeignDnsChangeAndReportsRetryableConflict()
    {
        using var fixture = new DnsAdapterFixture();
        var resourceId = fixture.DnsStore.Seed(CreateStatic(
            PrimaryInterfaceId,
            DnsAddressFamily.IPv4,
            "1.1.1.1"));
        var context = TestContextFactory.Create();
        var artifact = await fixture.Adapter.ApplyAsync(context, CancellationToken.None);
        fixture.DnsStore.SetExternal(
            resourceId,
            CreateStatic(PrimaryInterfaceId, DnsAddressFamily.IPv4, "9.9.9.9"));

        var restored = await fixture.Adapter.RestoreAsync(context, artifact, CancellationToken.None);

        Assert.False(restored.Restored);
        Assert.True(restored.Retryable);
        Assert.Equal("9.9.9.9", Assert.Single(fixture.DnsStore.ReadState(resourceId).NameServers));
    }

    [Fact]
    public async Task ArtifactAndOwnershipLedgerNeverPersistTargetOrQueryNames()
    {
        using var fixture = new DnsAdapterFixture();
        fixture.DnsStore.Seed(CreateStatic(
            PrimaryInterfaceId,
            DnsAddressFamily.IPv4,
            "1.1.1.1"));

        var artifact = await fixture.Adapter.ApplyAsync(
            TestContextFactory.Create("*://*.youtube.com/*"),
            CancellationToken.None);
        var persisted = JsonSerializer.Serialize(artifact) + string.Concat(
            Directory.EnumerateFiles(fixture.LedgerDirectory, "*.json")
                .Select(File.ReadAllText));

        Assert.DoesNotContain("youtube.com", persisted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("youtu.be", persisted, StringComparison.OrdinalIgnoreCase);
    }

    private static DnsInterfaceSettingsState CreateStatic(
        Guid interfaceId,
        DnsAddressFamily family,
        params string[] nameServers)
    {
        return DnsSettingsCodecTests.CreateState(
            interfaceId,
            family,
            DnsConfigurationOrigin.Static,
            nameServers);
    }

    private static void AssertOrdered(List<string> events, params string[] expectedPrefixes)
    {
        var cursor = -1;
        foreach (var prefix in expectedPrefixes)
        {
            cursor = Enumerable.Range(cursor + 1, events.Count - cursor - 1)
                .First(index => events[index].StartsWith(prefix, StringComparison.Ordinal));
        }
    }

    private sealed class DnsAdapterFixture : IDisposable
    {
        private readonly FileOwnershipLedger _ledger;

        public DnsAdapterFixture()
        {
            LedgerDirectory = Path.Combine(
                Path.GetTempPath(),
                "DistractionFirewall.DnsAdapter.Tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(LedgerDirectory);
            _ledger = new FileOwnershipLedger(LedgerDirectory, "dns-test-install");
            var coordinator = new OwnedMutationCoordinator(_ledger);
            DnsStore = new FakeDnsSettingsStore(Events);
            Launcher = new FakeDnsFilterLauncher(Events);
            ReadyProbe = new FakeDnsFilterReadyProbe(Events);
            Seeder = new FakeDnsObservationSeeder(Events);
            Adapter = new WindowsDnsEnforcementAdapter(
                DnsStore,
                Launcher,
                ReadyProbe,
                Seeder,
                coordinator,
                _ledger,
                WindowsMutationGate.CreateForTests(),
                @"C:\ProgramData\DistractionFirewall\targets\active.json",
                @"C:\ProgramData\DistractionFirewall\observations",
                TimeSpan.FromSeconds(1));
        }

        public string LedgerDirectory { get; }

        public List<string> Events { get; } = [];

        public FakeDnsSettingsStore DnsStore { get; }

        public FakeDnsFilterLauncher Launcher { get; }

        public FakeDnsFilterReadyProbe ReadyProbe { get; }

        public FakeDnsObservationSeeder Seeder { get; }

        public WindowsDnsEnforcementAdapter Adapter { get; }

        public void Dispose()
        {
            Adapter.Dispose();
            _ledger.Dispose();
            Directory.Delete(LedgerDirectory, recursive: true);
        }
    }
}
