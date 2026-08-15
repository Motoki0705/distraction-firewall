using DistractionFirewall.Enforcement.Windows.Browser;
using DistractionFirewall.Enforcement.Windows.Mutation;
using DistractionFirewall.Enforcement.Windows.Ownership;

namespace DistractionFirewall.Integration.Windows.Tests;

public sealed class BrowserPolicyEnforcementAdapterTests
{
    [Fact]
    public void LiveStoreUsesRegistry64ForSharedMachinePolicyKeys()
    {
        var store = new WindowsRegistryPolicyStore(WindowsMutationGate.Disabled);

        Assert.Equal(Microsoft.Win32.RegistryView.Registry64, store.View);
    }

    [Fact]
    public async Task ApplyConfiguresAllThreeBrowsersAndRestoreRemovesOnlyOwnedValues()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var registry = new FakeRegistryPolicyStore();
            var adapter = new BrowserPolicyEnforcementAdapter(
                registry,
                new OwnedMutationCoordinator(ledger),
                WindowsMutationGate.CreateForTests());
            var context = TestContextFactory.Create("*://*.youtube.com/*", "*://youtu.be/*");

            var artifact = await adapter.ApplyAsync(context, CancellationToken.None);

            Assert.Equal(12, artifact.OwnedResourceIds.Count);
            Assert.Equal(12, registry.MutationCount);
            Assert.Equal(
                "off",
                RegistryPolicyValueCodec.DecodeString(registry.Read(
                    @"SOFTWARE\Policies\Google\Chrome",
                    "DnsOverHttpsMode")));
            Assert.Equal(
                0,
                RegistryPolicyValueCodec.DecodeDWord(registry.Read(
                    @"SOFTWARE\Policies\Microsoft\Edge",
                    "QuicAllowed")));
            Assert.Equal(
                1,
                RegistryPolicyValueCodec.DecodeDWord(registry.Read(
                    @"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS",
                    "Locked")));
            Assert.True((await adapter.VerifyAsync(context, artifact, CancellationToken.None)).TargetBlocked);

            var restored = await adapter.RestoreAsync(context, artifact, CancellationToken.None);

            Assert.True(restored.Restored);
            Assert.Equal(24, registry.MutationCount);
            Assert.False(registry.Read(
                @"SOFTWARE\Policies\Google\Chrome",
                "DnsOverHttpsMode").Exists);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task IdenticalPreexistingListEntryIsPreservedAndNotOwned()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var registry = new FakeRegistryPolicyStore();
            const string pattern = "*://*.youtube.com/*";
            registry.Seed(
                @"SOFTWARE\Policies\Google\Chrome\URLBlocklist",
                "37",
                RegistryPolicyValueCodec.String(pattern));
            var adapter = new BrowserPolicyEnforcementAdapter(
                registry,
                new OwnedMutationCoordinator(ledger),
                WindowsMutationGate.CreateForTests());
            var context = TestContextFactory.Create(pattern);

            var artifact = await adapter.ApplyAsync(context, CancellationToken.None);
            var restored = await adapter.RestoreAsync(context, artifact, CancellationToken.None);

            Assert.True(restored.Restored);
            Assert.Equal(
                pattern,
                RegistryPolicyValueCodec.DecodeString(registry.Read(
                    @"SOFTWARE\Policies\Google\Chrome\URLBlocklist",
                    "37")));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task ConflictingScalarFailsBeforeAnyMutation()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var registry = new FakeRegistryPolicyStore();
            registry.Seed(
                @"SOFTWARE\Policies\Google\Chrome",
                "DnsOverHttpsMode",
                RegistryPolicyValueCodec.String("secure"));
            var adapter = new BrowserPolicyEnforcementAdapter(
                registry,
                new OwnedMutationCoordinator(ledger),
                WindowsMutationGate.CreateForTests());

            await Assert.ThrowsAsync<OwnershipConflictException>(() => adapter.ApplyAsync(
                TestContextFactory.Create("*://*.youtube.com/*"),
                CancellationToken.None));
            Assert.Equal(0, registry.MutationCount);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task BroadAllowlistFailsBeforeAnyMutation()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var registry = new FakeRegistryPolicyStore();
            registry.Seed(
                @"SOFTWARE\Policies\Microsoft\Edge\URLAllowlist",
                "1",
                RegistryPolicyValueCodec.String("<all_urls>"));
            var adapter = new BrowserPolicyEnforcementAdapter(
                registry,
                new OwnedMutationCoordinator(ledger),
                WindowsMutationGate.CreateForTests());

            await Assert.ThrowsAsync<OwnershipConflictException>(() => adapter.ApplyAsync(
                TestContextFactory.Create("*://*.youtube.com/*"),
                CancellationToken.None));
            Assert.Equal(0, registry.MutationCount);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task DisabledMutationGateCannotTouchPolicyStore()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var registry = new FakeRegistryPolicyStore();
            var adapter = new BrowserPolicyEnforcementAdapter(
                registry,
                new OwnedMutationCoordinator(ledger),
                WindowsMutationGate.Disabled);

            await Assert.ThrowsAsync<InvalidOperationException>(() => adapter.ApplyAsync(
                TestContextFactory.Create("*://*.youtube.com/*"),
                CancellationToken.None));
            Assert.Equal(0, registry.MutationCount);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static string CreateTemporaryDirectory()
    {
        var directory = Path.Combine(Path.GetTempPath(), "DistractionFirewall.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }
}
