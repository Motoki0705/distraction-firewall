using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Core.Targets;
using DistractionFirewall.Enforcement.Windows;
using DistractionFirewall.Enforcement.Windows.Mutation;
using DistractionFirewall.Enforcement.Windows.Ownership;
using DistractionFirewall.Enforcement.Windows.Wfp;

namespace DistractionFirewall.Integration.Windows.Tests;

public sealed class WfpEnforcementAdapterTests
{
    [Fact]
    public async Task AdapterOwnsAleAndTransportFiltersForBothAddressFamilies()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var policy = new FakeWfpPolicyStore();
            var adapter = new WfpEnforcementAdapter(
                policy,
                ledger,
                new FixedAddressSource("8.8.8.8", "2606:4700:4700::1111"),
                WindowsMutationGate.CreateForTests());
            var context = TestContextFactory.Create("*://*.youtube.com/*");

            var artifact = await adapter.ApplyAsync(context, CancellationToken.None);

            Assert.Equal(4, artifact.OwnedResourceIds.Count);
            Assert.Equal(4, policy.Filters.Count);
            Assert.Contains(policy.Filters, filter => filter.LayerKey == WfpProductConstants.AleAuthConnectV4);
            Assert.Contains(policy.Filters, filter => filter.LayerKey == WfpProductConstants.AleAuthConnectV6);
            Assert.Contains(policy.Filters, filter => filter.LayerKey == WfpProductConstants.OutboundTransportV4);
            Assert.Contains(policy.Filters, filter => filter.LayerKey == WfpProductConstants.OutboundTransportV6);
            Assert.True((await adapter.VerifyAsync(context, artifact, CancellationToken.None)).TargetBlocked);

            var restored = await adapter.RestoreAsync(context, artifact, CancellationToken.None);

            Assert.True(restored.Restored);
            Assert.Empty(policy.Filters);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task RequiredEmptyAddressSourceRejectsApplyBeforeWfpMutation()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var policy = new FakeWfpPolicyStore();
            var adapter = new WfpEnforcementAdapter(
                policy,
                ledger,
                new MutableAddressSource(),
                WindowsMutationGate.CreateForTests());
            var context = TestContextFactory.Create("*://*.youtube.com/*");

            var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                adapter.ApplyAsync(context, CancellationToken.None));

            Assert.Contains("no TTL-valid public", exception.Message, StringComparison.Ordinal);
            Assert.Empty(policy.Filters);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task EmptyAddressSourceIsPendingRatherThanBlocked()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var adapter = new WfpEnforcementAdapter(
                new FakeWfpPolicyStore(),
                ledger,
                new MutableAddressSource(),
                WindowsMutationGate.CreateForTests());
            var context = TestContextFactory.Create(
                SharedAddressAction.Observe,
                "*://*.youtube.com/*");

            var artifact = await adapter.ApplyAsync(context, CancellationToken.None);
            var verification = await adapter.VerifyAsync(context, artifact, CancellationToken.None);

            Assert.Empty(artifact.OwnedResourceIds);
            Assert.False(verification.TargetBlocked);
            Assert.True(verification.GeneralConnectivityAvailable);
            Assert.StartsWith("Pending observations:", verification.Summary, StringComparison.Ordinal);
            Assert.True(adapter.IsPending(artifact, verification));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task ReconcileAddsCurrentAddressesAndRemovesExpiredOwnedFilters()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var policy = new FakeWfpPolicyStore();
            var addresses = new MutableAddressSource("8.8.8.8");
            var adapter = new WfpEnforcementAdapter(
                policy,
                ledger,
                addresses,
                WindowsMutationGate.CreateForTests());
            var context = TestContextFactory.Create("*://*.youtube.com/*");

            var original = await adapter.ApplyAsync(context, CancellationToken.None);
            var originalRecordIds = original.OwnedResourceIds.ToArray();
            addresses.Set("8.8.8.8", "2606:4700:4700::1111");

            Assert.False((await adapter.VerifyAsync(context, original, CancellationToken.None)).TargetBlocked);
            var expanded = await adapter.ReconcileAsync(context, original, CancellationToken.None);

            Assert.Equal(4, expanded.OwnedResourceIds.Count);
            Assert.Equal(4, policy.Filters.Count);
            Assert.True((await adapter.VerifyAsync(context, expanded, CancellationToken.None)).TargetBlocked);

            addresses.Set("2606:4700:4700::1111");
            Assert.False((await adapter.VerifyAsync(context, expanded, CancellationToken.None)).TargetBlocked);
            var contracted = await adapter.ReconcileAsync(context, expanded, CancellationToken.None);

            Assert.Equal(2, contracted.OwnedResourceIds.Count);
            Assert.Equal(2, policy.Filters.Count);
            Assert.All(policy.Filters, filter => Assert.Equal("2606:4700:4700::1111", filter.Address));
            Assert.True((await adapter.VerifyAsync(context, contracted, CancellationToken.None)).TargetBlocked);
            foreach (var recordId in originalRecordIds)
            {
                var record = await ledger.GetAsync(recordId, CancellationToken.None);
                Assert.NotNull(record);
                Assert.Equal(OwnershipMutationPhase.Restored, record.Phase);
                Assert.DoesNotContain(recordId, contracted.OwnedResourceIds);
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task FailedAtomicReconcileLeavesExistingPolicyAndArtifactOwnershipIntact()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var policy = new FakeWfpPolicyStore();
            var addresses = new MutableAddressSource("8.8.8.8");
            var adapter = new WfpEnforcementAdapter(
                policy,
                ledger,
                addresses,
                WindowsMutationGate.CreateForTests());
            var context = TestContextFactory.Create("*://*.youtube.com/*");
            var artifact = await adapter.ApplyAsync(context, CancellationToken.None);
            var originalFilterKeys = policy.Filters.Select(filter => filter.FilterKey).Order().ToArray();
            addresses.Set("2606:4700:4700::1111");
            policy.ThrowOnReconcileAfterAdd = true;

            await Assert.ThrowsAsync<InvalidOperationException>(() => adapter.ReconcileAsync(
                context,
                artifact,
                CancellationToken.None));

            Assert.Equal(originalFilterKeys, policy.Filters.Select(filter => filter.FilterKey).Order().ToArray());
            foreach (var recordId in artifact.OwnedResourceIds)
            {
                Assert.Equal(
                    OwnershipMutationPhase.Applied,
                    (await ledger.GetAsync(recordId, CancellationToken.None))!.Phase);
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task RequiredAddressFloorLossFailsReconcileWithoutRemovingOwnedFilters()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var policy = new FakeWfpPolicyStore();
            var addresses = new MutableAddressSource("8.8.8.8");
            var adapter = new WfpEnforcementAdapter(
                policy,
                ledger,
                addresses,
                WindowsMutationGate.CreateForTests());
            var context = TestContextFactory.Create("*://*.youtube.com/*");
            var artifact = await adapter.ApplyAsync(context, CancellationToken.None);
            var originalFilterKeys = policy.Filters.Select(filter => filter.FilterKey).Order().ToArray();
            addresses.Set();

            await Assert.ThrowsAsync<InvalidOperationException>(() => adapter.ReconcileAsync(
                context,
                artifact,
                CancellationToken.None));

            Assert.Equal(originalFilterKeys, policy.Filters.Select(filter => filter.FilterKey).Order().ToArray());
            foreach (var recordId in artifact.OwnedResourceIds)
            {
                Assert.Equal(
                    OwnershipMutationPhase.Applied,
                    (await ledger.GetAsync(recordId, CancellationToken.None))!.Phase);
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task CompositeAcceptsPendingWfpOnlyWhenPrimaryLayerBlocks()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var primary = new PrimaryBlockingAdapter();
            var wfp = new WfpEnforcementAdapter(
                new FakeWfpPolicyStore(),
                ledger,
                new MutableAddressSource(),
                WindowsMutationGate.CreateForTests());
            using var composite = new WindowsEnforcementAdapter(
                [primary, wfp],
                new NoOpDisposable());
            var context = TestContextFactory.Create(
                SharedAddressAction.Observe,
                "*://*.youtube.com/*");

            var artifact = await composite.ApplyAsync(context, CancellationToken.None);
            var verification = await composite.VerifyAsync(context, artifact, CancellationToken.None);

            Assert.True(verification.TargetBlocked);
            Assert.True(verification.GeneralConnectivityAvailable);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task RequiredEmptyAddressSourceRollsBackEarlierCompositeComponents()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var primary = new PrimaryBlockingAdapter();
            var wfp = new WfpEnforcementAdapter(
                new FakeWfpPolicyStore(),
                ledger,
                new MutableAddressSource(),
                WindowsMutationGate.CreateForTests());
            using var composite = new WindowsEnforcementAdapter(
                [primary, wfp],
                new NoOpDisposable());

            await Assert.ThrowsAsync<InvalidOperationException>(() => composite.ApplyAsync(
                TestContextFactory.Create("*://*.youtube.com/*"),
                CancellationToken.None));

            Assert.Equal(1, primary.RestoreCallCount);
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

    private sealed class PrimaryBlockingAdapter : IEnforcementAdapter, IWindowsPrimaryBlockingAdapter
    {
        public int RestoreCallCount { get; private set; }

        public string AdapterId => "primary";

        public Task<EnforcementHealth> CheckHealthAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new EnforcementHealth(AdapterId, true, true, "healthy"));

        public Task<EnforcementArtifact> ApplyAsync(
            EnforcementContext context,
            CancellationToken cancellationToken) =>
            Task.FromResult(new EnforcementArtifact(
                AdapterId,
                1,
                ["primary-resource"],
                new Dictionary<string, string>()));

        public Task<EnforcementVerification> VerifyAsync(
            EnforcementContext context,
            EnforcementArtifact artifact,
            CancellationToken cancellationToken) =>
            Task.FromResult(new EnforcementVerification(AdapterId, true, true, "blocked"));

        public Task<RestoreResult> RestoreAsync(
            EnforcementContext context,
            EnforcementArtifact artifact,
            CancellationToken cancellationToken)
        {
            RestoreCallCount++;
            return Task.FromResult(new RestoreResult(AdapterId, true, false, "restored"));
        }
    }

    private sealed class NoOpDisposable : IDisposable
    {
        public void Dispose()
        {
        }
    }
}
