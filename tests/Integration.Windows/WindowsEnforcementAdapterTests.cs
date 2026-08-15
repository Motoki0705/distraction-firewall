using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Enforcement.Windows;

namespace DistractionFirewall.Integration.Windows.Tests;

public sealed class WindowsEnforcementAdapterTests
{
    [Fact]
    public async Task CompositeRoundTripsComponentArtifactsAndRestoresInReverseOrder()
    {
        var calls = new List<string>();
        var first = new RecordingAdapter("first", calls);
        var second = new RecordingAdapter("second", calls);
        using var adapter = new WindowsEnforcementAdapter([first, second], new NoOpDisposable());
        var context = TestContextFactory.Create("*://*.youtube.com/*");

        var artifact = await adapter.ApplyAsync(context, CancellationToken.None);
        var verification = await adapter.VerifyAsync(context, artifact, CancellationToken.None);
        var restore = await adapter.RestoreAsync(context, artifact, CancellationToken.None);

        Assert.True(verification.TargetBlocked);
        Assert.True(restore.Restored);
        Assert.Equal(
            ["apply:first", "apply:second", "verify:first", "verify:second", "restore:second", "restore:first"],
            calls);
    }

    [Fact]
    public async Task CompositeApplyFailureRollsBackEarlierComponents()
    {
        var calls = new List<string>();
        var first = new RecordingAdapter("first", calls);
        var failing = new RecordingAdapter("failing", calls) { FailApply = true };
        using var adapter = new WindowsEnforcementAdapter([first, failing], new NoOpDisposable());

        await Assert.ThrowsAsync<InvalidOperationException>(() => adapter.ApplyAsync(
            TestContextFactory.Create("*://*.youtube.com/*"),
            CancellationToken.None));

        Assert.Equal(["apply:first", "apply:failing", "restore:first"], calls);
    }

    [Fact]
    public async Task ReconcileFailureRollsBackOnlyNewlyOwnedResources()
    {
        var calls = new List<string>();
        var first = new IncrementalRecordingAdapter("first", calls);
        var failing = new RecordingAdapter("failing", calls);
        using var adapter = new WindowsEnforcementAdapter([first, failing], new NoOpDisposable());
        var context = TestContextFactory.Create("*://*.youtube.com/*");
        var artifact = await adapter.ApplyAsync(context, CancellationToken.None);
        first.NeedsReconcile = true;
        failing.TargetBlocked = false;
        failing.FailApply = true;

        await Assert.ThrowsAsync<InvalidOperationException>(() => adapter.ReconcileAsync(
            context,
            artifact,
            CancellationToken.None));

        Assert.Single(first.RestoredArtifacts);
        Assert.Equal(["new-resource"], first.RestoredArtifacts[0].OwnedResourceIds);
        Assert.DoesNotContain("old-resource", first.RestoredArtifacts[0].OwnedResourceIds);
    }

    private sealed class RecordingAdapter : IEnforcementAdapter
    {
        private readonly List<string> _calls;

        public RecordingAdapter(string adapterId, List<string> calls)
        {
            AdapterId = adapterId;
            _calls = calls;
        }

        public string AdapterId { get; }

        public bool FailApply { get; set; }

        public bool TargetBlocked { get; set; } = true;

        public Task<EnforcementHealth> CheckHealthAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(new EnforcementHealth(AdapterId, true, true, "healthy"));
        }

        public Task<EnforcementArtifact> ApplyAsync(
            EnforcementContext context,
            CancellationToken cancellationToken)
        {
            _calls.Add("apply:" + AdapterId);
            if (FailApply)
            {
                throw new InvalidOperationException("injected failure");
            }

            return Task.FromResult(new EnforcementArtifact(
                AdapterId,
                1,
                ["resource"],
                new Dictionary<string, string>()));
        }

        public Task<EnforcementVerification> VerifyAsync(
            EnforcementContext context,
            EnforcementArtifact artifact,
            CancellationToken cancellationToken)
        {
            _calls.Add("verify:" + AdapterId);
            Assert.Equal(AdapterId, artifact.AdapterId);
            return Task.FromResult(new EnforcementVerification(
                AdapterId,
                TargetBlocked,
                true,
                TargetBlocked ? "verified" : "reconciliation required"));
        }

        public Task<RestoreResult> RestoreAsync(
            EnforcementContext context,
            EnforcementArtifact artifact,
            CancellationToken cancellationToken)
        {
            _calls.Add("restore:" + AdapterId);
            Assert.Equal(AdapterId, artifact.AdapterId);
            return Task.FromResult(new RestoreResult(AdapterId, true, false, "restored"));
        }
    }

    private sealed class IncrementalRecordingAdapter : IEnforcementReconciliationAdapter
    {
        private readonly List<string> _calls;

        public IncrementalRecordingAdapter(string adapterId, List<string> calls)
        {
            AdapterId = adapterId;
            _calls = calls;
        }

        public string AdapterId { get; }

        public bool NeedsReconcile { get; set; }

        public List<EnforcementArtifact> RestoredArtifacts { get; } = [];

        public Task<EnforcementHealth> CheckHealthAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new EnforcementHealth(AdapterId, true, true, "healthy"));

        public Task<EnforcementArtifact> ApplyAsync(
            EnforcementContext context,
            CancellationToken cancellationToken)
        {
            _calls.Add("apply:" + AdapterId);
            return Task.FromResult(new EnforcementArtifact(
                AdapterId,
                1,
                ["old-resource"],
                new Dictionary<string, string>()));
        }

        public Task<EnforcementVerification> VerifyAsync(
            EnforcementContext context,
            EnforcementArtifact artifact,
            CancellationToken cancellationToken)
        {
            _calls.Add("verify:" + AdapterId);
            return Task.FromResult(new EnforcementVerification(
                AdapterId,
                !NeedsReconcile,
                true,
                NeedsReconcile ? "reconciliation required" : "verified"));
        }

        public Task<EnforcementArtifact> ReconcileAsync(
            EnforcementContext context,
            EnforcementArtifact existingArtifact,
            CancellationToken cancellationToken)
        {
            _calls.Add("reconcile:" + AdapterId);
            return Task.FromResult(new EnforcementArtifact(
                AdapterId,
                1,
                ["new-resource"],
                new Dictionary<string, string>()));
        }

        public Task<RestoreResult> RestoreAsync(
            EnforcementContext context,
            EnforcementArtifact artifact,
            CancellationToken cancellationToken)
        {
            _calls.Add("restore:" + AdapterId);
            RestoredArtifacts.Add(artifact);
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
