using DistractionFirewall.Contracts;
using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Core.Persistence;

namespace DistractionFirewall.LeaseLifecycleTests;

public sealed class FileLeaseCapsuleStoreTests
{
    [Fact]
    public void Relative_capsule_root_is_rejected()
    {
        Assert.Throws<ArgumentException>(() => new FileLeaseCapsuleStore("relative-root"));
    }

    [Fact]
    public async Task Capsule_and_artifacts_round_trip_and_only_hash_of_nonce_is_persisted()
    {
        using var workspace = new TestWorkspace();
        var preparation = TestData.Preparation();
        var leaseId = Guid.NewGuid();
        var manifest = TestData.Manifest(leaseId);
        var state = TestData.State(leaseId, LeaseState.Activating);
        var artifact = new EnforcementArtifact(
            "safe-test",
            SchemaVersion: 1,
            ["owned:test"],
            new Dictionary<string, string>(StringComparer.Ordinal) { ["key"] = "value" });

        await workspace.Store.SavePreparationAsync(preparation, CancellationToken.None);
        await workspace.Store.CreateCapsuleAsync(manifest, state, CancellationToken.None);
        await workspace.Store.SaveArtifactsAsync(leaseId, [artifact], CancellationToken.None);

        var persistedPreparation = Assert.IsType<DistractionFirewall.Core.Leases.PreparedLease>(
            await workspace.Store.GetPreparationAsync(preparation.PreparationId, CancellationToken.None));
        Assert.Equal(preparation.PreparationId, persistedPreparation.PreparationId);
        Assert.Equal(preparation.RequestFingerprint, persistedPreparation.RequestFingerprint);
        Assert.Equal(preparation.NonceHash, persistedPreparation.NonceHash);
        Assert.Equal("youtube", Assert.Single(persistedPreparation.TargetSnapshot).StableId);
        var persistedManifest = Assert.IsType<DistractionFirewall.Core.Leases.LeaseManifest>(
            await workspace.Store.GetManifestAsync(leaseId, CancellationToken.None));
        Assert.Equal(manifest.LeaseId, persistedManifest.LeaseId);
        Assert.Equal(manifest.CommitRequestFingerprint, persistedManifest.CommitRequestFingerprint);
        Assert.Equal("youtube", Assert.Single(persistedManifest.TargetSnapshot).StableId);
        Assert.Equal(state, await workspace.Store.GetStateAsync(leaseId, CancellationToken.None));
        var persistedArtifact = Assert.Single(await workspace.Store.GetArtifactsAsync(
            leaseId,
            CancellationToken.None));
        Assert.Equal(artifact.AdapterId, persistedArtifact.AdapterId);
        Assert.Equal(artifact.OwnedResourceIds, persistedArtifact.OwnedResourceIds);
        Assert.Equal("value", persistedArtifact.Properties["key"]);
        Assert.Equal(leaseId, await workspace.Store.GetActiveLeaseIdAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Second_active_lease_is_rejected_until_first_completes()
    {
        using var workspace = new TestWorkspace();
        var firstLeaseId = Guid.NewGuid();
        await workspace.Store.CreateCapsuleAsync(
            TestData.Manifest(firstLeaseId),
            TestData.State(firstLeaseId, LeaseState.Activating),
            CancellationToken.None);
        var secondLeaseId = Guid.NewGuid();

        await Assert.ThrowsAsync<LeaseStoreConflictException>(() => workspace.Store.CreateCapsuleAsync(
            TestData.Manifest(secondLeaseId),
            TestData.State(secondLeaseId, LeaseState.Activating),
            CancellationToken.None));

        var completed = TestData.State(firstLeaseId, LeaseState.Completed, sequence: 1);
        await workspace.Store.SaveStateAsync(completed, CancellationToken.None);
        await workspace.Store.CreateCapsuleAsync(
            TestData.Manifest(secondLeaseId),
            TestData.State(secondLeaseId, LeaseState.Activating),
            CancellationToken.None);
        Assert.Equal(secondLeaseId, await workspace.Store.GetActiveLeaseIdAsync(CancellationToken.None));
    }

    [Fact]
    public async Task State_sequence_rejects_stale_and_conflicting_writes()
    {
        using var workspace = new TestWorkspace();
        var leaseId = Guid.NewGuid();
        var initial = TestData.State(leaseId, LeaseState.Activating);
        await workspace.Store.CreateCapsuleAsync(
            TestData.Manifest(leaseId),
            initial,
            CancellationToken.None);
        var active = initial with
        {
            State = LeaseState.Active,
            Sequence = 1,
            Health = LeaseHealth.Healthy,
        };
        await workspace.Store.SaveStateAsync(active, CancellationToken.None);

        await Assert.ThrowsAsync<LeaseStoreConflictException>(() => workspace.Store.SaveStateAsync(
            initial,
            CancellationToken.None));
        await Assert.ThrowsAsync<LeaseStoreConflictException>(() => workspace.Store.SaveStateAsync(
            active with { Health = LeaseHealth.Degraded },
            CancellationToken.None));
    }
}
