using System.Text;
using DistractionFirewall.Enforcement.Windows.Ownership;

namespace DistractionFirewall.Integration.Windows.Tests;

public sealed class OwnershipLedgerTests
{
    [Fact]
    public async Task PrepareAndPhaseUpdateAreDurableAndAtomic()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            string recordId;
            using (var ledger = new FileOwnershipLedger(directory, "test-install"))
            {
                var record = await ledger.PrepareAsync(
                    "adapter",
                    Guid.Parse("6f5056d8-ad90-4aaa-a40a-d0ea4e97412c"),
                    "resource",
                    OwnedResourceState.Missing,
                    OwnedResourceState.Present("test/value", Encoding.UTF8.GetBytes("desired")),
                    CancellationToken.None);
                recordId = record.RecordId;
                Assert.Equal(OwnershipMutationPhase.Prepared, record.Phase);
                _ = await ledger.SetPhaseAsync(
                    recordId,
                    OwnershipMutationPhase.Applied,
                    null,
                    CancellationToken.None);
                Assert.True(File.Exists(ledger.GetRecordPath(recordId)));
            }

            using var reopened = new FileOwnershipLedger(directory, "test-install");
            var durable = await reopened.GetAsync(recordId, CancellationToken.None);
            Assert.NotNull(durable);
            Assert.Equal(OwnershipMutationPhase.Applied, durable.Phase);
            Assert.Empty(Directory.EnumerateFiles(directory, "*.tmp.*"));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task CoordinatorAppliesAndRestoresOnlyItsOwnedValue()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var coordinator = new OwnedMutationCoordinator(ledger);
            var store = new FakeCompareExchangeStore();
            var desired = OwnedResourceState.Present("test/value", [1, 2, 3]);

            var applied = await coordinator.ApplyAsync(
                store,
                "adapter",
                Guid.NewGuid(),
                "resource",
                desired,
                failIfPresent: true,
                CancellationToken.None);

            Assert.True(applied.Owned);
            Assert.NotNull(applied.RecordId);
            Assert.Equal(1, store.MutationCount);

            var restored = await coordinator.RestoreAsync(store, applied.RecordId, CancellationToken.None);
            Assert.True(restored.Restored);
            Assert.False(restored.Conflict);
            Assert.Equal(2, store.MutationCount);
            Assert.False((await store.ReadAsync("resource", CancellationToken.None)).Exists);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task RestoreLeavesForeignCurrentStateUntouched()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var coordinator = new OwnedMutationCoordinator(ledger);
            var store = new FakeCompareExchangeStore();
            var desired = OwnedResourceState.Present("test/value", [1]);
            var foreign = OwnedResourceState.Present("test/value", [9]);
            var applied = await coordinator.ApplyAsync(
                store,
                "adapter",
                Guid.NewGuid(),
                "resource",
                desired,
                failIfPresent: true,
                CancellationToken.None);
            store.Set("resource", foreign);

            var restored = await coordinator.RestoreAsync(store, applied.RecordId!, CancellationToken.None);

            Assert.False(restored.Restored);
            Assert.True(restored.Conflict);
            Assert.True(OwnedResourceState.ExactEquals(
                foreign,
                await store.ReadAsync("resource", CancellationToken.None)));
            Assert.Equal(1, store.MutationCount);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task ApplyFailsClosedOnPreexistingConflict()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var ledger = new FileOwnershipLedger(directory, "test-install");
            var coordinator = new OwnedMutationCoordinator(ledger);
            var store = new FakeCompareExchangeStore();
            store.Set("resource", OwnedResourceState.Present("test/value", [4]));

            await Assert.ThrowsAsync<OwnershipConflictException>(() => coordinator.ApplyAsync(
                store,
                "adapter",
                Guid.NewGuid(),
                "resource",
                OwnedResourceState.Present("test/value", [5]),
                failIfPresent: true,
                CancellationToken.None));
            Assert.Equal(0, store.MutationCount);
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
