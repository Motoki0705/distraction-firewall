using DistractionFirewall.Enforcement.Windows.Installation;

namespace DistractionFirewall.Integration.Windows.Tests;

public sealed class WindowsInstallationCleanupTests
{
    [Fact]
    public async Task CleanupPreflightsEveryBackendBeforeDeletingAnything()
    {
        var first = new FakeInstallationCleanupBackend("first");
        var second = new FakeInstallationCleanupBackend("second")
        {
            ValidateFailure = new InvalidOperationException("foreign resource"),
        };
        var cleanup = new WindowsInstallationCleanup([first, second]);

        var exception = await Assert.ThrowsAsync<WindowsInstallationCleanupException>(() =>
            cleanup.CleanupAsync(CancellationToken.None));

        Assert.Equal("second", exception.BackendId);
        Assert.Equal("preflight validation", exception.Operation);
        Assert.Equal(1, first.ValidateCount);
        Assert.Equal(1, second.ValidateCount);
        Assert.Equal(0, first.CleanupCount);
        Assert.Equal(0, second.CleanupCount);
    }

    [Fact]
    public async Task CleanupRevalidatesAndDeletesBackendsInDeclaredOrder()
    {
        var calls = new List<string>();
        var first = new FakeInstallationCleanupBackend("first", calls);
        var second = new FakeInstallationCleanupBackend("second", calls);
        var cleanup = new WindowsInstallationCleanup([first, second]);

        await cleanup.CleanupAsync(CancellationToken.None);

        Assert.Equal(
            ["validate:first", "validate:second", "cleanup:first", "cleanup:second"],
            calls);
    }

    [Fact]
    public async Task CleanupStopsAfterCompareAndDeleteFailure()
    {
        var first = new FakeInstallationCleanupBackend("first")
        {
            CleanupFailure = new InvalidOperationException("CAS mismatch"),
        };
        var second = new FakeInstallationCleanupBackend("second");
        var cleanup = new WindowsInstallationCleanup([first, second]);

        var exception = await Assert.ThrowsAsync<WindowsInstallationCleanupException>(() =>
            cleanup.CleanupAsync(CancellationToken.None));

        Assert.Equal("first", exception.BackendId);
        Assert.Equal("compare-and-delete", exception.Operation);
        Assert.Equal(1, first.CleanupCount);
        Assert.Equal(0, second.CleanupCount);
    }

    private sealed class FakeInstallationCleanupBackend : IWindowsInstallationCleanupBackend
    {
        private readonly List<string>? _calls;

        public FakeInstallationCleanupBackend(string backendId, List<string>? calls = null)
        {
            BackendId = backendId;
            _calls = calls;
        }

        public string BackendId { get; }

        public Exception? ValidateFailure { get; init; }

        public Exception? CleanupFailure { get; init; }

        public int ValidateCount { get; private set; }

        public int CleanupCount { get; private set; }

        public void ValidateReadyForCleanup()
        {
            ValidateCount++;
            _calls?.Add("validate:" + BackendId);
            if (ValidateFailure is not null)
            {
                throw ValidateFailure;
            }
        }

        public void CleanupValidatedResources()
        {
            CleanupCount++;
            _calls?.Add("cleanup:" + BackendId);
            if (CleanupFailure is not null)
            {
                throw CleanupFailure;
            }
        }
    }
}
