using DistractionFirewall.Core.Persistence;
using DistractionFirewall.Finalizer;
using DistractionFirewall.Runtime.Windows;

namespace DistractionFirewall.LeaseLifecycleTests;

public sealed class RuntimeUninstallGuardTests
{
    [Fact]
    public async Task Guard_succeeds_when_protected_marker_is_absent()
    {
        using var workspace = new TestWorkspace();
        var paths = CreateRuntimePaths(workspace.RootPath);
        var guard = new RuntimeUninstallGuard(paths);

        await guard.VerifyInactiveAsync(TimeSpan.FromSeconds(1), CancellationToken.None);

        Assert.True(File.Exists(Path.Combine(
            paths.DataRoot,
            FileLeaseCapsuleStore.LockFileName)));
    }

    [Fact]
    public async Task Guard_refuses_any_active_marker_directory_entry()
    {
        using var workspace = new TestWorkspace();
        var paths = CreateRuntimePaths(workspace.RootPath);
        Directory.CreateDirectory(Path.Combine(
            paths.DataRoot,
            FileLeaseCapsuleStore.ActiveLeaseFileName));
        var guard = new RuntimeUninstallGuard(paths);

        await Assert.ThrowsAsync<ActiveLeasePresentException>(() =>
            guard.VerifyInactiveAsync(TimeSpan.FromSeconds(1), CancellationToken.None));
    }

    [Fact]
    public async Task Guard_waits_for_capsule_lock_then_observes_marker_created_by_lock_owner()
    {
        using var workspace = new TestWorkspace();
        var paths = CreateRuntimePaths(workspace.RootPath);
        var lockPath = Path.Combine(paths.DataRoot, FileLeaseCapsuleStore.LockFileName);
        var markerPath = Path.Combine(paths.DataRoot, FileLeaseCapsuleStore.ActiveLeaseFileName);
        var guard = new RuntimeUninstallGuard(paths);
        await using var lockOwner = new FileStream(
            lockPath,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None);

        var verification = guard.VerifyInactiveAsync(TimeSpan.FromSeconds(2), CancellationToken.None);
        await Task.Delay(TimeSpan.FromMilliseconds(100));
        Assert.False(verification.IsCompleted);
        await File.WriteAllTextAsync(markerPath, "{}");
        await lockOwner.DisposeAsync();

        await Assert.ThrowsAsync<ActiveLeasePresentException>(() => verification);
    }

    [Fact]
    public async Task Guard_fails_closed_when_capsule_lock_cannot_be_acquired()
    {
        using var workspace = new TestWorkspace();
        var paths = CreateRuntimePaths(workspace.RootPath);
        var lockPath = Path.Combine(paths.DataRoot, FileLeaseCapsuleStore.LockFileName);
        var guard = new RuntimeUninstallGuard(paths);
        await using var lockOwner = new FileStream(
            lockPath,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None);

        await Assert.ThrowsAsync<TimeoutException>(() =>
            guard.VerifyInactiveAsync(TimeSpan.FromMilliseconds(100), CancellationToken.None));
    }

    [Fact]
    public void Guard_rejects_a_data_root_outside_the_fixed_runtime_layout()
    {
        using var workspace = new TestWorkspace();
        var paths = CreateRuntimePaths(workspace.RootPath);
        var escapedRoot = Path.Combine(workspace.RootPath, "escaped");

        Assert.Throws<InvalidOperationException>(() =>
            new RuntimeUninstallGuard(paths with
            {
                DataRoot = escapedRoot,
                LeaseStoreDirectory = escapedRoot,
            }));
    }

    [Fact]
    public async Task Guard_rejects_a_directory_at_the_lock_path()
    {
        using var workspace = new TestWorkspace();
        var paths = CreateRuntimePaths(workspace.RootPath);
        Directory.CreateDirectory(Path.Combine(
            paths.DataRoot,
            FileLeaseCapsuleStore.LockFileName));
        var guard = new RuntimeUninstallGuard(paths);

        await Assert.ThrowsAsync<IOException>(() =>
            guard.VerifyInactiveAsync(TimeSpan.FromSeconds(1), CancellationToken.None));
    }

    private static RuntimePaths CreateRuntimePaths(string rootPath)
    {
        var programFilesRoot = Path.Combine(rootPath, "program-files");
        var programDataRoot = Path.Combine(rootPath, "program-data");
        var componentDirectory = Path.Combine(
            programFilesRoot,
            "Distraction Firewall Lease Runtime",
            "finalizer");
        Directory.CreateDirectory(componentDirectory);
        var paths = RuntimePathResolver.ResolveForTests(
            programFilesRoot,
            programDataRoot,
            RuntimeComponent.Finalizer,
            componentDirectory);
        Directory.CreateDirectory(paths.DataRoot);
        return paths;
    }
}
