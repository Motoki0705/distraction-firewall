using System.Diagnostics;
using DistractionFirewall.Core.Persistence;
using DistractionFirewall.Runtime.Windows;

namespace DistractionFirewall.Finalizer;

public sealed class ActiveLeasePresentException : InvalidOperationException
{
    public ActiveLeasePresentException(string message)
        : base(message)
    {
    }
}

/// <summary>
/// Performs the installer's final, fail-closed inactive-lease check while holding the
/// same exclusive file lock used by <see cref="FileLeaseCapsuleStore"/>.
/// </summary>
public sealed class RuntimeUninstallGuard
{
    public static readonly TimeSpan DefaultLockTimeout = TimeSpan.FromSeconds(30);

    private static readonly TimeSpan LockRetryDelay = TimeSpan.FromMilliseconds(20);
    private readonly string _dataRoot;
    private readonly string _activeLeasePath;
    private readonly string _lockPath;

    public RuntimeUninstallGuard(RuntimePaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        if (paths.Component != RuntimeComponent.Finalizer)
        {
            throw new ArgumentException(
                "The runtime uninstall guard must execute from the installed Finalizer component.",
                nameof(paths));
        }

        var programDataRoot = NormalizeRoot(paths.ProgramDataRoot, nameof(paths));
        var expectedDataRoot = Path.GetFullPath(Path.Combine(
            programDataRoot,
            "DistractionFirewall",
            "Runtime",
            "v1"));
        _dataRoot = NormalizeRoot(paths.DataRoot, nameof(paths));
        if (!string.Equals(_dataRoot, expectedDataRoot, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                NormalizeRoot(paths.LeaseStoreDirectory, nameof(paths)),
                expectedDataRoot,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The runtime uninstall guard refuses a data root outside the fixed Runtime v1 layout.");
        }

        _activeLeasePath = ResolveDirectChild(
            _dataRoot,
            FileLeaseCapsuleStore.ActiveLeaseFileName);
        _lockPath = ResolveDirectChild(_dataRoot, FileLeaseCapsuleStore.LockFileName);
    }

    public async Task VerifyInactiveAsync(
        TimeSpan lockTimeout,
        CancellationToken cancellationToken)
    {
        if (lockTimeout <= TimeSpan.Zero || lockTimeout > TimeSpan.FromMinutes(2))
        {
            throw new ArgumentOutOfRangeException(
                nameof(lockTimeout),
                "The uninstall guard lock timeout must be positive and no more than two minutes.");
        }

        RequireExistingNonReparseDirectory(_dataRoot);
        await using var storeLock = await AcquireStoreLockAsync(lockTimeout, cancellationToken)
            .ConfigureAwait(false);

        // Validate again after winning the inter-process lock. The installer must have stopped
        // and disabled the Activation Service before invoking this command, so a clean result
        // cannot be invalidated by a subsequent lease commit.
        RequireExistingNonReparseDirectory(_dataRoot);
        if (HasDirectoryEntry(_dataRoot, FileLeaseCapsuleStore.ActiveLeaseFileName))
        {
            throw new ActiveLeasePresentException(
                $"Runtime removal was refused because '{_activeLeasePath}' exists.");
        }
    }

    private async Task<FileStream> AcquireStoreLockAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var started = Stopwatch.GetTimestamp();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RejectUnsafeExistingLockEntry();
            try
            {
                return new FileStream(
                    _lockPath,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    bufferSize: 1,
                    FileOptions.Asynchronous | FileOptions.WriteThrough);
            }
            catch (IOException) when (Stopwatch.GetElapsedTime(started) < timeout)
            {
                await Task.Delay(LockRetryDelay, cancellationToken).ConfigureAwait(false);
            }
            catch (IOException exception)
            {
                throw new TimeoutException(
                    "Timed out waiting for the protected lease capsule store lock.",
                    exception);
            }
        }
    }

    private void RejectUnsafeExistingLockEntry()
    {
        var entry = Directory.EnumerateFileSystemEntries(
                _dataRoot,
                FileLeaseCapsuleStore.LockFileName,
                SearchOption.TopDirectoryOnly)
            .FirstOrDefault(path => string.Equals(
                Path.GetFileName(path),
                FileLeaseCapsuleStore.LockFileName,
                StringComparison.OrdinalIgnoreCase));
        if (entry is null)
        {
            return;
        }

        var attributes = File.GetAttributes(entry);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new IOException("The protected lease capsule store lock is not a regular file.");
        }
    }

    private static bool HasDirectoryEntry(string directory, string fileName)
    {
        return Directory.EnumerateFileSystemEntries(directory, fileName, SearchOption.TopDirectoryOnly)
            .Any(path => string.Equals(
                Path.GetFileName(path),
                fileName,
                StringComparison.OrdinalIgnoreCase));
    }

    private static void RequireExistingNonReparseDirectory(string path)
    {
        if (!Directory.Exists(path))
        {
            throw new DirectoryNotFoundException(
                $"The protected Runtime data root '{path}' does not exist.");
        }

        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException(
                $"The protected Runtime data root '{path}' must not be a reparse point.");
        }
    }

    private static string ResolveDirectChild(string root, string fileName)
    {
        var candidate = Path.GetFullPath(Path.Combine(root, fileName));
        var expectedParent = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        var actualParent = Path.GetDirectoryName(candidate);
        if (!string.Equals(expectedParent, actualParent, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The uninstall guard path escaped the Runtime data root.");
        }

        return candidate;
    }

    private static string NormalizeRoot(string path, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path))
        {
            throw new ArgumentException("A fully-qualified runtime path is required.", parameterName);
        }

        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
    }
}
