using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Core.Targets;
using DistractionFirewall.Enforcement.Windows.Dns;

namespace DistractionFirewall.Runtime.Windows;

public sealed class ProtectedLeaseTargetSnapshotStore
{
    private static readonly JsonSerializerOptions SerializerOptions = CreateSerializerOptions();
    private readonly string _protectedDirectoryPath;
    private readonly string _snapshotPath;
    private readonly string _lockPath;

    public ProtectedLeaseTargetSnapshotStore(
        string protectedDirectoryPath,
        string snapshotPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(protectedDirectoryPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(snapshotPath);
        _protectedDirectoryPath = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(protectedDirectoryPath));
        _snapshotPath = Path.GetFullPath(snapshotPath);
        if (!Directory.Exists(_protectedDirectoryPath))
        {
            throw new DirectoryNotFoundException(
                $"The protected DNS data directory '{_protectedDirectoryPath}' does not exist.");
        }

        var parent = Path.TrimEndingDirectorySeparator(
            Path.GetDirectoryName(_snapshotPath)
            ?? throw new ArgumentException("The target snapshot has no parent directory.", nameof(snapshotPath)));
        if (!PathsEqual(parent, _protectedDirectoryPath))
        {
            throw new ArgumentException(
                "The target snapshot must be a direct child of the protected DNS data directory.",
                nameof(snapshotPath));
        }

        _lockPath = Path.Combine(_protectedDirectoryPath, ".target-snapshot.lock");
        if (PathsEqual(_snapshotPath, _lockPath))
        {
            throw new ArgumentException(
                "The target snapshot path cannot replace its cross-process lock.",
                nameof(snapshotPath));
        }

        ValidatePaths();
    }

    public string SnapshotPath => _snapshotPath;

    public void EnsureInactivePlaceholder()
    {
        using var processLock = AcquireLock(CancellationToken.None);
        if (!File.Exists(_snapshotPath))
        {
            WriteBytesAtomically("[]"u8);
        }
    }

    public async Task WriteAsync(
        EnforcementContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var catalog = new TargetCatalog(context.Targets);
        var ruleHash = TargetCatalog.ComputeDefinitionHash(catalog.Targets);
        if (!string.Equals(ruleHash, context.RuleHash, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The lease target snapshot does not match its protected rule hash.");
        }

        await using var processLock = await AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(
            catalog.Targets.OrderBy(target => target.StableId, StringComparer.Ordinal),
            SerializerOptions);
        await WriteBytesAtomicallyAsync(bytes, cancellationToken).ConfigureAwait(false);
        var persisted = await TargetCatalog.LoadAsync(_snapshotPath, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(
                TargetCatalog.ComputeDefinitionHash(persisted.Targets),
                context.RuleHash,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("The persisted lease target snapshot failed rule-hash verification.");
        }
    }

    public async Task ClearAsync(CancellationToken cancellationToken)
    {
        await using var processLock = await AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        await WriteBytesAtomicallyAsync("[]"u8.ToArray(), cancellationToken).ConfigureAwait(false);
    }

    private FileStream AcquireLock(CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 400; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ValidatePaths();
            try
            {
                return new FileStream(
                    _lockPath,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    bufferSize: 1,
                    FileOptions.WriteThrough);
            }
            catch (IOException) when (attempt < 399)
            {
                Thread.Sleep(25);
            }
        }

        throw new IOException("The protected target snapshot lock is unavailable.");
    }

    private async Task<FileStream> AcquireLockAsync(CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 400; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ValidatePaths();
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
            catch (IOException) when (attempt < 399)
            {
                await Task.Delay(25, cancellationToken).ConfigureAwait(false);
            }
        }

        throw new IOException("The protected target snapshot lock is unavailable.");
    }

    private void WriteBytesAtomically(ReadOnlySpan<byte> bytes)
    {
        ValidatePaths();
        var temporaryPath = TemporaryPath();
        try
        {
            using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 4096,
                FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }

            ValidatePaths();
            ReplaceAtomically(temporaryPath, _snapshotPath);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private async Task WriteBytesAtomicallyAsync(
        ReadOnlyMemory<byte> bytes,
        CancellationToken cancellationToken)
    {
        ValidatePaths();
        var temporaryPath = TemporaryPath();
        try
        {
            await using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 4096,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            ValidatePaths();
            await ReplaceAtomicallyAsync(
                temporaryPath,
                _snapshotPath,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private void ValidatePaths()
    {
        RejectReparseOrDirectory(_protectedDirectoryPath, expectDirectory: true);
        RejectReparseOrDirectory(_snapshotPath, expectDirectory: false);
        RejectReparseOrDirectory(_lockPath, expectDirectory: false);
    }

    private static void ReplaceAtomically(string temporaryPath, string destinationPath)
    {
        for (var attempt = 0; attempt < 40; attempt++)
        {
            try
            {
                File.Move(temporaryPath, destinationPath, overwrite: true);
                return;
            }
            catch (Exception exception) when (
                attempt < 39 && exception is IOException or UnauthorizedAccessException)
            {
                Thread.Sleep(25);
            }
        }

        throw new IOException("The atomic target snapshot replacement failed.");
    }

    private static async Task ReplaceAtomicallyAsync(
        string temporaryPath,
        string destinationPath,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 40; attempt++)
        {
            try
            {
                File.Move(temporaryPath, destinationPath, overwrite: true);
                return;
            }
            catch (Exception exception) when (
                attempt < 39 && exception is IOException or UnauthorizedAccessException)
            {
                await Task.Delay(25, cancellationToken).ConfigureAwait(false);
            }
        }

        throw new IOException("The atomic target snapshot replacement failed.");
    }

    private static void RejectReparseOrDirectory(string path, bool expectDirectory)
    {
        if (new FileInfo(path).LinkTarget is not null ||
            new DirectoryInfo(path).LinkTarget is not null)
        {
            throw new IOException("A protected target snapshot path is a symbolic link.");
        }

        if (!File.Exists(path) && !Directory.Exists(path))
        {
            if (expectDirectory)
            {
                throw new DirectoryNotFoundException($"Protected directory '{path}' does not exist.");
            }

            return;
        }

        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0 ||
            ((attributes & FileAttributes.Directory) != 0) != expectDirectory)
        {
            throw new IOException($"Protected target snapshot path '{path}' has an unsafe file type.");
        }
    }

    private string TemporaryPath() => Path.Combine(
        _protectedDirectoryPath,
        $".{Path.GetFileName(_snapshotPath)}.{Guid.NewGuid():N}.tmp");

    private static bool PathsEqual(string left, string right) => string.Equals(
        left,
        right,
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    private static JsonSerializerOptions CreateSerializerOptions()
    {
        var resolver = new DefaultJsonTypeInfoResolver();
        resolver.Modifiers.Add(static typeInfo =>
        {
            if (typeInfo.Type != typeof(IpBlockPolicyDefinition))
            {
                return;
            }

            foreach (var property in typeInfo.Properties.Where(property =>
                         !string.Equals(property.Name, "mode", StringComparison.Ordinal)))
            {
                property.ShouldSerialize = static (value, _) =>
                    ((IpBlockPolicyDefinition)value).Mode == IpBlockMode.DnsObserved;
            }
        });
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            PropertyNameCaseInsensitive = false,
            TypeInfoResolver = resolver,
            WriteIndented = true,
        };
        options.Converters.Add(new JsonStringEnumConverter(
            JsonNamingPolicy.SnakeCaseLower,
            allowIntegerValues: false));
        return options;
    }
}

public sealed class LeaseTargetSnapshotDnsEnforcementAdapter :
    IEnforcementReconciliationAdapter,
    IDisposable
{
    private readonly WindowsDnsEnforcementAdapter _inner;
    private readonly ProtectedLeaseTargetSnapshotStore _snapshotStore;
    private bool _disposed;

    public LeaseTargetSnapshotDnsEnforcementAdapter(
        WindowsDnsEnforcementAdapter inner,
        ProtectedLeaseTargetSnapshotStore snapshotStore)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _snapshotStore = snapshotStore ?? throw new ArgumentNullException(nameof(snapshotStore));
    }

    public string AdapterId => _inner.AdapterId;

    public Task<EnforcementHealth> CheckHealthAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        return _inner.CheckHealthAsync(cancellationToken);
    }

    public async Task<EnforcementArtifact> ApplyAsync(
        EnforcementContext context,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        await _snapshotStore.WriteAsync(context, cancellationToken).ConfigureAwait(false);
        return await _inner.ApplyAsync(context, cancellationToken).ConfigureAwait(false);
    }

    public async Task<EnforcementArtifact> ReconcileAsync(
        EnforcementContext context,
        EnforcementArtifact existingArtifact,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        await _snapshotStore.WriteAsync(context, cancellationToken).ConfigureAwait(false);
        return await _inner.ReconcileAsync(context, existingArtifact, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<EnforcementVerification> VerifyAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        await _snapshotStore.WriteAsync(context, cancellationToken).ConfigureAwait(false);
        return await _inner.VerifyAsync(context, artifact, cancellationToken).ConfigureAwait(false);
    }

    public async Task<RestoreResult> RestoreAsync(
        EnforcementContext context,
        EnforcementArtifact artifact,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        var result = await _inner.RestoreAsync(context, artifact, cancellationToken).ConfigureAwait(false);
        if (result.Restored)
        {
            await _snapshotStore.ClearAsync(cancellationToken).ConfigureAwait(false);
        }

        return result;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _inner.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}
