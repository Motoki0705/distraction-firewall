using System.Text.Json;
using DistractionFirewall.Contracts;
using DistractionFirewall.Core.Enforcement;
using DistractionFirewall.Core.Leases;

namespace DistractionFirewall.Core.Persistence;

public sealed class FileLeaseCapsuleStore : ILeaseLifecycleStore
{
    public const string ActiveLeaseFileName = "active-lease.json";
    private const string ArtifactsFileName = "artifacts.json";
    public const string LockFileName = ".capsule-store.lock";
    private const string ManifestFileName = "manifest.json";
    private const string StateFileName = "state.json";
    private readonly string _activeLeasePath;
    private readonly string _leasesPath;
    private readonly string _lockPath;
    private readonly string _preparationsPath;
    private readonly string _rootPrefix;
    private readonly JsonSerializerOptions _serializerOptions;

    public FileLeaseCapsuleStore(string rootPath, JsonSerializerOptions? serializerOptions = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        if (!Path.IsPathFullyQualified(rootPath))
        {
            throw new ArgumentException("The capsule root must be an absolute path.", nameof(rootPath));
        }

        RootPath = Path.GetFullPath(rootPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        _rootPrefix = RootPath + Path.DirectorySeparatorChar;
        _serializerOptions = serializerOptions ?? ProtocolJson.CreateOptions();

        Directory.CreateDirectory(RootPath);
        RejectReparsePoint(RootPath);
        _leasesPath = ResolveUnderRoot("leases");
        _preparationsPath = ResolveUnderRoot("preparations");
        Directory.CreateDirectory(_leasesPath);
        Directory.CreateDirectory(_preparationsPath);
        RejectReparsePoint(_leasesPath);
        RejectReparsePoint(_preparationsPath);

        _activeLeasePath = ResolveUnderRoot(ActiveLeaseFileName);
        _lockPath = ResolveUnderRoot(LockFileName);
    }

    public string RootPath { get; }

    public static string DefaultRootPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "DistractionFirewall",
        "Runtime",
        "v1");

    public async Task<bool> HasActiveLeaseAsync(CancellationToken cancellationToken)
    {
        await using var storeLock = await AcquireStoreLockAsync(cancellationToken).ConfigureAwait(false);
        return await GetActiveLeaseIdCoreAsync(cancellationToken).ConfigureAwait(false) is not null;
    }

    public async Task<Guid?> GetActiveLeaseIdAsync(CancellationToken cancellationToken)
    {
        await using var storeLock = await AcquireStoreLockAsync(cancellationToken).ConfigureAwait(false);
        return await GetActiveLeaseIdCoreAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task SavePreparationAsync(PreparedLease preparation, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(preparation);
        ValidateGuid(preparation.PreparationId, nameof(preparation.PreparationId));
        ValidateGuid(preparation.RequestId, nameof(preparation.RequestId));

        await using var storeLock = await AcquireStoreLockAsync(cancellationToken).ConfigureAwait(false);
        var path = GetPreparationPath(preparation.PreparationId);
        var current = await ReadAsync<PreparedLease>(path, cancellationToken).ConfigureAwait(false);
        if (current is not null)
        {
            if (current.RequestId != preparation.RequestId ||
                !string.Equals(current.RequestFingerprint, preparation.RequestFingerprint, StringComparison.Ordinal) ||
                !string.Equals(current.NonceHash, preparation.NonceHash, StringComparison.Ordinal))
            {
                throw new LeaseStoreConflictException(
                    $"Preparation '{preparation.PreparationId}' already represents a different request.");
            }

            return;
        }

        await WriteAtomicAsync(path, preparation, cancellationToken).ConfigureAwait(false);
    }

    public Task<PreparedLease?> GetPreparationAsync(Guid preparationId, CancellationToken cancellationToken)
    {
        ValidateGuid(preparationId, nameof(preparationId));
        return ReadAsync<PreparedLease>(GetPreparationPath(preparationId), cancellationToken);
    }

    public async Task CreateCapsuleAsync(
        LeaseManifest manifest,
        LeaseRuntimeState state,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(state);
        ValidateGuid(manifest.LeaseId, nameof(manifest.LeaseId));
        if (manifest.LeaseId != state.LeaseId)
        {
            throw new ArgumentException("Manifest and runtime state must identify the same lease.", nameof(state));
        }

        if (manifest.SchemaVersion != LeaseManifest.CurrentSchemaVersion)
        {
            throw new InvalidDataException($"Unsupported lease manifest schema {manifest.SchemaVersion}.");
        }

        await using var storeLock = await AcquireStoreLockAsync(cancellationToken).ConfigureAwait(false);
        var activeLeaseId = await GetActiveLeaseIdCoreAsync(cancellationToken).ConfigureAwait(false);
        if (activeLeaseId is not null && activeLeaseId != manifest.LeaseId)
        {
            throw new LeaseStoreConflictException($"Lease '{activeLeaseId}' is already active.");
        }

        var leasePath = GetLeasePath(manifest.LeaseId);
        Directory.CreateDirectory(leasePath);
        RejectReparsePoint(leasePath);

        var manifestPath = GetLeaseFilePath(manifest.LeaseId, ManifestFileName);
        var currentManifest = await ReadAsync<LeaseManifest>(manifestPath, cancellationToken).ConfigureAwait(false);
        if (currentManifest is not null && !ManifestIdentityMatches(currentManifest, manifest))
        {
            throw new LeaseStoreConflictException($"Lease '{manifest.LeaseId}' has a conflicting manifest.");
        }

        var statePath = GetLeaseFilePath(manifest.LeaseId, StateFileName);
        var currentState = await ReadAsync<LeaseRuntimeState>(statePath, cancellationToken).ConfigureAwait(false);
        if (currentState is not null && currentState.LeaseId != state.LeaseId)
        {
            throw new LeaseStoreConflictException($"Lease '{manifest.LeaseId}' has a conflicting state file.");
        }

        // State is written first so a crash cannot expose a manifest that Commit treats as
        // complete while the mutable half of the capsule is missing. Neither file becomes
        // active until the marker is atomically published below.
        if (currentState is null)
        {
            await WriteAtomicAsync(statePath, state, cancellationToken).ConfigureAwait(false);
        }

        if (currentManifest is null)
        {
            await WriteAtomicAsync(manifestPath, manifest, cancellationToken).ConfigureAwait(false);
        }

        await WriteAtomicAsync(
            _activeLeasePath,
            new ActiveLeaseMarker(manifest.LeaseId),
            cancellationToken).ConfigureAwait(false);
    }

    public Task<LeaseManifest?> GetManifestAsync(Guid leaseId, CancellationToken cancellationToken)
    {
        ValidateGuid(leaseId, nameof(leaseId));
        return ReadAsync<LeaseManifest>(GetLeaseFilePath(leaseId, ManifestFileName), cancellationToken);
    }

    public Task<LeaseRuntimeState?> GetStateAsync(Guid leaseId, CancellationToken cancellationToken)
    {
        ValidateGuid(leaseId, nameof(leaseId));
        return ReadAsync<LeaseRuntimeState>(GetLeaseFilePath(leaseId, StateFileName), cancellationToken);
    }

    public async Task SaveStateAsync(LeaseRuntimeState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(state);
        ValidateGuid(state.LeaseId, nameof(state.LeaseId));

        await using var storeLock = await AcquireStoreLockAsync(cancellationToken).ConfigureAwait(false);
        var path = GetLeaseFilePath(state.LeaseId, StateFileName);
        var current = await ReadAsync<LeaseRuntimeState>(path, cancellationToken).ConfigureAwait(false)
            ?? throw new FileNotFoundException($"Lease '{state.LeaseId}' does not have a state file.", path);
        if (state.Sequence < current.Sequence ||
            (state.Sequence == current.Sequence && !RuntimeStateMatches(current, state)))
        {
            throw new LeaseStoreConflictException(
                $"Lease '{state.LeaseId}' state sequence {state.Sequence} conflicts with stored sequence {current.Sequence}.");
        }

        if (state.Sequence > current.Sequence)
        {
            await WriteAtomicAsync(path, state, cancellationToken).ConfigureAwait(false);
        }

        if (state.State == LeaseState.Completed)
        {
            var marker = await ReadAsync<ActiveLeaseMarker>(_activeLeasePath, cancellationToken).ConfigureAwait(false);
            if (marker?.LeaseId == state.LeaseId)
            {
                File.Delete(_activeLeasePath);
            }
        }
    }

    public async Task SaveArtifactsAsync(
        Guid leaseId,
        IReadOnlyList<EnforcementArtifact> artifacts,
        CancellationToken cancellationToken)
    {
        ValidateGuid(leaseId, nameof(leaseId));
        ArgumentNullException.ThrowIfNull(artifacts);
        if (artifacts.Any(artifact => string.IsNullOrWhiteSpace(artifact.AdapterId)) ||
            artifacts.Select(artifact => artifact.AdapterId).Distinct(StringComparer.Ordinal).Count() != artifacts.Count)
        {
            throw new InvalidDataException("Enforcement artifact adapter IDs must be non-empty and unique.");
        }

        await using var storeLock = await AcquireStoreLockAsync(cancellationToken).ConfigureAwait(false);
        if (!File.Exists(GetLeaseFilePath(leaseId, ManifestFileName)))
        {
            throw new FileNotFoundException($"Lease '{leaseId}' does not have a manifest.");
        }

        await WriteAtomicAsync(
            GetLeaseFilePath(leaseId, ArtifactsFileName),
            artifacts,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<EnforcementArtifact>> GetArtifactsAsync(
        Guid leaseId,
        CancellationToken cancellationToken)
    {
        ValidateGuid(leaseId, nameof(leaseId));
        var artifacts = await ReadAsync<EnforcementArtifact[]>(
            GetLeaseFilePath(leaseId, ArtifactsFileName),
            cancellationToken).ConfigureAwait(false);
        return artifacts ?? Array.Empty<EnforcementArtifact>();
    }

    private async Task<Guid?> GetActiveLeaseIdCoreAsync(CancellationToken cancellationToken)
    {
        var marker = await ReadAsync<ActiveLeaseMarker>(_activeLeasePath, cancellationToken).ConfigureAwait(false);
        if (marker is null)
        {
            return null;
        }

        ValidateGuid(marker.LeaseId, "active lease marker");
        var state = await ReadAsync<LeaseRuntimeState>(
            GetLeaseFilePath(marker.LeaseId, StateFileName),
            cancellationToken).ConfigureAwait(false);
        if (state?.State == LeaseState.Completed)
        {
            File.Delete(_activeLeasePath);
            return null;
        }

        return marker.LeaseId;
    }

    private async Task<FileStream> AcquireStoreLockAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
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
            catch (IOException)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(20), cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task<T?> ReadAsync<T>(string path, CancellationToken cancellationToken)
    {
        EnsureUnderRoot(path);
        if (!File.Exists(path))
        {
            return default;
        }

        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 4096,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        try
        {
            return await JsonSerializer.DeserializeAsync<T>(
                stream,
                _serializerOptions,
                cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidDataException($"Capsule file '{path}' contains JSON null.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"Capsule file '{path}' is invalid.", exception);
        }
    }

    private async Task WriteAtomicAsync<T>(string destinationPath, T value, CancellationToken cancellationToken)
    {
        EnsureUnderRoot(destinationPath);
        var directory = Path.GetDirectoryName(destinationPath)
            ?? throw new InvalidOperationException("Capsule destination has no parent directory.");
        Directory.CreateDirectory(directory);
        RejectReparsePoint(directory);
        var temporaryPath = Path.Combine(
            directory,
            $".{Path.GetFileName(destinationPath)}.{Guid.NewGuid():N}.tmp");
        EnsureUnderRoot(temporaryPath);

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
                await JsonSerializer.SerializeAsync(
                    stream,
                    value,
                    _serializerOptions,
                    cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            if (File.Exists(destinationPath))
            {
                File.Replace(temporaryPath, destinationPath, destinationBackupFileName: null);
            }
            else
            {
                File.Move(temporaryPath, destinationPath);
            }
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private string GetPreparationPath(Guid preparationId) => ResolveUnderRoot(
        "preparations",
        $"{preparationId:N}.json");

    private string GetLeasePath(Guid leaseId) => ResolveUnderRoot("leases", leaseId.ToString("N"));

    private string GetLeaseFilePath(Guid leaseId, string fileName) => ResolveUnderRoot(
        "leases",
        leaseId.ToString("N"),
        fileName);

    private string ResolveUnderRoot(params string[] segments)
    {
        var path = Path.GetFullPath(Path.Combine([RootPath, .. segments]));
        EnsureUnderRoot(path);
        return path;
    }

    private void EnsureUnderRoot(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (!fullPath.StartsWith(_rootPrefix, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(fullPath, RootPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"Capsule path '{fullPath}' escapes the fixed root.");
        }
    }

    private static void RejectReparsePoint(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException($"Capsule path '{path}' must not be a reparse point.");
        }
    }

    private static void ValidateGuid(Guid value, string parameterName)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("A non-empty GUID is required.", parameterName);
        }
    }

    private static bool ManifestIdentityMatches(LeaseManifest left, LeaseManifest right) =>
        left.LeaseId == right.LeaseId &&
        left.PreparationId == right.PreparationId &&
        left.CommitRequestId == right.CommitRequestId &&
        string.Equals(left.CommitRequestFingerprint, right.CommitRequestFingerprint, StringComparison.Ordinal) &&
        string.Equals(left.RuleHash, right.RuleHash, StringComparison.Ordinal) &&
        left.ExpiresAtUtc == right.ExpiresAtUtc;

    private static bool RuntimeStateMatches(LeaseRuntimeState left, LeaseRuntimeState right) =>
        left.LeaseId == right.LeaseId &&
        left.State == right.State &&
        left.Sequence == right.Sequence &&
        left.UpdatedAtUtc == right.UpdatedAtUtc &&
        left.LastHeartbeatUtc == right.LastHeartbeatUtc &&
        left.Health == right.Health &&
        left.AppInstallState == right.AppInstallState &&
        left.RuntimeInstallIntent == right.RuntimeInstallIntent &&
        left.RuntimeInstallState == right.RuntimeInstallState &&
        left.WorkerHandoffCompleted == right.WorkerHandoffCompleted &&
        string.Equals(left.LastErrorCode, right.LastErrorCode, StringComparison.Ordinal);

    private sealed record ActiveLeaseMarker(Guid LeaseId);
}
