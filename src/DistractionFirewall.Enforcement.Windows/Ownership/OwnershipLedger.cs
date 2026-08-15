using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DistractionFirewall.Enforcement.Windows.Ownership;

internal enum OwnershipMutationPhase
{
    Prepared,
    Applied,
    RestorePending,
    Restored,
    Conflict,
}

internal sealed record OwnershipMutationRecord
{
    public const int CurrentSchemaVersion = 1;

    public required int SchemaVersion { get; init; }

    public required string RecordId { get; init; }

    public required string ProductInstanceId { get; init; }

    public required string AdapterId { get; init; }

    public required Guid LeaseId { get; init; }

    public required string ResourceId { get; init; }

    public required OwnedResourceState OriginalState { get; init; }

    public required OwnedResourceState DesiredState { get; init; }

    public required OwnershipMutationPhase Phase { get; init; }

    public required DateTimeOffset UpdatedAtUtc { get; init; }

    public string? ConflictReason { get; init; }
}

internal interface IOwnershipLedger
{
    Task<OwnershipMutationRecord> PrepareAsync(
        string adapterId,
        Guid leaseId,
        string resourceId,
        OwnedResourceState originalState,
        OwnedResourceState desiredState,
        CancellationToken cancellationToken);

    Task<OwnershipMutationRecord?> GetAsync(
        string recordId,
        CancellationToken cancellationToken);

    Task<OwnershipMutationRecord> SetPhaseAsync(
        string recordId,
        OwnershipMutationPhase phase,
        string? conflictReason,
        CancellationToken cancellationToken);
}

internal sealed class FileOwnershipLedger : IOwnershipLedger, IDisposable
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    private readonly string _rootDirectory;
    private readonly string _productInstanceId;
    private readonly Semaphore _crossProcessSemaphore;
    private bool _disposed;

    public FileOwnershipLedger(string rootDirectory, string productInstanceId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(productInstanceId);

        _rootDirectory = Path.GetFullPath(rootDirectory);
        _productInstanceId = productInstanceId;
        var semaphoreName = "Local\\DistractionFirewall.Ownership." +
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(_rootDirectory)))[..24];
        _crossProcessSemaphore = new Semaphore(1, 1, semaphoreName);
    }

    public async Task<OwnershipMutationRecord> PrepareAsync(
        string adapterId,
        Guid leaseId,
        string resourceId,
        OwnedResourceState originalState,
        OwnedResourceState desiredState,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentException.ThrowIfNullOrWhiteSpace(adapterId);
        ArgumentException.ThrowIfNullOrWhiteSpace(resourceId);
        ArgumentNullException.ThrowIfNull(originalState);
        ArgumentNullException.ThrowIfNull(desiredState);

        var recordId = CreateRecordId(adapterId, leaseId, resourceId);
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var existing = await ReadWithoutLockAsync(recordId, cancellationToken).ConfigureAwait(false);
            if (existing is not null)
            {
                ValidateRetry(existing, originalState, desiredState);
                return existing;
            }

            var record = new OwnershipMutationRecord
            {
                SchemaVersion = OwnershipMutationRecord.CurrentSchemaVersion,
                RecordId = recordId,
                ProductInstanceId = _productInstanceId,
                AdapterId = adapterId,
                LeaseId = leaseId,
                ResourceId = resourceId,
                OriginalState = originalState,
                DesiredState = desiredState,
                Phase = OwnershipMutationPhase.Prepared,
                UpdatedAtUtc = DateTimeOffset.UtcNow,
            };

            await WriteAtomicWithoutLockAsync(record, cancellationToken).ConfigureAwait(false);
            return record;
        }
        finally
        {
            _crossProcessSemaphore.Release();
        }
    }

    public async Task<OwnershipMutationRecord?> GetAsync(
        string recordId,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentException.ThrowIfNullOrWhiteSpace(recordId);

        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await ReadWithoutLockAsync(recordId, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _crossProcessSemaphore.Release();
        }
    }

    public async Task<OwnershipMutationRecord> SetPhaseAsync(
        string recordId,
        OwnershipMutationPhase phase,
        string? conflictReason,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentException.ThrowIfNullOrWhiteSpace(recordId);

        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var existing = await ReadWithoutLockAsync(recordId, cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidOperationException($"Ownership record '{recordId}' was not found.");
            var updated = existing with
            {
                Phase = phase,
                UpdatedAtUtc = DateTimeOffset.UtcNow,
                ConflictReason = conflictReason,
            };
            await WriteAtomicWithoutLockAsync(updated, cancellationToken).ConfigureAwait(false);
            return updated;
        }
        finally
        {
            _crossProcessSemaphore.Release();
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _crossProcessSemaphore.Dispose();
        _disposed = true;
    }

    internal string GetRecordPath(string recordId)
    {
        return Path.Combine(_rootDirectory, recordId + ".json");
    }

    private static string CreateRecordId(string adapterId, Guid leaseId, string resourceId)
    {
        var input = string.Join('\0', adapterId, leaseId.ToString("N"), resourceId);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static void ValidateRetry(
        OwnershipMutationRecord existing,
        OwnedResourceState originalState,
        OwnedResourceState desiredState)
    {
        if (existing.SchemaVersion != OwnershipMutationRecord.CurrentSchemaVersion
            || !OwnedResourceState.ExactEquals(existing.OriginalState, originalState)
            || !OwnedResourceState.ExactEquals(existing.DesiredState, desiredState))
        {
            throw new OwnershipConflictException(
                existing.ResourceId,
                "The durable ownership record does not match the requested mutation.");
        }
    }

    private async Task EnterAsync(CancellationToken cancellationToken)
    {
        var signaled = await Task.Run(
            () => WaitHandle.WaitAny([_crossProcessSemaphore, cancellationToken.WaitHandle]),
            CancellationToken.None).ConfigureAwait(false);
        if (signaled == 1)
        {
            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    private async Task<OwnershipMutationRecord?> ReadWithoutLockAsync(
        string recordId,
        CancellationToken cancellationToken)
    {
        var path = GetRecordPath(recordId);
        if (!File.Exists(path))
        {
            return null;
        }

        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 4096,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var record = await JsonSerializer.DeserializeAsync<OwnershipMutationRecord>(
            stream,
            SerializerOptions,
            cancellationToken).ConfigureAwait(false);
        if (record is null
            || record.SchemaVersion != OwnershipMutationRecord.CurrentSchemaVersion
            || !string.Equals(record.ProductInstanceId, _productInstanceId, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"Ownership record '{recordId}' is invalid or belongs to another installation.");
        }

        return record;
    }

    private async Task WriteAtomicWithoutLockAsync(
        OwnershipMutationRecord record,
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(_rootDirectory);
        var targetPath = GetRecordPath(record.RecordId);
        var temporaryPath = targetPath + ".tmp." + Guid.NewGuid().ToString("N");
        var backupPath = targetPath + ".bak";

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
                    record,
                    SerializerOptions,
                    cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            if (File.Exists(targetPath))
            {
                File.Replace(temporaryPath, targetPath, backupPath, ignoreMetadataErrors: true);
                File.Delete(backupPath);
            }
            else
            {
                File.Move(temporaryPath, targetPath);
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

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}

internal sealed class OwnershipConflictException : InvalidOperationException
{
    public OwnershipConflictException(string resourceId, string message)
        : base($"Ownership conflict for '{resourceId}': {message}")
    {
        ResourceId = resourceId;
    }

    public string ResourceId { get; }
}
