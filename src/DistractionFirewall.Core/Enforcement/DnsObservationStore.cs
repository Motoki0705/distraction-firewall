using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DistractionFirewall.Core.Enforcement;

public sealed record DnsObservationAppendContext(
    Guid LeaseId,
    DateTimeOffset LeaseExpiresAtUtc,
    int MaximumTtlSeconds);

public sealed record DnsObservedAddressCandidate(
    IPAddress Address,
    uint TtlSeconds);

public sealed record ActiveDnsObservedAddress(
    Guid LeaseId,
    long Sequence,
    IPAddress Address,
    DateTimeOffset ExpiresAtUtc);

public interface IDnsObservedAddressStore
{
    ValueTask AppendAsync(
        DnsObservationAppendContext context,
        IReadOnlyCollection<DnsObservedAddressCandidate> addresses,
        CancellationToken cancellationToken);

    ValueTask<IReadOnlyList<ActiveDnsObservedAddress>> ReadActiveAsync(
        Guid leaseId,
        CancellationToken cancellationToken);
}

public sealed class FileDnsObservedAddressStore : IDnsObservedAddressStore
{
    public const int CurrentSchemaVersion = 1;
    public const int MaximumObservationCount = 4096;
    private const long MaximumDocumentBytes = 2 * 1024 * 1024;
    private const int LockRetryCount = 400;
    private static readonly JsonSerializerOptions SerializerOptions = CreateSerializerOptions();
    private readonly string _protectedDirectoryPath;
    private readonly string _storePath;
    private readonly string _lockPath;
    private readonly TimeProvider _timeProvider;

    public FileDnsObservedAddressStore(
        string protectedDirectoryPath,
        string storePath,
        TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(protectedDirectoryPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(storePath);
        _protectedDirectoryPath = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(protectedDirectoryPath));
        _storePath = Path.GetFullPath(storePath);
        _timeProvider = timeProvider ?? TimeProvider.System;
        if (!Directory.Exists(_protectedDirectoryPath))
        {
            throw new DirectoryNotFoundException(
                $"The protected observation directory '{_protectedDirectoryPath}' does not exist.");
        }

        var parent = Path.TrimEndingDirectorySeparator(
            Path.GetDirectoryName(_storePath)
            ?? throw new ArgumentException("The observation store path has no parent directory.", nameof(storePath)));
        if (!PathsEqual(parent, _protectedDirectoryPath))
        {
            throw new ArgumentException(
                "The observation store must be a direct child of the protected directory.",
                nameof(storePath));
        }

        var fileName = Path.GetFileName(_storePath);
        if (string.IsNullOrWhiteSpace(fileName) || fileName is "." or "..")
        {
            throw new ArgumentException("The observation store file name is invalid.", nameof(storePath));
        }

        _lockPath = Path.Combine(_protectedDirectoryPath, ".observed-addresses.lock");
        if (PathsEqual(_storePath, _lockPath))
        {
            throw new ArgumentException(
                "The observation store path cannot replace its cross-process lock.",
                nameof(storePath));
        }

        ValidateProtectedPaths();
    }

    public string StorePath => _storePath;

    public async ValueTask EnsureCreatedAsync(CancellationToken cancellationToken)
    {
        await using var processLock = await AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        if (!File.Exists(_storePath))
        {
            await SaveDocumentAsync(ObservationDocument.Empty, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            _ = await LoadDocumentAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public async ValueTask AppendAsync(
        DnsObservationAppendContext context,
        IReadOnlyCollection<DnsObservedAddressCandidate> addresses,
        CancellationToken cancellationToken)
    {
        ValidateContext(context);
        ArgumentNullException.ThrowIfNull(addresses);
        cancellationToken.ThrowIfCancellationRequested();

        var candidates = NormalizeCandidates(addresses);
        await using var processLock = await AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        var document = await LoadDocumentAsync(cancellationToken).ConfigureAwait(false);
        var now = _timeProvider.GetUtcNow().ToUniversalTime();
        var leaseExpiry = context.LeaseExpiresAtUtc.ToUniversalTime();
        var policyExpiry = now.AddSeconds(context.MaximumTtlSeconds);
        var entries = document.Observations
            .Where(entry => entry.ExpiresAtUtc > now && entry.LeaseId == context.LeaseId)
            .Select(entry => entry with
            {
                ExpiresAtUtc = Min(entry.ExpiresAtUtc, Min(leaseExpiry, policyExpiry)),
            })
            .Where(entry => entry.ExpiresAtUtc > now)
            .ToDictionary(entry => entry.Address, StringComparer.Ordinal);
        var nextSequence = entries.Count == 0
            ? 0
            : entries.Values.Max(entry => entry.Sequence);

        if (leaseExpiry > now)
        {
            foreach (var candidate in candidates.OrderBy(item => item.Key, StringComparer.Ordinal))
            {
                if (candidate.Value == 0)
                {
                    continue;
                }

                var ttlSeconds = Math.Min((long)candidate.Value, context.MaximumTtlSeconds);
                var expiresAtUtc = Min(now.AddSeconds(ttlSeconds), leaseExpiry);
                if (expiresAtUtc <= now)
                {
                    continue;
                }

                if (entries.TryGetValue(candidate.Key, out var existing) &&
                    existing.ExpiresAtUtc >= expiresAtUtc)
                {
                    continue;
                }

                entries[candidate.Key] = new ObservationEntry
                {
                    LeaseId = context.LeaseId,
                    Sequence = checked(++nextSequence),
                    Address = candidate.Key,
                    ExpiresAtUtc = expiresAtUtc,
                };
            }
        }

        if (entries.Count > MaximumObservationCount)
        {
            throw new InvalidDataException(
                $"The observation store cannot contain more than {MaximumObservationCount} addresses.");
        }

        var updated = new ObservationDocument
        {
            SchemaVersion = CurrentSchemaVersion,
            Observations = entries.Values
                .OrderBy(entry => entry.Sequence)
                .ThenBy(entry => entry.Address, StringComparer.Ordinal)
                .ToList(),
        };
        await SaveDocumentAsync(updated, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<IReadOnlyList<ActiveDnsObservedAddress>> ReadActiveAsync(
        Guid leaseId,
        CancellationToken cancellationToken)
    {
        if (leaseId == Guid.Empty)
        {
            throw new ArgumentException("A non-empty lease ID is required.", nameof(leaseId));
        }

        await using var processLock = await AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        var document = await LoadDocumentAsync(cancellationToken).ConfigureAwait(false);
        var now = _timeProvider.GetUtcNow().ToUniversalTime();
        var retained = document.Observations
            .Where(entry => entry.ExpiresAtUtc > now)
            .OrderBy(entry => entry.Sequence)
            .ThenBy(entry => entry.Address, StringComparer.Ordinal)
            .ToList();
        if (retained.Count != document.Observations.Count)
        {
            await SaveDocumentAsync(
                document with { Observations = retained },
                cancellationToken).ConfigureAwait(false);
        }

        return retained
            .Where(entry => entry.LeaseId == leaseId)
            .Select(entry => new ActiveDnsObservedAddress(
                entry.LeaseId,
                entry.Sequence,
                IPAddress.Parse(entry.Address),
                entry.ExpiresAtUtc))
            .ToArray();
    }

    public static IPAddress NormalizePublicAddress(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        var normalized = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        if (!IsPublic(normalized))
        {
            throw new ArgumentException(
                "Only publicly routable unicast observation addresses are accepted.",
                nameof(address));
        }

        return new IPAddress(normalized.GetAddressBytes());
    }

    private static Dictionary<string, uint> NormalizeCandidates(
        IReadOnlyCollection<DnsObservedAddressCandidate> addresses)
    {
        if (addresses.Count > MaximumObservationCount)
        {
            throw new ArgumentException(
                $"A single append cannot contain more than {MaximumObservationCount} addresses.",
                nameof(addresses));
        }

        var normalized = new Dictionary<string, uint>(StringComparer.Ordinal);
        foreach (var candidate in addresses)
        {
            ArgumentNullException.ThrowIfNull(candidate);
            var address = NormalizePublicAddress(candidate.Address).ToString();
            if (!normalized.TryGetValue(address, out var ttl) || candidate.TtlSeconds > ttl)
            {
                normalized[address] = candidate.TtlSeconds;
            }
        }

        return normalized;
    }

    private async Task<FileStream> AcquireLockAsync(CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < LockRetryCount; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ValidateProtectedPaths();
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
            catch (IOException) when (attempt + 1 < LockRetryCount)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(25), cancellationToken).ConfigureAwait(false);
            }
        }

        throw new IOException("The cross-process DNS observation store lock is unavailable.");
    }

    private async Task<ObservationDocument> LoadDocumentAsync(CancellationToken cancellationToken)
    {
        ValidateProtectedPaths();
        if (!File.Exists(_storePath))
        {
            return ObservationDocument.Empty;
        }

        await using var stream = new FileStream(
            _storePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 4096,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length > MaximumDocumentBytes)
        {
            throw new InvalidDataException("The DNS observation document exceeds its size limit.");
        }

        ObservationDocument document;
        try
        {
            document = await JsonSerializer.DeserializeAsync<ObservationDocument>(
                stream,
                SerializerOptions,
                cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidDataException("The DNS observation document is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The DNS observation document is invalid.", exception);
        }

        ValidateDocument(document);
        return document;
    }

    private async Task SaveDocumentAsync(
        ObservationDocument document,
        CancellationToken cancellationToken)
    {
        ValidateDocument(document);
        ValidateProtectedPaths();
        var temporaryPath = Path.Combine(
            _protectedDirectoryPath,
            $".{Path.GetFileName(_storePath)}.{Guid.NewGuid():N}.tmp");
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
                    document,
                    SerializerOptions,
                    cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            ValidateProtectedPaths();
            await ReplaceAtomicallyAsync(
                temporaryPath,
                _storePath,
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

    private void ValidateProtectedPaths()
    {
        RejectReparsePoint(_protectedDirectoryPath);
        RejectExistingNonRegularFile(_storePath);
        RejectExistingNonRegularFile(_lockPath);
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

        throw new IOException("The atomic DNS observation document replacement failed.");
    }

    private static void RejectExistingNonRegularFile(string path)
    {
        if (new FileInfo(path).LinkTarget is not null ||
            new DirectoryInfo(path).LinkTarget is not null)
        {
            throw new IOException($"Protected observation path '{path}' is a symbolic link.");
        }

        if (!File.Exists(path) && !Directory.Exists(path))
        {
            return;
        }

        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException($"Protected observation path '{path}' is a reparse point.");
        }

        if ((attributes & FileAttributes.Directory) != 0)
        {
            throw new IOException($"Protected observation file '{path}' is a directory.");
        }
    }

    private static void RejectReparsePoint(string path)
    {
        if (new DirectoryInfo(path).LinkTarget is not null)
        {
            throw new IOException($"Protected observation directory '{path}' is a symbolic link.");
        }

        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException($"Protected observation directory '{path}' is a reparse point.");
        }
    }

    private static void ValidateContext(DnsObservationAppendContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.LeaseId == Guid.Empty ||
            context.LeaseExpiresAtUtc == default ||
            context.MaximumTtlSeconds is < 1 or > 86400)
        {
            throw new ArgumentException("The DNS observation append context is invalid.", nameof(context));
        }
    }

    private static void ValidateDocument(ObservationDocument document)
    {
        if (document.SchemaVersion != CurrentSchemaVersion ||
            document.Observations is null ||
            document.Observations.Count > MaximumObservationCount)
        {
            throw new InvalidDataException("The DNS observation document schema or count is invalid.");
        }

        Guid? leaseId = null;
        var addresses = new HashSet<string>(StringComparer.Ordinal);
        var sequences = new HashSet<long>();
        foreach (var entry in document.Observations)
        {
            if (entry.LeaseId == Guid.Empty || entry.Sequence <= 0 ||
                string.IsNullOrWhiteSpace(entry.Address) || entry.ExpiresAtUtc == default ||
                entry.ExpiresAtUtc.Offset != TimeSpan.Zero ||
                !sequences.Add(entry.Sequence))
            {
                throw new InvalidDataException("A DNS observation entry is invalid.");
            }

            leaseId ??= entry.LeaseId;
            if (leaseId != entry.LeaseId)
            {
                throw new InvalidDataException("A DNS observation document cannot mix leases.");
            }

            if (!IPAddress.TryParse(entry.Address, out var parsed))
            {
                throw new InvalidDataException("A DNS observation address is invalid.");
            }

            IPAddress normalized;
            try
            {
                normalized = NormalizePublicAddress(parsed);
            }
            catch (ArgumentException exception)
            {
                throw new InvalidDataException("A DNS observation address is not public.", exception);
            }

            if (!string.Equals(normalized.ToString(), entry.Address, StringComparison.Ordinal) ||
                !addresses.Add(entry.Address))
            {
                throw new InvalidDataException("A DNS observation address is not canonical or is duplicated.");
            }
        }
    }

    private static bool IsPublic(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            return !IsInRange(bytes, [0], 8) &&
                !IsInRange(bytes, [10], 8) &&
                !IsInRange(bytes, [100, 64], 10) &&
                !IsInRange(bytes, [127], 8) &&
                !IsInRange(bytes, [169, 254], 16) &&
                !IsInRange(bytes, [172, 16], 12) &&
                !IsInRange(bytes, [192, 0, 0], 24) &&
                !IsInRange(bytes, [192, 0, 2], 24) &&
                !IsInRange(bytes, [192, 31, 196], 24) &&
                !IsInRange(bytes, [192, 52, 193], 24) &&
                !IsInRange(bytes, [192, 88, 99], 24) &&
                !IsInRange(bytes, [192, 168], 16) &&
                !IsInRange(bytes, [192, 175, 48], 24) &&
                !IsInRange(bytes, [198, 18], 15) &&
                !IsInRange(bytes, [198, 51, 100], 24) &&
                !IsInRange(bytes, [203, 0, 113], 24) &&
                !IsInRange(bytes, [224], 4) &&
                !IsInRange(bytes, [240], 4);
        }

        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return false;
        }

        var ipv6 = address.GetAddressBytes();
        if (IsInRange(ipv6, new byte[12], 96) ||
            IsInRange(ipv6, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 128) ||
            IsInRange(ipv6, [0x00, 0x64, 0xff, 0x9b, 0x00, 0x01], 48) ||
            IsInRange(ipv6, [0x01, 0x00, 0, 0, 0, 0, 0, 0], 64) ||
            IsInRange(ipv6, [0x20, 0x01, 0x00], 23) ||
            IsInRange(ipv6, [0x20, 0x01, 0x0d, 0xb8], 32) ||
            IsInRange(ipv6, [0x20, 0x02], 16) ||
            IsInRange(ipv6, [0x3f, 0xff, 0x00], 20) ||
            IsInRange(ipv6, [0x5f, 0x00], 16) ||
            IsInRange(ipv6, [0xfc], 7) ||
            IsInRange(ipv6, [0xfe, 0x80], 10) ||
            IsInRange(ipv6, [0xfe, 0xc0], 10) ||
            IsInRange(ipv6, [0xff], 8))
        {
            return false;
        }

        // The well-known NAT64 prefix is useful for blocking a public IPv4
        // destination on IPv6-only networks, but must not smuggle a private IPv4.
        if (IsInRange(
            ipv6,
            [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0],
            96))
        {
            return IsPublic(new IPAddress(ipv6[^4..]));
        }

        return true;
    }

    private static bool IsInRange(byte[] address, byte[] prefix, int prefixLength)
    {
        if (prefixLength < 0 || prefixLength > address.Length * 8 ||
            prefix.Length * 8 < prefixLength)
        {
            return false;
        }

        var wholeBytes = prefixLength / 8;
        for (var index = 0; index < wholeBytes; index++)
        {
            if (address[index] != prefix[index])
            {
                return false;
            }
        }

        var remainingBits = prefixLength % 8;
        if (remainingBits == 0)
        {
            return true;
        }

        var mask = (byte)(0xff << (8 - remainingBits));
        return (address[wholeBytes] & mask) == (prefix[wholeBytes] & mask);
    }

    private static DateTimeOffset Min(DateTimeOffset left, DateTimeOffset right) =>
        left <= right ? left : right;

    private static bool PathsEqual(string left, string right) => string.Equals(
        left,
        right,
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    private static JsonSerializerOptions CreateSerializerOptions() => new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = true,
    };

    private sealed record ObservationDocument
    {
        public static ObservationDocument Empty { get; } = new()
        {
            SchemaVersion = CurrentSchemaVersion,
            Observations = [],
        };

        [JsonRequired]
        public int SchemaVersion { get; init; }

        [JsonRequired]
        public required List<ObservationEntry> Observations { get; init; }
    }

    private sealed record ObservationEntry
    {
        [JsonRequired]
        public Guid LeaseId { get; init; }

        [JsonRequired]
        public long Sequence { get; init; }

        [JsonRequired]
        public required string Address { get; init; }

        [JsonRequired]
        public DateTimeOffset ExpiresAtUtc { get; init; }
    }
}
