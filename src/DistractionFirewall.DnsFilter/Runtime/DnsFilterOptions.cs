using System.Globalization;
using System.Net;

namespace DistractionFirewall.DnsFilter.Runtime;

public sealed class DnsFilterOptions
{
    public const int ReadyTokenByteLength = 32;
    public static readonly TimeSpan MaximumLeaseDuration = TimeSpan.FromHours(12);
    public static readonly TimeSpan MinimumRemainingLeaseDuration = TimeSpan.FromSeconds(1);

    private readonly byte[] _readyToken;

    private DnsFilterOptions(
        Guid leaseId,
        DateTimeOffset leaseExpiresUtc,
        string targetSnapshotPath,
        string observationStorePath,
        IEnumerable<IPEndPoint> upstreams,
        byte[] readyToken)
    {
        LeaseId = leaseId;
        LeaseExpiresUtc = leaseExpiresUtc;
        TargetSnapshotPath = targetSnapshotPath;
        ObservationStorePath = observationStorePath;
        Upstreams = upstreams.ToArray();
        _readyToken = readyToken.ToArray();
    }

    public Guid LeaseId { get; }

    public DateTimeOffset LeaseExpiresUtc { get; }

    public string TargetSnapshotPath { get; }

    public string ObservationStorePath { get; }

    public IReadOnlyList<IPEndPoint> Upstreams { get; }

    public ReadOnlyMemory<byte> ReadyToken => _readyToken;

    public static DnsFilterOptions Parse(string[] args) => Parse(args, TimeProvider.System);

    public static DnsFilterOptions Parse(string[] args, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(timeProvider);
        if (args.Length == 0 || !string.Equals(args[0], "dns-filter", StringComparison.Ordinal))
        {
            throw new ArgumentException("The production command must begin with 'dns-filter'.", nameof(args));
        }

        Guid? leaseId = null;
        DateTimeOffset? leaseExpiresUtc = null;
        string? targetSnapshotPath = null;
        string? observationStorePath = null;
        byte[]? readyToken = null;
        var upstreams = new List<IPEndPoint>();
        var singletonOptions = new HashSet<string>(StringComparer.Ordinal);

        for (var index = 1; index < args.Length; index++)
        {
            var option = args[index];
            switch (option)
            {
                case "--lease-id":
                    RequireSingleton(singletonOptions, option);
                    var leaseIdText = ReadValue(args, ref index, option);
                    if (!Guid.TryParseExact(leaseIdText, "D", out var parsedLeaseId) || parsedLeaseId == Guid.Empty)
                    {
                        throw new ArgumentException("--lease-id must be a non-empty GUID in D format.", nameof(args));
                    }

                    leaseId = parsedLeaseId;
                    break;
                case "--lease-expires-utc":
                    RequireSingleton(singletonOptions, option);
                    var expiresText = ReadValue(args, ref index, option);
                    if (!DateTimeOffset.TryParseExact(
                            expiresText,
                            "O",
                            CultureInfo.InvariantCulture,
                            DateTimeStyles.None,
                            out var parsedExpiration) ||
                        parsedExpiration.Offset != TimeSpan.Zero)
                    {
                        throw new ArgumentException(
                            "--lease-expires-utc must be an O-format timestamp with a zero UTC offset.",
                            nameof(args));
                    }

                    leaseExpiresUtc = parsedExpiration;
                    break;
                case "--target-snapshot":
                    RequireSingleton(singletonOptions, option);
                    targetSnapshotPath = NormalizeDataPath(ReadValue(args, ref index, option), option);
                    break;
                case "--observation-store":
                    RequireSingleton(singletonOptions, option);
                    observationStorePath = NormalizeDataPath(ReadValue(args, ref index, option), option);
                    break;
                case "--ready-token":
                    RequireSingleton(singletonOptions, option);
                    readyToken = ParseReadyToken(ReadValue(args, ref index, option));
                    break;
                case "--upstream":
                    var upstream = ParseUpstream(ReadValue(args, ref index, option));
                    if (upstreams.Contains(upstream))
                    {
                        throw new ArgumentException("--upstream values must be unique.", nameof(args));
                    }

                    upstreams.Add(upstream);
                    break;
                default:
                    throw new ArgumentException("The command contains an unsupported production option.", nameof(args));
            }
        }

        if (leaseId is null ||
            leaseExpiresUtc is null ||
            targetSnapshotPath is null ||
            observationStorePath is null ||
            readyToken is null ||
            upstreams.Count == 0)
        {
            throw new ArgumentException("The command is missing one or more required production options.", nameof(args));
        }

        var remaining = leaseExpiresUtc.Value - timeProvider.GetUtcNow();
        if (remaining < MinimumRemainingLeaseDuration || remaining > MaximumLeaseDuration)
        {
            throw new ArgumentException(
                "--lease-expires-utc must be at least one second and no more than twelve hours in the future.",
                nameof(args));
        }

        return new DnsFilterOptions(
            leaseId.Value,
            leaseExpiresUtc.Value,
            targetSnapshotPath,
            observationStorePath,
            upstreams,
            readyToken);
    }

    private static void RequireSingleton(HashSet<string> seen, string option)
    {
        if (!seen.Add(option))
        {
            throw new ArgumentException($"{option} may only be supplied once.");
        }
    }

    private static string ReadValue(string[] args, ref int index, string option)
    {
        if (++index >= args.Length || args[index].StartsWith("--", StringComparison.Ordinal))
        {
            throw new ArgumentException($"{option} requires a value.", nameof(args));
        }

        return args[index];
    }

    private static string NormalizeDataPath(string value, string option)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            !Path.IsPathFullyQualified(value) ||
            value.Contains('%', StringComparison.Ordinal) ||
            value.Any(char.IsControl) ||
            value.Contains('"', StringComparison.Ordinal))
        {
            throw new ArgumentException($"{option} must be a literal, fully-qualified path.");
        }

        var fullPath = Path.GetFullPath(value);
        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrEmpty(root) ||
            string.Equals(
                Path.TrimEndingDirectorySeparator(fullPath),
                Path.TrimEndingDirectorySeparator(root),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException($"{option} cannot name a file-system root.");
        }

        return fullPath;
    }

    private static byte[] ParseReadyToken(string value)
    {
        if (value.Length != ReadyTokenByteLength * 2 ||
            value.Any(character => character is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
        {
            throw new ArgumentException(
                "--ready-token must be 32 bytes encoded as 64 lower-case hexadecimal characters.");
        }

        return Convert.FromHexString(value);
    }

    private static IPEndPoint ParseUpstream(string value)
    {
        if (!IPAddress.TryParse(value, out var address) ||
            !string.Equals(address.ToString(), value, StringComparison.OrdinalIgnoreCase) ||
            IsDisallowedUpstream(address))
        {
            throw new ArgumentException("--upstream must be a non-loopback unicast IP literal.");
        }

        return new IPEndPoint(address, 53);
    }

    private static bool IsDisallowedUpstream(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) ||
            address.Equals(IPAddress.Any) ||
            address.Equals(IPAddress.IPv6Any) ||
            address.Equals(IPAddress.None) ||
            address.Equals(IPAddress.IPv6None) ||
            address.IsIPv6Multicast)
        {
            return true;
        }

        var bytes = address.GetAddressBytes();
        return address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
            (bytes[0] is >= 224 and <= 239 || bytes.All(value => value == byte.MaxValue));
    }
}
