using System.Security.Cryptography;

namespace DistractionFirewall.Enforcement.Windows.Ownership;

internal sealed record OwnedResourceState
{
    public required bool Exists { get; init; }

    public required string ContentType { get; init; }

    public required byte[] Data { get; init; }

    public static OwnedResourceState Missing { get; } = new()
    {
        Exists = false,
        ContentType = string.Empty,
        Data = [],
    };

    public static OwnedResourceState Present(string contentType, byte[] data)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(contentType);
        ArgumentNullException.ThrowIfNull(data);

        return new OwnedResourceState
        {
            Exists = true,
            ContentType = contentType,
            Data = data.ToArray(),
        };
    }

    public string ComputeHash()
    {
        using var incrementalHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        incrementalHash.AppendData([Exists ? (byte)1 : (byte)0]);
        incrementalHash.AppendData(System.Text.Encoding.UTF8.GetBytes(ContentType));
        incrementalHash.AppendData([0]);
        incrementalHash.AppendData(Data);
        return Convert.ToHexString(incrementalHash.GetHashAndReset());
    }

    public static bool ExactEquals(OwnedResourceState left, OwnedResourceState right)
    {
        return left.Exists == right.Exists
            && string.Equals(left.ContentType, right.ContentType, StringComparison.Ordinal)
            && left.Data.AsSpan().SequenceEqual(right.Data);
    }
}

internal interface ICompareExchangeResourceStore
{
    ValueTask<OwnedResourceState> ReadAsync(
        string resourceId,
        CancellationToken cancellationToken);

    bool StatesEqual(OwnedResourceState left, OwnedResourceState right);

    ValueTask<bool> TryWriteAsync(
        string resourceId,
        OwnedResourceState expected,
        OwnedResourceState replacement,
        CancellationToken cancellationToken);
}

internal interface IPostWriteVerificationStore
{
    bool ReplacementWasApplied(
        OwnedResourceState actual,
        OwnedResourceState replacement);
}
