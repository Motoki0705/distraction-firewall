using System.Security.Cryptography;
using System.Text;

namespace DistractionFirewall.ActivationService;

public sealed class LeaseNonceService
{
    private const int KeyLength = 32;
    private const string KeyFileName = "activation-hmac.key";
    private readonly byte[] _key;

    public LeaseNonceService(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeyLength)
        {
            throw new ArgumentException($"The nonce key must contain exactly {KeyLength} bytes.", nameof(key));
        }

        _key = key.ToArray();
    }

    public static LeaseNonceService LoadOrCreate(string fixedRootPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fixedRootPath);
        if (!Path.IsPathFullyQualified(fixedRootPath))
        {
            throw new ArgumentException("The nonce key root must be absolute.", nameof(fixedRootPath));
        }

        var root = Path.GetFullPath(fixedRootPath).TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar);
        Directory.CreateDirectory(root);
        var keyPath = Path.GetFullPath(Path.Combine(root, KeyFileName));
        var rootPrefix = root + Path.DirectorySeparatorChar;
        if (!keyPath.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Nonce key path escapes the fixed capsule root.");
        }

        if (File.Exists(keyPath))
        {
            return new LeaseNonceService(ReadKey(keyPath));
        }

        var key = RandomNumberGenerator.GetBytes(KeyLength);
        var temporaryPath = Path.Combine(root, $".{KeyFileName}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: KeyLength,
                FileOptions.WriteThrough))
            {
                stream.Write(key);
                stream.Flush(flushToDisk: true);
            }

            try
            {
                File.Move(temporaryPath, keyPath);
            }
            catch (IOException) when (File.Exists(keyPath))
            {
                CryptographicOperations.ZeroMemory(key);
                return new LeaseNonceService(ReadKey(keyPath));
            }

            return new LeaseNonceService(key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    public Guid GetPreparationId(Guid requestId) => DeriveGuid("preparation-id-v1", requestId);

    public Guid GetLeaseId(Guid commitRequestId) => DeriveGuid("lease-id-v1", commitRequestId);

    public string CreateNonce(Guid requestId, string requestFingerprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestFingerprint);
        var digest = ComputeHmac("nonce-v1", requestId, requestFingerprint);
        return Convert.ToBase64String(digest)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    public static string HashNonce(string nonce)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nonce);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(nonce)));
    }

    public static bool VerifyNonce(string nonce, string expectedHash)
    {
        if (string.IsNullOrWhiteSpace(nonce) || nonce.Length > 512 ||
            string.IsNullOrWhiteSpace(expectedHash))
        {
            return false;
        }

        byte[] expected;
        try
        {
            expected = Convert.FromHexString(expectedHash);
        }
        catch (FormatException)
        {
            return false;
        }

        var actual = SHA256.HashData(Encoding.UTF8.GetBytes(nonce));
        return expected.Length == actual.Length && CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    private Guid DeriveGuid(string domain, Guid requestId)
    {
        if (requestId == Guid.Empty)
        {
            throw new ArgumentException("A non-empty request ID is required.", nameof(requestId));
        }

        var digest = ComputeHmac(domain, requestId, string.Empty);
        return new Guid(digest.AsSpan(0, 16));
    }

    private byte[] ComputeHmac(string domain, Guid requestId, string value)
    {
        var message = Encoding.UTF8.GetBytes($"{domain}\n{requestId:D}\n{value}");
        return HMACSHA256.HashData(_key, message);
    }

    private static byte[] ReadKey(string path)
    {
        var key = File.ReadAllBytes(path);
        if (key.Length != KeyLength)
        {
            throw new InvalidDataException($"Nonce key '{path}' has invalid length {key.Length}.");
        }

        return key;
    }
}
