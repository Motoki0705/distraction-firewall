using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using DistractionFirewall.Enforcement.Windows.Mutation;
using DistractionFirewall.Enforcement.Windows.Ownership;
using Microsoft.Win32;

namespace DistractionFirewall.Enforcement.Windows.Browser;

internal readonly record struct RegistryPolicyValueId(string KeyPath, string ValueName)
{
    private sealed record SerializedId(string KeyPath, string ValueName);

    public override string ToString()
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(new SerializedId(KeyPath, ValueName));
        return "registry64:" + Convert.ToBase64String(json)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    public static RegistryPolicyValueId Parse(string resourceId)
    {
        const string prefix = "registry64:";
        if (!resourceId.StartsWith(prefix, StringComparison.Ordinal))
        {
            throw new FormatException("The resource identifier is not an HKLM Registry64 value.");
        }

        var encoded = resourceId[prefix.Length..]
            .Replace('-', '+')
            .Replace('_', '/');
        encoded = encoded.PadRight((encoded.Length + 3) / 4 * 4, '=');
        var serialized = JsonSerializer.Deserialize<SerializedId>(Convert.FromBase64String(encoded))
            ?? throw new FormatException("The registry resource identifier is invalid.");
        return new RegistryPolicyValueId(serialized.KeyPath, serialized.ValueName);
    }
}

internal static class RegistryPolicyValueCodec
{
    public const string StringContentType = "registry/reg_sz";
    public const string DWordContentType = "registry/reg_dword";

    public static OwnedResourceState String(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return OwnedResourceState.Present(StringContentType, Encoding.UTF8.GetBytes(value));
    }

    public static OwnedResourceState DWord(int value)
    {
        var bytes = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(bytes, value);
        return OwnedResourceState.Present(DWordContentType, bytes);
    }

    public static string DecodeString(OwnedResourceState state)
    {
        if (!state.Exists || !string.Equals(state.ContentType, StringContentType, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The registry value is not REG_SZ.");
        }

        return Encoding.UTF8.GetString(state.Data);
    }

    public static int DecodeDWord(OwnedResourceState state)
    {
        if (!state.Exists
            || !string.Equals(state.ContentType, DWordContentType, StringComparison.Ordinal)
            || state.Data.Length != sizeof(int))
        {
            throw new InvalidDataException("The registry value is not REG_DWORD.");
        }

        return BinaryPrimitives.ReadInt32LittleEndian(state.Data);
    }

    public static OwnedResourceState FromRegistryValue(RegistryValueKind kind, object value)
    {
        return kind switch
        {
            RegistryValueKind.String when value is string text => String(text),
            RegistryValueKind.DWord when value is int number => DWord(number),
            _ => OwnedResourceState.Present(
                "registry/" + kind.ToString().ToLowerInvariant(),
                JsonSerializer.SerializeToUtf8Bytes(value, value.GetType())),
        };
    }
}

internal interface IRegistryPolicyStore : ICompareExchangeResourceStore
{
    RegistryView View { get; }

    ValueTask<IReadOnlyDictionary<string, OwnedResourceState>> ReadKeyValuesAsync(
        string keyPath,
        CancellationToken cancellationToken);
}

internal sealed class WindowsRegistryPolicyStore : IRegistryPolicyStore
{
    private readonly WindowsMutationGate _mutationGate;

    public WindowsRegistryPolicyStore(WindowsMutationGate mutationGate)
    {
        _mutationGate = mutationGate ?? throw new ArgumentNullException(nameof(mutationGate));
    }

    public RegistryView View => RegistryView.Registry64;

    public ValueTask<OwnedResourceState> ReadAsync(
        string resourceId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var id = RegistryPolicyValueId.Parse(resourceId);
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, View);
        using var key = baseKey.OpenSubKey(id.KeyPath, writable: false);
        if (key is null || !key.GetValueNames().Contains(id.ValueName, StringComparer.Ordinal))
        {
            return ValueTask.FromResult(OwnedResourceState.Missing);
        }

        var value = key.GetValue(id.ValueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames)
            ?? throw new InvalidDataException($"Registry value '{id.KeyPath}\\{id.ValueName}' has no readable data.");
        return ValueTask.FromResult(
            RegistryPolicyValueCodec.FromRegistryValue(key.GetValueKind(id.ValueName), value));
    }

    public bool StatesEqual(OwnedResourceState left, OwnedResourceState right)
    {
        return OwnedResourceState.ExactEquals(left, right);
    }

    public async ValueTask<bool> TryWriteAsync(
        string resourceId,
        OwnedResourceState expected,
        OwnedResourceState replacement,
        CancellationToken cancellationToken)
    {
        _mutationGate.Demand();
        cancellationToken.ThrowIfCancellationRequested();

        var current = await ReadAsync(resourceId, cancellationToken).ConfigureAwait(false);
        if (!StatesEqual(current, expected))
        {
            return false;
        }

        var id = RegistryPolicyValueId.Parse(resourceId);
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, View);
        if (replacement.Exists)
        {
            using var key = baseKey.CreateSubKey(id.KeyPath, writable: true)
                ?? throw new UnauthorizedAccessException($"Unable to create or open HKLM\\{id.KeyPath}.");
            switch (replacement.ContentType)
            {
                case RegistryPolicyValueCodec.StringContentType:
                    key.SetValue(id.ValueName, RegistryPolicyValueCodec.DecodeString(replacement), RegistryValueKind.String);
                    break;
                case RegistryPolicyValueCodec.DWordContentType:
                    key.SetValue(id.ValueName, RegistryPolicyValueCodec.DecodeDWord(replacement), RegistryValueKind.DWord);
                    break;
                default:
                    throw new InvalidOperationException(
                        $"Writing registry content type '{replacement.ContentType}' is not supported.");
            }

            key.Flush();
        }
        else
        {
            using var key = baseKey.OpenSubKey(id.KeyPath, writable: true);
            key?.DeleteValue(id.ValueName, throwOnMissingValue: false);
            key?.Flush();
        }

        var verified = await ReadAsync(resourceId, cancellationToken).ConfigureAwait(false);
        return StatesEqual(verified, replacement);
    }

    public ValueTask<IReadOnlyDictionary<string, OwnedResourceState>> ReadKeyValuesAsync(
        string keyPath,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, View);
        using var key = baseKey.OpenSubKey(keyPath, writable: false);
        if (key is null)
        {
            return ValueTask.FromResult<IReadOnlyDictionary<string, OwnedResourceState>>(
                new Dictionary<string, OwnedResourceState>(StringComparer.Ordinal));
        }

        var result = new Dictionary<string, OwnedResourceState>(StringComparer.Ordinal);
        foreach (var valueName in key.GetValueNames())
        {
            var value = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            if (value is not null)
            {
                result[valueName] = RegistryPolicyValueCodec.FromRegistryValue(
                    key.GetValueKind(valueName),
                    value);
            }
        }

        return ValueTask.FromResult<IReadOnlyDictionary<string, OwnedResourceState>>(result);
    }
}
