using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;

namespace DistractionFirewall.Runtime.Windows;

public sealed record RuntimeSettings
{
    public const int CurrentSchemaVersion = 1;

    public required int SchemaVersion { get; init; }

    public required string ProductInstanceId { get; init; }

    public required IReadOnlyList<string> OwnerSids { get; init; }
}

public sealed record RuntimeInstallerSeed(string OwnerSid, string ProductInstanceId);

public interface IRuntimeInstallerSeedSource
{
    RuntimeInstallerSeed ReadRequired();
}

public sealed class RegistryRuntimeInstallerSeedSource : IRuntimeInstallerSeedSource
{
    public const string RegistryPath = @"SOFTWARE\Motoki0705\DistractionFirewall\Runtime";
    private const string OwnerSidValueName = "OwnerSid";
    private const string ProductInstanceIdValueName = "ProductInstanceId";

    public RuntimeInstallerSeed ReadRequired()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The installer seed registry requires Windows.");
        }

        using var localMachine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = localMachine.OpenSubKey(RegistryPath, writable: false)
            ?? throw new InvalidDataException(
                $"Installer registry seed 'HKLM\\{RegistryPath}' is missing.");
        return new RuntimeInstallerSeed(
            ReadRequiredString(key, OwnerSidValueName),
            ReadRequiredString(key, ProductInstanceIdValueName));
    }

    private static string ReadRequiredString(RegistryKey key, string valueName)
    {
        if (key.GetValueKind(valueName) != RegistryValueKind.String ||
            key.GetValue(
                valueName,
                defaultValue: null,
                RegistryValueOptions.DoNotExpandEnvironmentNames) is not string value ||
            string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidDataException(
                $"Installer registry value '{valueName}' must be a non-empty REG_SZ.");
        }

        return value;
    }
}

public static class RuntimeSettingsLoader
{
    private const int MaximumSettingsBytes = 64 * 1024;
    private static readonly JsonSerializerOptions SerializerOptions = CreateSerializerOptions();

    public static async Task<RuntimeSettings> LoadOrBootstrapRequiredAsync(
        RuntimePaths paths,
        IRuntimeInstallerSeedSource installerSeedSource,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(paths);
        ArgumentNullException.ThrowIfNull(installerSeedSource);
        if (!File.Exists(paths.SettingsPath))
        {
            var seed = installerSeedSource.ReadRequired();
            var settings = Validate(new RuntimeSettings
            {
                SchemaVersion = RuntimeSettings.CurrentSchemaVersion,
                ProductInstanceId = seed.ProductInstanceId,
                OwnerSids = [seed.OwnerSid],
            });
            await WriteAtomicIfMissingAsync(paths, settings, cancellationToken).ConfigureAwait(false);
        }

        RuntimePathResolver.ValidateBootstrappedSettingsFile(paths);
        return await LoadRequiredAsync(paths, cancellationToken).ConfigureAwait(false);
    }

    public static async Task<RuntimeSettings> LoadRequiredAsync(
        RuntimePaths paths,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(paths);
        var path = paths.SettingsPath;
        if (!File.Exists(path))
        {
            throw new FileNotFoundException(
                "Installer-provisioned runtime settings are missing; activation remains fail closed.",
                path);
        }

        var file = new FileInfo(path);
        if (file.Length is <= 0 or > MaximumSettingsBytes)
        {
            throw new InvalidDataException("Runtime settings size is invalid.");
        }

        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 4096,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        RuntimeSettings settings;
        try
        {
            settings = await JsonSerializer.DeserializeAsync<RuntimeSettings>(
                stream,
                SerializerOptions,
                cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidDataException("Runtime settings contain JSON null.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Runtime settings JSON is invalid or contains unknown fields.", exception);
        }

        return Validate(settings);
    }

    public static async Task<string> ResolveInstallationCleanupProductInstanceIdAsync(
        RuntimePaths paths,
        IRuntimeInstallerSeedSource installerSeedSource,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(paths);
        ArgumentNullException.ThrowIfNull(installerSeedSource);
        if (File.Exists(paths.SettingsPath))
        {
            var settings = await LoadRequiredAsync(paths, cancellationToken).ConfigureAwait(false);
            return settings.ProductInstanceId;
        }

        if (Directory.Exists(paths.DataRoot)
            && Directory.EnumerateFileSystemEntries(paths.DataRoot).Any(
                entry => string.Equals(
                    Path.GetFileName(entry),
                    Path.GetFileName(paths.SettingsPath),
                    StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidDataException(
                "The Runtime settings path exists but is not a readable regular file.");
        }

        // A service that never started has no settings.json yet. The installed,
        // 64-bit HKLM seed still binds cleanup to this product's fixed identity.
        // OwnerSid is deliberately not used here: it authorizes activation, not
        // removal of installation-scoped objects by the LocalSystem MSI action.
        var seed = installerSeedSource.ReadRequired();
        if (!string.Equals(
                seed.ProductInstanceId,
                RuntimePaths.ProductInstanceId,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The installer registry seed identifies a different product instance.");
        }

        return RuntimePaths.ProductInstanceId;
    }

    public static RuntimeSettings Validate(RuntimeSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (settings.SchemaVersion != RuntimeSettings.CurrentSchemaVersion)
        {
            throw new InvalidDataException(
                $"Runtime settings schema {settings.SchemaVersion} is not supported.");
        }

        if (!string.Equals(
            settings.ProductInstanceId,
            RuntimePaths.ProductInstanceId,
            StringComparison.Ordinal))
        {
            throw new InvalidDataException("Runtime settings identify a different product instance.");
        }

        if (settings.OwnerSids is null || settings.OwnerSids.Count is < 1 or > 8 ||
            settings.OwnerSids.Any(string.IsNullOrWhiteSpace) ||
            settings.OwnerSids.Distinct(StringComparer.OrdinalIgnoreCase).Count() != settings.OwnerSids.Count)
        {
            throw new InvalidDataException("Runtime settings require one to eight unique owner SIDs.");
        }

        var normalized = settings.OwnerSids.Select(ParseOwnerSid).ToArray();
        return settings with { OwnerSids = normalized };
    }

    private static string ParseOwnerSid(string value)
    {
        SecurityIdentifier sid;
        try
        {
            sid = new SecurityIdentifier(value.Trim());
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException($"Owner SID '{value}' is invalid.", exception);
        }

        WellKnownSidType[] forbidden =
        [
            WellKnownSidType.NullSid,
            WellKnownSidType.WorldSid,
            WellKnownSidType.LocalSid,
            WellKnownSidType.AnonymousSid,
            WellKnownSidType.AuthenticatedUserSid,
            WellKnownSidType.LocalSystemSid,
            WellKnownSidType.LocalServiceSid,
            WellKnownSidType.NetworkServiceSid,
            WellKnownSidType.BuiltinAdministratorsSid,
            WellKnownSidType.BuiltinUsersSid,
            WellKnownSidType.BuiltinGuestsSid,
        ];
        if (forbidden.Any(sid.IsWellKnown))
        {
            throw new InvalidDataException($"Owner SID '{value}' is a broad or service identity.");
        }

        return sid.Value;
    }

    private static async Task WriteAtomicIfMissingAsync(
        RuntimePaths paths,
        RuntimeSettings settings,
        CancellationToken cancellationToken)
    {
        if (!Directory.Exists(paths.DataRoot))
        {
            throw new DirectoryNotFoundException(
                "The installer must create the protected ProgramData runtime root before settings bootstrap.");
        }

        var temporaryPath = Path.Combine(
            paths.DataRoot,
            $".settings.{Guid.NewGuid():N}.tmp");
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
                    settings,
                    SerializerOptions,
                    cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            try
            {
                File.Move(temporaryPath, paths.SettingsPath);
            }
            catch (IOException) when (File.Exists(paths.SettingsPath))
            {
                // A concurrent LocalSystem host won bootstrap. Its file is validated below.
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

    private static JsonSerializerOptions CreateSerializerOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            ReadCommentHandling = JsonCommentHandling.Disallow,
        };
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower));
        return options;
    }
}
