using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using DistractionFirewall.Enforcement.Windows.Installation;
using DistractionFirewall.Runtime.Windows;

[assembly: InternalsVisibleTo("DistractionFirewall.LeaseLifecycleTests")]

namespace DistractionFirewall.Finalizer;

internal enum CleanupFailureStage
{
    ResolveInstalledPaths,
    VerifyExecutionIdentity,
    VerifyInactiveLease,
    ResolveProductIdentity,
    CreateCleanupBackends,
    RemoveOwnedInstallationResources,
}

internal sealed record CleanupFailureExceptionDescriptor(
    string Type,
    string HResult);

internal sealed record CleanupFailureDiagnosticDocument
{
    public const int CurrentSchemaVersion = 1;

    public required int SchemaVersion { get; init; }

    public required DateTimeOffset OccurredAtUtc { get; init; }

    public required string Operation { get; init; }

    public required CleanupFailureStage Stage { get; init; }

    public required string? Backend { get; init; }

    public required string? BackendOperation { get; init; }

    public required IReadOnlyList<CleanupFailureExceptionDescriptor> Exceptions { get; init; }
}

internal static class CleanupFailureDiagnostic
{
    public const string FileName = "cleanup-failure.json";
    private const int MaximumExceptionDepth = 8;
    private const string CleanupOperation = "runtime-installation-cleanup";
    private static readonly JsonSerializerOptions SerializerOptions = CreateSerializerOptions();

    public static CleanupFailureDiagnosticDocument Create(
        CleanupFailureStage stage,
        Exception exception,
        DateTimeOffset? occurredAtUtc = null)
    {
        ArgumentNullException.ThrowIfNull(exception);
        var cleanupException = FindCleanupException(exception);
        return new CleanupFailureDiagnosticDocument
        {
            SchemaVersion = CleanupFailureDiagnosticDocument.CurrentSchemaVersion,
            OccurredAtUtc = (occurredAtUtc ?? DateTimeOffset.UtcNow).ToUniversalTime(),
            Operation = CleanupOperation,
            Stage = stage,
            Backend = MapBackend(cleanupException?.BackendId),
            BackendOperation = MapBackendOperation(cleanupException?.Operation),
            Exceptions = DescribeExceptions(exception),
        };
    }

    public static string FormatConsoleSummary(CleanupFailureDiagnosticDocument diagnostic)
    {
        ArgumentNullException.ThrowIfNull(diagnostic);
        var root = diagnostic.Exceptions.Count == 0
            ? new CleanupFailureExceptionDescriptor("UnknownException", "0x00000000")
            : diagnostic.Exceptions[0];
        var backend = diagnostic.Backend is null
            ? string.Empty
            : $"; backend={diagnostic.Backend}; backend_operation={diagnostic.BackendOperation}";
        return $"stage={FormatStage(diagnostic.Stage)}; type={root.Type}; hresult={root.HResult}{backend}";
    }

    public static bool TryWrite(
        RuntimePaths paths,
        CleanupFailureDiagnosticDocument diagnostic)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(paths);
            ArgumentNullException.ThrowIfNull(diagnostic);
            var destination = ResolveSafeDiagnosticPath(paths);
            var temporaryPath = Path.Combine(
                paths.DataRoot,
                $".{FileName}.{Guid.NewGuid():N}.tmp");
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
                    JsonSerializer.Serialize(stream, diagnostic, SerializerOptions);
                    stream.Flush(flushToDisk: true);
                }

                RejectReparsePointOrDirectory(destination);
                File.Move(temporaryPath, destination, overwrite: true);
                return true;
            }
            finally
            {
                TryDeleteTemporaryFile(temporaryPath);
            }
        }
        catch
        {
            // Diagnostics are best effort and must never replace the cleanup failure.
            return false;
        }
    }

    public static bool TryDelete(RuntimePaths paths)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(paths);
            var path = ResolveSafeDiagnosticPath(paths);
            RejectReparsePointOrDirectory(path);
            if (File.Exists(path))
            {
                File.Delete(path);
            }

            return true;
        }
        catch
        {
            // A stale diagnostic must not mask the authoritative uninstall result.
            return false;
        }
    }

    private static List<CleanupFailureExceptionDescriptor> DescribeExceptions(
        Exception exception)
    {
        var descriptors = new List<CleanupFailureExceptionDescriptor>(MaximumExceptionDepth);
        Exception? current = exception;
        while (current is not null && descriptors.Count < MaximumExceptionDepth)
        {
            descriptors.Add(new CleanupFailureExceptionDescriptor(
                current.GetType().FullName ?? current.GetType().Name,
                $"0x{unchecked((uint)current.HResult):X8}"));
            current = current.InnerException;
        }

        return descriptors;
    }

    private static WindowsInstallationCleanupException? FindCleanupException(Exception exception)
    {
        Exception? current = exception;
        for (var depth = 0; current is not null && depth < MaximumExceptionDepth; depth++)
        {
            if (current is WindowsInstallationCleanupException cleanupException)
            {
                return cleanupException;
            }

            current = current.InnerException;
        }

        return null;
    }

    private static string? MapBackend(string? backendId) => backendId switch
    {
        "windows-wfp-infrastructure" => "windows-wfp-infrastructure",
        "windows-task-scheduler-infrastructure" => "windows-task-scheduler-infrastructure",
        _ => null,
    };

    private static string? MapBackendOperation(string? operation) => operation switch
    {
        "preflight validation" => "preflight-validation",
        "compare-and-delete" => "compare-and-delete",
        _ => null,
    };

    private static string ResolveSafeDiagnosticPath(RuntimePaths paths)
    {
        if (!Directory.Exists(paths.DataRoot))
        {
            throw new DirectoryNotFoundException(
                "The protected Runtime data root is unavailable for cleanup diagnostics.");
        }

        RejectReparseAncestors(paths.ProgramDataRoot, paths.DataRoot);
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(paths.DataRoot));
        var path = Path.GetFullPath(Path.Combine(root, FileName));
        if (!string.Equals(
                Path.GetDirectoryName(path),
                root,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The cleanup diagnostic path escaped the protected Runtime data root.");
        }

        return path;
    }

    private static void RejectReparseAncestors(string trustedRootPath, string dataRootPath)
    {
        var trustedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(trustedRootPath));
        var dataRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(dataRootPath));
        var trustedPrefix = trustedRoot + Path.DirectorySeparatorChar;
        if (!dataRoot.StartsWith(trustedPrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The cleanup diagnostic root escaped the Runtime ProgramData boundary.");
        }

        var current = new DirectoryInfo(dataRoot);
        while (!string.Equals(current.FullName, trustedRoot, StringComparison.OrdinalIgnoreCase))
        {
            if (!current.Exists)
            {
                throw new DirectoryNotFoundException(
                    "A protected Runtime diagnostic ancestor is unavailable.");
            }

            RejectReparsePoint(current.FullName);
            current = current.Parent
                ?? throw new InvalidOperationException(
                    "The cleanup diagnostic root escaped the Runtime ProgramData boundary.");
        }
    }

    private static void RejectReparsePointOrDirectory(string path)
    {
        FileAttributes attributes;
        try
        {
            attributes = File.GetAttributes(path);
        }
        catch (FileNotFoundException)
        {
            return;
        }
        catch (DirectoryNotFoundException)
        {
            return;
        }

        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException("The cleanup diagnostic path must not be a reparse point.");
        }

        if ((attributes & FileAttributes.Directory) != 0)
        {
            throw new IOException("The cleanup diagnostic path is occupied by a directory.");
        }
    }

    private static void RejectReparsePoint(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException("The cleanup diagnostic path must not be a reparse point.");
        }
    }

    private static void TryDeleteTemporaryFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Preserve the original diagnostic write result.
        }
    }

    private static string FormatStage(CleanupFailureStage stage) => stage switch
    {
        CleanupFailureStage.ResolveInstalledPaths => "resolve-installed-paths",
        CleanupFailureStage.VerifyExecutionIdentity => "verify-execution-identity",
        CleanupFailureStage.VerifyInactiveLease => "verify-inactive-lease",
        CleanupFailureStage.ResolveProductIdentity => "resolve-product-identity",
        CleanupFailureStage.CreateCleanupBackends => "create-cleanup-backends",
        CleanupFailureStage.RemoveOwnedInstallationResources =>
            "remove-owned-installation-resources",
        _ => "unknown",
    };

    private static JsonSerializerOptions CreateSerializerOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            WriteIndented = true,
        };
        // The live-validation reader and the persisted diagnostic schema use
        // kebab-case stage values. Keep property names snake_case, but do not
        // silently apply that policy to enum values as well.
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.KebabCaseLower));
        return options;
    }
}
