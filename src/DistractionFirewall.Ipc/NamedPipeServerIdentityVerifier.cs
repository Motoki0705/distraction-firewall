using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace DistractionFirewall.Ipc;

internal sealed record NamedPipeServerProcessIdentity(
    uint ProcessId,
    string UserSid,
    string ServiceCommandLine);

internal sealed record WindowsServiceProcessStatus(
    uint ServiceType,
    uint CurrentState,
    uint ProcessId);

internal sealed record WindowsServiceStatus(
    uint ServiceType,
    uint CurrentState);

internal sealed record WindowsActivationServiceSnapshot(
    WindowsServiceProcessStatus BeforeConfigurationRead,
    WindowsServiceStatus InterrogatedStatus,
    WindowsServiceProcessStatus AfterConfigurationRead,
    string UserSid,
    string CommandLine);

internal interface INamedPipeServerIdentityVerifier
{
    void Verify(SafePipeHandle pipeHandle);
}

internal interface INamedPipeServerIdentityNative
{
    NamedPipeServerProcessIdentity Inspect(SafePipeHandle pipeHandle);
}

internal interface IWindowsActivationServiceIdentityApi
{
    uint GetNamedPipeServerProcessId(SafePipeHandle pipeHandle);

    WindowsActivationServiceSnapshot QueryActivationService();
}

internal interface IActivationServiceImagePolicy
{
    void DemandExpectedAndProtected(string actualServiceCommandLine);
}

internal sealed class WindowsNamedPipeServerIdentityVerifier : INamedPipeServerIdentityVerifier
{
    private const string LocalSystemSid = "S-1-5-18";
    private readonly INamedPipeServerIdentityNative _native;
    private readonly IActivationServiceImagePolicy _imagePolicy;

    internal WindowsNamedPipeServerIdentityVerifier(
        INamedPipeServerIdentityNative native,
        IActivationServiceImagePolicy imagePolicy)
    {
        _native = native ?? throw new ArgumentNullException(nameof(native));
        _imagePolicy = imagePolicy ?? throw new ArgumentNullException(nameof(imagePolicy));
    }

    public static WindowsNamedPipeServerIdentityVerifier CreateDefault()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Activation service identity verification requires Windows.");
        }

        return new WindowsNamedPipeServerIdentityVerifier(
            new WindowsNamedPipeServerIdentityNative(),
            InstalledActivationServiceImagePolicy.CreateDefault());
    }

    public void Verify(SafePipeHandle pipeHandle)
    {
        ArgumentNullException.ThrowIfNull(pipeHandle);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Activation service identity verification requires Windows.");
        }

        if (pipeHandle.IsInvalid || pipeHandle.IsClosed)
        {
            throw new UnauthorizedAccessException(
                "The connected activation pipe did not expose a valid Windows handle.");
        }

        var identity = _native.Inspect(pipeHandle);
        if (!string.Equals(identity.UserSid, LocalSystemSid, StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException(
                $"Activation pipe server process {identity.ProcessId} is not running as LocalSystem.");
        }

        _imagePolicy.DemandExpectedAndProtected(identity.ServiceCommandLine);
    }
}

[SupportedOSPlatform("windows")]
internal sealed class WindowsNamedPipeServerIdentityNative : INamedPipeServerIdentityNative
{
    private const uint ServiceWin32OwnProcess = 0x00000010;
    private const uint ServiceRunning = 0x00000004;
    private readonly IWindowsActivationServiceIdentityApi _api;

    public WindowsNamedPipeServerIdentityNative()
        : this(new WindowsActivationServiceIdentityApi())
    {
    }

    internal WindowsNamedPipeServerIdentityNative(IWindowsActivationServiceIdentityApi api)
    {
        _api = api ?? throw new ArgumentNullException(nameof(api));
    }

    public NamedPipeServerProcessIdentity Inspect(SafePipeHandle pipeHandle)
    {
        ArgumentNullException.ThrowIfNull(pipeHandle);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Windows named-pipe process inspection is unavailable on this platform.");
        }

        if (pipeHandle.IsInvalid || pipeHandle.IsClosed)
        {
            throw new UnauthorizedAccessException(
                "The connected activation pipe did not expose a valid Windows handle.");
        }

        // A standard user cannot reliably open a LocalSystem process or its token.
        // Bind the kernel-reported pipe PID to the fixed SCM service instead. The
        // active interrogation and before/after snapshots close the PID-reuse gap
        // without granting the caller any process or service mutation rights.
        var pipeProcessIdBefore = _api.GetNamedPipeServerProcessId(pipeHandle);
        if (pipeProcessIdBefore == 0)
        {
            throw new UnauthorizedAccessException(
                "The activation pipe reported a zero server process ID.");
        }

        var service = _api.QueryActivationService();
        var pipeProcessIdAfter = _api.GetNamedPipeServerProcessId(pipeHandle);
        if (pipeProcessIdAfter == 0 || pipeProcessIdAfter != pipeProcessIdBefore)
        {
            throw new UnauthorizedAccessException(
                "The activation pipe server process ID changed during identity verification.");
        }

        var before = service.BeforeConfigurationRead;
        var interrogated = service.InterrogatedStatus;
        var after = service.AfterConfigurationRead;
        if (before.ServiceType != ServiceWin32OwnProcess
            || interrogated.ServiceType != ServiceWin32OwnProcess
            || after.ServiceType != ServiceWin32OwnProcess)
        {
            throw new UnauthorizedAccessException(
                "The activation service is not a dedicated Win32 own-process service.");
        }

        if (before.CurrentState != ServiceRunning
            || interrogated.CurrentState != ServiceRunning
            || after.CurrentState != ServiceRunning)
        {
            throw new UnauthorizedAccessException(
                "The activation service was not continuously running during identity verification.");
        }

        if (before.ProcessId == 0
            || before.ProcessId != after.ProcessId
            || before.ProcessId != pipeProcessIdBefore)
        {
            throw new UnauthorizedAccessException(
                "The activation pipe server is not the stable process registered for the activation service.");
        }

        return new NamedPipeServerProcessIdentity(
            pipeProcessIdBefore,
            service.UserSid,
            service.CommandLine);
    }
}

[SupportedOSPlatform("windows")]
internal sealed partial class WindowsActivationServiceIdentityApi
    : IWindowsActivationServiceIdentityApi
{
    private const string ActivationServiceName = "DistractionFirewallActivation";
    private const uint ScManagerConnect = 0x00000001;
    private const uint ServiceQueryConfig = 0x00000001;
    private const uint ServiceQueryStatus = 0x00000004;
    private const uint ServiceInterrogate = 0x00000080;
    private const uint ServiceControlInterrogate = 0x00000004;
    private const int ScStatusProcessInfo = 0;
    private const int ErrorInsufficientBuffer = 122;

    public uint GetNamedPipeServerProcessId(SafePipeHandle pipeHandle)
    {
        if (GetNamedPipeServerProcessIdNative(pipeHandle, out var processId) == 0
            || processId == 0)
        {
            ThrowLastWin32("GetNamedPipeServerProcessId failed.");
        }

        return processId;
    }

    public WindowsActivationServiceSnapshot QueryActivationService()
    {
        var serviceManager = OpenSCManager(
            machineName: null,
            databaseName: null,
            ScManagerConnect);
        if (serviceManager == nint.Zero)
        {
            ThrowLastWin32("OpenSCManagerW failed while authenticating the activation service.");
        }

        try
        {
            var service = OpenService(
                serviceManager,
                ActivationServiceName,
                ServiceQueryConfig | ServiceQueryStatus | ServiceInterrogate);
            if (service == nint.Zero)
            {
                ThrowLastWin32(
                    $"OpenServiceW refused identity queries for '{ActivationServiceName}'.");
            }

            try
            {
                var before = QueryProcessStatus(service);
                var configuration = QueryConfiguration(service);
                var interrogated = Interrogate(service);
                var after = QueryProcessStatus(service);
                return new WindowsActivationServiceSnapshot(
                    before,
                    interrogated,
                    after,
                    ResolveAccountSid(configuration.StartName),
                    configuration.CommandLine);
            }
            finally
            {
                _ = CloseServiceHandle(service);
            }
        }
        finally
        {
            _ = CloseServiceHandle(serviceManager);
        }
    }

    private static WindowsServiceStatus Interrogate(nint service)
    {
        if (ControlService(
                service,
                ServiceControlInterrogate,
                out var status) == 0)
        {
            ThrowLastWin32("SERVICE_CONTROL_INTERROGATE failed for the activation service.");
        }

        return new WindowsServiceStatus(status.ServiceType, status.CurrentState);
    }

    private static WindowsServiceProcessStatus QueryProcessStatus(nint service)
    {
        var bufferLength = checked((uint)Marshal.SizeOf<ServiceStatusProcess>());
        var buffer = Marshal.AllocHGlobal(checked((int)bufferLength));
        try
        {
            if (QueryServiceStatusEx(
                    service,
                    ScStatusProcessInfo,
                    buffer,
                    bufferLength,
                    out var requiredBytes) == 0)
            {
                ThrowLastWin32("QueryServiceStatusEx failed for the activation service.");
            }

            if (requiredBytes > bufferLength)
            {
                throw new InvalidDataException(
                    "QueryServiceStatusEx returned an oversized activation service status.");
            }

            var status = Marshal.PtrToStructure<ServiceStatusProcess>(buffer);
            return new WindowsServiceProcessStatus(
                status.ServiceType,
                status.CurrentState,
                status.ProcessId);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static WindowsServiceConfiguration QueryConfiguration(nint service)
    {
        _ = QueryServiceConfig(
            service,
            queryServiceConfig: nint.Zero,
            bufferSize: 0,
            out var requiredBytes);
        var sizeQueryError = Marshal.GetLastPInvokeError();
        if (requiredBytes == 0 || sizeQueryError != ErrorInsufficientBuffer)
        {
            throw new Win32Exception(
                sizeQueryError,
                "QueryServiceConfigW did not report an activation service configuration buffer size.");
        }

        var buffer = Marshal.AllocHGlobal(checked((int)requiredBytes));
        try
        {
            if (QueryServiceConfig(service, buffer, requiredBytes, out var writtenBytes) == 0)
            {
                ThrowLastWin32("QueryServiceConfigW failed for the activation service.");
            }

            if (writtenBytes > requiredBytes)
            {
                throw new InvalidDataException(
                    "QueryServiceConfigW returned an oversized activation service configuration.");
            }

            var configuration = Marshal.PtrToStructure<QueryServiceConfigNative>(buffer);
            var commandLine = Marshal.PtrToStringUni(configuration.BinaryPathName);
            var startName = Marshal.PtrToStringUni(configuration.ServiceStartName);
            if (string.IsNullOrWhiteSpace(commandLine) || string.IsNullOrWhiteSpace(startName))
            {
                throw new InvalidDataException(
                    "The activation service configuration omitted its command line or start account.");
            }

            return new WindowsServiceConfiguration(commandLine, startName);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    internal static string ResolveAccountSid(string accountName)
    {
        if (string.Equals(accountName, "LocalSystem", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityIdentifier(WellKnownSidType.LocalSystemSid, domainSid: null).Value;
        }

        try
        {
            var account = new NTAccount(accountName);
            return ((SecurityIdentifier)account.Translate(typeof(SecurityIdentifier))).Value;
        }
        catch (IdentityNotMappedException exception)
        {
            throw new UnauthorizedAccessException(
                $"The activation service account '{accountName}' could not be resolved to a SID.",
                exception);
        }
    }

    private static void ThrowLastWin32(string message)
    {
        throw new Win32Exception(Marshal.GetLastPInvokeError(), message);
    }

    [LibraryImport("kernel32.dll", EntryPoint = "GetNamedPipeServerProcessId", SetLastError = true)]
    private static partial int GetNamedPipeServerProcessIdNative(
        SafePipeHandle pipeHandle,
        out uint serverProcessId);

    [LibraryImport(
        "advapi32.dll",
        EntryPoint = "OpenSCManagerW",
        SetLastError = true,
        StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint OpenSCManager(
        string? machineName,
        string? databaseName,
        uint desiredAccess);

    [LibraryImport(
        "advapi32.dll",
        EntryPoint = "OpenServiceW",
        SetLastError = true,
        StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint OpenService(
        nint serviceManager,
        string serviceName,
        uint desiredAccess);

    [LibraryImport("advapi32.dll", EntryPoint = "QueryServiceStatusEx", SetLastError = true)]
    private static partial int QueryServiceStatusEx(
        nint service,
        int infoLevel,
        nint buffer,
        uint bufferSize,
        out uint bytesNeeded);

    [LibraryImport("advapi32.dll", EntryPoint = "QueryServiceConfigW", SetLastError = true)]
    private static partial int QueryServiceConfig(
        nint service,
        nint queryServiceConfig,
        uint bufferSize,
        out uint bytesNeeded);

    [LibraryImport("advapi32.dll", EntryPoint = "ControlService", SetLastError = true)]
    private static partial int ControlService(
        nint service,
        uint control,
        out ServiceStatus status);

    [LibraryImport("advapi32.dll", EntryPoint = "CloseServiceHandle", SetLastError = true)]
    private static partial int CloseServiceHandle(nint serviceHandle);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ServiceStatusProcess
    {
        public readonly uint ServiceType;
        public readonly uint CurrentState;
        public readonly uint ControlsAccepted;
        public readonly uint Win32ExitCode;
        public readonly uint ServiceSpecificExitCode;
        public readonly uint CheckPoint;
        public readonly uint WaitHint;
        public readonly uint ProcessId;
        public readonly uint ServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ServiceStatus
    {
        public readonly uint ServiceType;
        public readonly uint CurrentState;
        public readonly uint ControlsAccepted;
        public readonly uint Win32ExitCode;
        public readonly uint ServiceSpecificExitCode;
        public readonly uint CheckPoint;
        public readonly uint WaitHint;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct QueryServiceConfigNative
    {
        public readonly uint ServiceType;
        public readonly uint StartType;
        public readonly uint ErrorControl;
        public readonly nint BinaryPathName;
        public readonly nint LoadOrderGroup;
        public readonly uint TagId;
        public readonly nint Dependencies;
        public readonly nint ServiceStartName;
        public readonly nint DisplayName;
    }

    private sealed record WindowsServiceConfiguration(string CommandLine, string StartName);
}

internal interface IActivationImageFileSystem
{
    string GetFullPath(string path);

    bool FileExists(string path);

    bool DirectoryExists(string path);

    FileAttributes GetAttributes(string path);
}

internal sealed class WindowsActivationImageFileSystem : IActivationImageFileSystem
{
    public string GetFullPath(string path) => Path.GetFullPath(path);

    public bool FileExists(string path) => File.Exists(path);

    public bool DirectoryExists(string path) => Directory.Exists(path);

    public FileAttributes GetAttributes(string path) => File.GetAttributes(path);
}

internal sealed class InstalledActivationServiceImagePolicy : IActivationServiceImagePolicy
{
    private const string RuntimeDirectoryName = "Distraction Firewall Lease Runtime";
    private const string ServiceDirectoryName = "activation-service";
    private const string ServiceExecutableName = "distraction-firewall-activation-service.exe";
    private const string ServiceCommandSuffix = " --service";
    private readonly string _expectedQuotedPath;
    private readonly string _expectedPath;
    private readonly IActivationImageFileSystem _fileSystem;
    private readonly string _trustedRoot;

    internal InstalledActivationServiceImagePolicy(
        string trustedRoot,
        string expectedPath,
        IActivationImageFileSystem fileSystem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(trustedRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedPath);
        _fileSystem = fileSystem ?? throw new ArgumentNullException(nameof(fileSystem));
        _trustedRoot = Path.TrimEndingDirectorySeparator(_fileSystem.GetFullPath(trustedRoot));
        _expectedPath = _fileSystem.GetFullPath(expectedPath);
        var trustedPrefix = _trustedRoot + Path.DirectorySeparatorChar;
        if (!_expectedPath.StartsWith(trustedPrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "The expected activation service image must be beneath the trusted Program Files root.",
                nameof(expectedPath));
        }

        _expectedQuotedPath = $"\"{_expectedPath}\"";
    }

    public static InstalledActivationServiceImagePolicy CreateDefault()
    {
        if (!OperatingSystem.IsWindows() || nint.Size != sizeof(long))
        {
            throw new PlatformNotSupportedException(
                "The installed activation service image policy requires Windows x64.");
        }

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (string.IsNullOrWhiteSpace(programFiles))
        {
            throw new DirectoryNotFoundException("The Windows Program Files root was unavailable.");
        }

        return new InstalledActivationServiceImagePolicy(
            programFiles,
            Path.Combine(
                programFiles,
                RuntimeDirectoryName,
                ServiceDirectoryName,
                ServiceExecutableName),
            new WindowsActivationImageFileSystem());
    }

    public void DemandExpectedAndProtected(string actualServiceCommandLine)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actualServiceCommandLine);
        if (actualServiceCommandLine.Length
                != _expectedQuotedPath.Length + ServiceCommandSuffix.Length
            || !actualServiceCommandLine.StartsWith(
                _expectedQuotedPath,
                StringComparison.OrdinalIgnoreCase)
            || !actualServiceCommandLine.EndsWith(
                ServiceCommandSuffix,
                StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException(
                "The activation service command line is not the exact fixed installed image plus --service.");
        }

        var current = _expectedPath;
        while (true)
        {
            var isImage = string.Equals(current, _expectedPath, StringComparison.OrdinalIgnoreCase);
            var exists = isImage
                ? _fileSystem.FileExists(current)
                : _fileSystem.DirectoryExists(current);
            if (!exists)
            {
                throw new UnauthorizedAccessException(
                    $"Protected activation service path '{current}' does not exist.");
            }

            var attributes = _fileSystem.GetAttributes(current);
            var wrongKind = isImage
                ? (attributes & FileAttributes.Directory) != 0
                : (attributes & FileAttributes.Directory) == 0;
            if (wrongKind || (attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new UnauthorizedAccessException(
                    $"Protected activation service path '{current}' is not a non-reparse {(isImage ? "file" : "directory")}.");
            }

            if (string.Equals(current, _trustedRoot, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            current = Path.GetDirectoryName(current)
                ?? throw new UnauthorizedAccessException(
                    "The activation service image escaped the trusted Program Files root.");
            var trustedPrefix = _trustedRoot + Path.DirectorySeparatorChar;
            if (!string.Equals(current, _trustedRoot, StringComparison.OrdinalIgnoreCase)
                && !current.StartsWith(trustedPrefix, StringComparison.OrdinalIgnoreCase))
            {
                throw new UnauthorizedAccessException(
                    "The activation service image escaped the trusted Program Files root.");
            }
        }
    }
}
