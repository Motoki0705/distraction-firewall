using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace DistractionFirewall.Ipc;

internal sealed record NamedPipeServerProcessIdentity(
    uint ProcessId,
    string UserSid,
    string ImagePath);

internal interface INamedPipeServerIdentityVerifier
{
    void Verify(SafePipeHandle pipeHandle);
}

internal interface INamedPipeServerIdentityNative
{
    NamedPipeServerProcessIdentity Inspect(SafePipeHandle pipeHandle);
}

internal interface IActivationServiceImagePolicy
{
    void DemandExpectedAndProtected(string actualImagePath);
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

        _imagePolicy.DemandExpectedAndProtected(identity.ImagePath);
    }
}

[SupportedOSPlatform("windows")]
internal sealed partial class WindowsNamedPipeServerIdentityNative : INamedPipeServerIdentityNative
{
    private const uint ProcessQueryLimitedInformation = 0x00001000;
    private const uint TokenQuery = 0x00000008;
    private const int TokenUserInformationClass = 1;
    private const int ErrorInsufficientBuffer = 122;
    private const int MaximumProcessImageCharacters = 32768;

    public NamedPipeServerProcessIdentity Inspect(SafePipeHandle pipeHandle)
    {
        ArgumentNullException.ThrowIfNull(pipeHandle);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Windows named-pipe process inspection is unavailable on this platform.");
        }

        if (GetNamedPipeServerProcessId(pipeHandle, out var processId) == 0 || processId == 0)
        {
            ThrowLastWin32("GetNamedPipeServerProcessId failed.");
        }

        var rawProcess = OpenProcess(ProcessQueryLimitedInformation, inheritHandle: 0, processId);
        if (rawProcess == nint.Zero)
        {
            ThrowLastWin32($"OpenProcess refused activation pipe server process {processId}.");
        }

        using var process = new SafeProcessHandle(rawProcess, ownsHandle: true);
        var imagePath = QueryImagePath(process);
        var userSid = QueryUserSid(process);
        return new NamedPipeServerProcessIdentity(processId, userSid, imagePath);
    }

    private static string QueryImagePath(SafeProcessHandle process)
    {
        var buffer = Marshal.AllocHGlobal(MaximumProcessImageCharacters * sizeof(char));
        try
        {
            var characters = (uint)MaximumProcessImageCharacters;
            if (QueryFullProcessImageName(process, flags: 0, buffer, ref characters) == 0
                || characters == 0
                || characters >= MaximumProcessImageCharacters)
            {
                ThrowLastWin32("QueryFullProcessImageNameW failed for the activation pipe server.");
            }

            return Marshal.PtrToStringUni(buffer, checked((int)characters))
                ?? throw new InvalidDataException(
                    "The activation pipe server image path could not be decoded.");
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static string QueryUserSid(SafeProcessHandle process)
    {
        if (OpenProcessToken(process, TokenQuery, out var rawToken) == 0
            || rawToken == nint.Zero)
        {
            ThrowLastWin32("OpenProcessToken failed for the activation pipe server.");
        }

        using var token = new SafeAccessTokenHandle(rawToken);
        _ = GetTokenInformation(
            token,
            TokenUserInformationClass,
            tokenInformation: nint.Zero,
            tokenInformationLength: 0,
            out var requiredBytes);
        if (requiredBytes == 0 || Marshal.GetLastPInvokeError() != ErrorInsufficientBuffer)
        {
            ThrowLastWin32("GetTokenInformation did not report a TOKEN_USER buffer size.");
        }

        var buffer = Marshal.AllocHGlobal(checked((int)requiredBytes));
        try
        {
            if (GetTokenInformation(
                    token,
                    TokenUserInformationClass,
                    buffer,
                    requiredBytes,
                    out var writtenBytes) == 0
                || writtenBytes != requiredBytes)
            {
                ThrowLastWin32("GetTokenInformation failed for the activation pipe server.");
            }

            var tokenUser = Marshal.PtrToStructure<TokenUser>(buffer);
            if (tokenUser.User.Sid == nint.Zero)
            {
                throw new InvalidDataException(
                    "The activation pipe server token did not contain a user SID.");
            }

            return new SecurityIdentifier(tokenUser.User.Sid).Value;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void ThrowLastWin32(string message)
    {
        throw new Win32Exception(Marshal.GetLastPInvokeError(), message);
    }

    [LibraryImport("kernel32.dll", EntryPoint = "GetNamedPipeServerProcessId", SetLastError = true)]
    private static partial int GetNamedPipeServerProcessId(
        SafePipeHandle pipeHandle,
        out uint serverProcessId);

    [LibraryImport("kernel32.dll", EntryPoint = "OpenProcess", SetLastError = true)]
    private static partial nint OpenProcess(
        uint desiredAccess,
        int inheritHandle,
        uint processId);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true)]
    private static partial int QueryFullProcessImageName(
        SafeProcessHandle process,
        uint flags,
        nint executableName,
        ref uint size);

    [LibraryImport("advapi32.dll", EntryPoint = "OpenProcessToken", SetLastError = true)]
    private static partial int OpenProcessToken(
        SafeProcessHandle process,
        uint desiredAccess,
        out nint tokenHandle);

    [LibraryImport("advapi32.dll", EntryPoint = "GetTokenInformation", SetLastError = true)]
    private static partial int GetTokenInformation(
        SafeAccessTokenHandle token,
        int tokenInformationClass,
        nint tokenInformation,
        uint tokenInformationLength,
        out uint returnLength);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct SidAndAttributes
    {
        public readonly nint Sid;
        public readonly uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct TokenUser
    {
        public readonly SidAndAttributes User;
    }
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

    public void DemandExpectedAndProtected(string actualImagePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actualImagePath);
        var actual = _fileSystem.GetFullPath(actualImagePath);
        if (!string.Equals(actual, _expectedPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException(
                $"Activation pipe server image '{actual}' is not the fixed installed service image.");
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
