using System.Diagnostics;
using System.Runtime.InteropServices;
using DistractionFirewall.Core.Time;

namespace DistractionFirewall.Runtime.Windows;

public interface IWindowsBootIdentifierSource
{
    string GetBootIdentifier();
}

public sealed class WindowsBootTimeAuthority : ITimeAuthority
{
    private readonly string _bootIdentifier;

    public WindowsBootTimeAuthority(IWindowsBootIdentifierSource bootIdentifierSource)
    {
        ArgumentNullException.ThrowIfNull(bootIdentifierSource);
        _bootIdentifier = bootIdentifierSource.GetBootIdentifier();
        ArgumentException.ThrowIfNullOrWhiteSpace(_bootIdentifier);
    }

    public TimeSnapshot Capture() => new(
        DateTimeOffset.UtcNow,
        _bootIdentifier,
        Stopwatch.GetTimestamp(),
        Stopwatch.Frequency);
}

public sealed class NativeWindowsBootIdentifierSource : IWindowsBootIdentifierSource
{
    private const int SystemTimeOfDayInformation = 3;
    private const int SystemBootEnvironmentInformation = 90;
    private const int NativeBufferBytes = 64;
    private const int NtSuccess = 0;

    public string GetBootIdentifier()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("A Windows kernel boot identifier requires Windows.");
        }

        var buffer = Marshal.AllocHGlobal(NativeBufferBytes);
        try
        {
            var status = NtQuerySystemInformation(
                SystemBootEnvironmentInformation,
                buffer,
                NativeBufferBytes,
                out var returnedLength);
            if (status == NtSuccess && returnedLength >= 16)
            {
                var identifier = Marshal.PtrToStructure<Guid>(buffer);
                if (identifier != Guid.Empty)
                {
                    return "windows-boot-guid:" + identifier.ToString("N");
                }
            }

            status = NtQuerySystemInformation(
                SystemTimeOfDayInformation,
                buffer,
                NativeBufferBytes,
                out returnedLength);
            if (status == NtSuccess && returnedLength >= sizeof(long))
            {
                var bootTimeFileTime = Marshal.ReadInt64(buffer);
                if (bootTimeFileTime > 0)
                {
                    return "windows-boot-time:" + bootTimeFileTime.ToString(
                        "X16",
                        System.Globalization.CultureInfo.InvariantCulture);
                }
            }

            throw new InvalidOperationException(
                $"Windows kernel boot identity queries failed (last NTSTATUS 0x{status:X8}).");
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [DllImport("ntdll.dll", EntryPoint = "NtQuerySystemInformation")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int NtQuerySystemInformation(
        int systemInformationClass,
        nint systemInformation,
        int systemInformationLength,
        out int returnLength);
}
