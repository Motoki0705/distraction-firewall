using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace DistractionFirewall.ActivationService;

internal sealed record WindowsNamedPipeCreationRequest(
    string PipeName,
    uint OpenMode,
    uint PipeMode,
    uint MaxInstances,
    uint OutBufferSize,
    uint InBufferSize,
    byte[] SecurityDescriptor);

internal interface IWindowsNamedPipeServerFactory
{
    NamedPipeServerStream Create(WindowsNamedPipeCreationRequest request);
}

internal sealed partial class WindowsNativeNamedPipeServerFactory : IWindowsNamedPipeServerFactory
{
    internal const uint PipeAccessDuplex = 0x00000003;
    internal const uint FileFlagFirstPipeInstance = 0x00080000;
    internal const uint FileFlagOverlapped = 0x40000000;
    internal const uint FileFlagWriteThrough = 0x80000000;
    internal const uint PipeRejectRemoteClients = 0x00000008;

    private static readonly nint InvalidHandleValue = new(-1);

    public NamedPipeServerStream Create(WindowsNamedPipeCreationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Windows native named-pipe creation is unavailable on this platform.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(request.PipeName);
        var requiredOpenMode = PipeAccessDuplex |
            FileFlagFirstPipeInstance |
            FileFlagOverlapped |
            FileFlagWriteThrough;
        if ((request.OpenMode & requiredOpenMode) != requiredOpenMode
            || (request.PipeMode & PipeRejectRemoteClients) == 0
            || request.MaxInstances != 1
            || request.SecurityDescriptor.Length == 0)
        {
            throw new InvalidOperationException(
                "The activation pipe requires duplex overlapped first-instance creation, remote-client rejection, one instance, and an explicit security descriptor.");
        }

        var descriptor = GCHandle.Alloc(request.SecurityDescriptor, GCHandleType.Pinned);
        nint rawHandle;
        try
        {
            var securityAttributes = new SecurityAttributes
            {
                Length = checked((uint)Marshal.SizeOf<SecurityAttributes>()),
                SecurityDescriptor = descriptor.AddrOfPinnedObject(),
                InheritHandle = 0,
            };
            rawHandle = CreateNamedPipe(
                request.PipeName,
                request.OpenMode,
                request.PipeMode,
                request.MaxInstances,
                request.OutBufferSize,
                request.InBufferSize,
                defaultTimeoutMilliseconds: 0,
                in securityAttributes);
        }
        finally
        {
            descriptor.Free();
        }

        if (rawHandle == InvalidHandleValue)
        {
            throw new Win32Exception(
                Marshal.GetLastPInvokeError(),
                "CreateNamedPipeW refused the protected activation pipe instance.");
        }

        SafePipeHandle? safeHandle = new(rawHandle, ownsHandle: true);
        try
        {
            var stream = new NamedPipeServerStream(
                PipeDirection.InOut,
                isAsync: true,
                isConnected: false,
                safeHandle);
            safeHandle = null;
            return stream;
        }
        finally
        {
            safeHandle?.Dispose();
        }
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateNamedPipeW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial nint CreateNamedPipe(
        string name,
        uint openMode,
        uint pipeMode,
        uint maxInstances,
        uint outBufferSize,
        uint inBufferSize,
        uint defaultTimeoutMilliseconds,
        in SecurityAttributes securityAttributes);

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public uint Length;
        public nint SecurityDescriptor;
        public int InheritHandle;
    }
}
