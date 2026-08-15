using System.IO.Pipes;
using DistractionFirewall.Contracts;
using DistractionFirewall.Ipc;
using Microsoft.Win32.SafeHandles;

namespace DistractionFirewall.ContractTests;

public sealed class NamedPipeServerIdentityTests
{
    [Fact]
    public void Verifier_requires_local_system_before_applying_image_policy()
    {
        using var pipeHandle = new SafePipeHandle((nint)1234, ownsHandle: false);
        var imagePolicy = new FakeImagePolicy();
        var verifier = new WindowsNamedPipeServerIdentityVerifier(
            new FakeServerIdentityNative(new NamedPipeServerProcessIdentity(
                ProcessId: 42,
                UserSid: "S-1-5-21-1000-1000-1000-1000",
                ImagePath: @"C:\foreign.exe")),
            imagePolicy);

        if (!OperatingSystem.IsWindows())
        {
            Assert.Throws<PlatformNotSupportedException>(() => verifier.Verify(pipeHandle));
            return;
        }

        Assert.Throws<UnauthorizedAccessException>(() => verifier.Verify(pipeHandle));
        Assert.Equal(0, imagePolicy.CallCount);
    }

    [Fact]
    public void Verifier_accepts_local_system_only_when_fixed_image_policy_accepts()
    {
        using var pipeHandle = new SafePipeHandle((nint)1234, ownsHandle: false);
        var imagePolicy = new FakeImagePolicy();
        var verifier = new WindowsNamedPipeServerIdentityVerifier(
            new FakeServerIdentityNative(new NamedPipeServerProcessIdentity(
                ProcessId: 42,
                UserSid: "S-1-5-18",
                ImagePath: @"C:\Program Files\Distraction Firewall Lease Runtime\activation-service\distraction-firewall-activation-service.exe")),
            imagePolicy);

        if (!OperatingSystem.IsWindows())
        {
            Assert.Throws<PlatformNotSupportedException>(() => verifier.Verify(pipeHandle));
            return;
        }

        verifier.Verify(pipeHandle);

        Assert.Equal(1, imagePolicy.CallCount);
        Assert.EndsWith(
            "distraction-firewall-activation-service.exe",
            imagePolicy.LastImagePath,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Verifier_fails_closed_when_image_policy_rejects()
    {
        using var pipeHandle = new SafePipeHandle((nint)1234, ownsHandle: false);
        var verifier = new WindowsNamedPipeServerIdentityVerifier(
            new FakeServerIdentityNative(new NamedPipeServerProcessIdentity(
                ProcessId: 42,
                UserSid: "S-1-5-18",
                ImagePath: @"C:\wrong.exe")),
            new FakeImagePolicy
            {
                Failure = new UnauthorizedAccessException("wrong image"),
            });

        if (!OperatingSystem.IsWindows())
        {
            Assert.Throws<PlatformNotSupportedException>(() => verifier.Verify(pipeHandle));
            return;
        }

        Assert.Throws<UnauthorizedAccessException>(() => verifier.Verify(pipeHandle));
    }

    [Fact]
    public void Fixed_image_policy_rejects_wrong_missing_or_reparse_paths()
    {
        var fileSystem = new FakeActivationImageFileSystem();
        var trustedRoot = Path.Combine(Path.GetPathRoot(Environment.CurrentDirectory)!, "trusted-program-files");
        var runtimeRoot = Path.Combine(trustedRoot, "Distraction Firewall Lease Runtime");
        var serviceRoot = Path.Combine(runtimeRoot, "activation-service");
        var expected = Path.Combine(serviceRoot, "distraction-firewall-activation-service.exe");
        fileSystem.AddDirectory(trustedRoot);
        fileSystem.AddDirectory(runtimeRoot);
        fileSystem.AddDirectory(serviceRoot);
        fileSystem.AddFile(expected);
        var policy = new InstalledActivationServiceImagePolicy(trustedRoot, expected, fileSystem);

        policy.DemandExpectedAndProtected(expected.ToUpperInvariant());
        Assert.Throws<UnauthorizedAccessException>(() =>
            policy.DemandExpectedAndProtected(Path.Combine(serviceRoot, "foreign.exe")));

        fileSystem.Remove(expected);
        Assert.Throws<UnauthorizedAccessException>(() =>
            policy.DemandExpectedAndProtected(expected));
        fileSystem.AddFile(expected);
        fileSystem.AddDirectory(runtimeRoot, reparsePoint: true);
        Assert.Throws<UnauthorizedAccessException>(() =>
            policy.DemandExpectedAndProtected(expected));
    }

    [Fact]
    public async Task Rpc_client_authenticates_server_before_writing_first_frame()
    {
        var pipeName = "DistractionFirewall.IdentityTest." + Guid.NewGuid().ToString("N");
        await using var server = new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        var verifier = new ThrowingServerIdentityVerifier();
        var client = new NamedPipeRpcClient(pipeName, serializerOptions: null, verifier);

        var call = client.CallAsync<ProtocolRequest, CapabilitiesResponse>(
            RpcMethods.GetCapabilities,
            new ProtocolRequest(ProtocolConstants.CurrentVersion),
            TimeSpan.FromSeconds(5));
        await server.WaitForConnectionAsync().WaitAsync(TimeSpan.FromSeconds(5));

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => call);
        var firstByte = new byte[1];
        var bytesRead = await server.ReadAsync(firstByte).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, bytesRead);
        Assert.Equal(1, verifier.CallCount);
    }

    private sealed class FakeServerIdentityNative : INamedPipeServerIdentityNative
    {
        private readonly NamedPipeServerProcessIdentity _identity;

        public FakeServerIdentityNative(NamedPipeServerProcessIdentity identity)
        {
            _identity = identity;
        }

        public NamedPipeServerProcessIdentity Inspect(SafePipeHandle pipeHandle) => _identity;
    }

    private sealed class FakeImagePolicy : IActivationServiceImagePolicy
    {
        public Exception? Failure { get; init; }

        public int CallCount { get; private set; }

        public string? LastImagePath { get; private set; }

        public void DemandExpectedAndProtected(string actualImagePath)
        {
            CallCount++;
            LastImagePath = actualImagePath;
            if (Failure is not null)
            {
                throw Failure;
            }
        }
    }

    private sealed class ThrowingServerIdentityVerifier : INamedPipeServerIdentityVerifier
    {
        public int CallCount { get; private set; }

        public void Verify(SafePipeHandle pipeHandle)
        {
            CallCount++;
            throw new UnauthorizedAccessException("injected server identity failure");
        }
    }

    private sealed class FakeActivationImageFileSystem : IActivationImageFileSystem
    {
        private readonly Dictionary<string, FileAttributes> _entries =
            new(StringComparer.OrdinalIgnoreCase);

        public string GetFullPath(string path) => Path.GetFullPath(path);

        public bool FileExists(string path) =>
            _entries.TryGetValue(GetFullPath(path), out var attributes)
            && (attributes & FileAttributes.Directory) == 0;

        public bool DirectoryExists(string path) =>
            _entries.TryGetValue(GetFullPath(path), out var attributes)
            && (attributes & FileAttributes.Directory) != 0;

        public FileAttributes GetAttributes(string path) => _entries[GetFullPath(path)];

        public void AddDirectory(string path, bool reparsePoint = false)
        {
            _entries[GetFullPath(path)] = FileAttributes.Directory |
                (reparsePoint ? FileAttributes.ReparsePoint : 0);
        }

        public void AddFile(string path)
        {
            _entries[GetFullPath(path)] = FileAttributes.Normal;
        }

        public void Remove(string path)
        {
            _entries.Remove(GetFullPath(path));
        }
    }
}
