using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Principal;
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
                ServiceCommandLine: "\"C:\\foreign.exe\" --service")),
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
                ServiceCommandLine: "\"C:\\Program Files\\Distraction Firewall Lease Runtime\\activation-service\\distraction-firewall-activation-service.exe\" --service")),
            imagePolicy);

        if (!OperatingSystem.IsWindows())
        {
            Assert.Throws<PlatformNotSupportedException>(() => verifier.Verify(pipeHandle));
            return;
        }

        verifier.Verify(pipeHandle);

        Assert.Equal(1, imagePolicy.CallCount);
        Assert.EndsWith(
            "distraction-firewall-activation-service.exe\" --service",
            imagePolicy.LastServiceCommandLine,
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
                ServiceCommandLine: "\"C:\\wrong.exe\" --service")),
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
        var expectedCommandLine = $"\"{expected}\" --service";

        policy.DemandExpectedAndProtected($"\"{expected.ToUpperInvariant()}\" --service");
        Assert.Throws<UnauthorizedAccessException>(() =>
            policy.DemandExpectedAndProtected($"\"{Path.Combine(serviceRoot, "foreign.exe")}\" --service"));
        foreach (var invalidCommandLine in new[]
        {
            $"\"{expected}\" --console",
            $"\"{expected}\" --SERVICE",
            $"\"{expected}\"  --service",
            $"\"{expected}\" --service extra",
            $"{expected} --service",
            @"%ProgramFiles%\Distraction Firewall Lease Runtime\activation-service\distraction-firewall-activation-service.exe --service",
        })
        {
            Assert.Throws<UnauthorizedAccessException>(() =>
                policy.DemandExpectedAndProtected(invalidCommandLine));
        }

        fileSystem.Remove(expected);
        Assert.Throws<UnauthorizedAccessException>(() =>
            policy.DemandExpectedAndProtected(expectedCommandLine));
        fileSystem.AddFile(expected);
        fileSystem.AddDirectory(runtimeRoot, reparsePoint: true);
        Assert.Throws<UnauthorizedAccessException>(() =>
            policy.DemandExpectedAndProtected(expectedCommandLine));
    }

    [Fact]
    public void Native_identity_accepts_only_a_stable_running_own_process_service_pid()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var pipeHandle = new SafePipeHandle((nint)1234, ownsHandle: false);
        var commandLine =
            "\"C:\\Program Files\\Distraction Firewall Lease Runtime\\activation-service\\distraction-firewall-activation-service.exe\" --service";
        var api = new FakeWindowsActivationServiceIdentityApi(
            [42, 42],
            CreateServiceSnapshot(42, commandLine));
        var native = new WindowsNamedPipeServerIdentityNative(api);

        var identity = native.Inspect(pipeHandle);

        Assert.Equal((uint)42, identity.ProcessId);
        Assert.Equal("S-1-5-18", identity.UserSid);
        Assert.Equal(commandLine, identity.ServiceCommandLine);
        Assert.Equal(2, api.PipeProcessIdCallCount);
        Assert.Equal(1, api.ServiceQueryCallCount);
    }

    [Fact]
    public void Native_identity_fails_closed_for_pid_reuse_or_non_service_processes()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var pipeHandle = new SafePipeHandle((nint)1234, ownsHandle: false);
        const string commandLine = "\"C:\\fixed.exe\" --service";
        var cases = new[]
        {
            new FakeWindowsActivationServiceIdentityApi(
                [42, 43],
                CreateServiceSnapshot(42, commandLine)),
            new FakeWindowsActivationServiceIdentityApi(
                [42, 42],
                CreateServiceSnapshot(43, commandLine)),
            new FakeWindowsActivationServiceIdentityApi(
                [42, 42],
                CreateServiceSnapshot(42, commandLine) with
                {
                    AfterConfigurationRead = new WindowsServiceProcessStatus(0x10, 4, 43),
                }),
            new FakeWindowsActivationServiceIdentityApi(
                [42, 42],
                CreateServiceSnapshot(42, commandLine) with
                {
                    BeforeConfigurationRead = new WindowsServiceProcessStatus(0x20, 4, 42),
                }),
            new FakeWindowsActivationServiceIdentityApi(
                [42, 42],
                CreateServiceSnapshot(42, commandLine) with
                {
                    AfterConfigurationRead = new WindowsServiceProcessStatus(0x10, 1, 42),
                }),
            new FakeWindowsActivationServiceIdentityApi(
                [42, 42],
                CreateServiceSnapshot(42, commandLine) with
                {
                    InterrogatedStatus = new WindowsServiceStatus(0x10, 1),
                }),
        };

        foreach (var api in cases)
        {
            AssertNativeIdentityRejected(api, pipeHandle);
        }
    }

    [SupportedOSPlatform("windows")]
    [Fact]
    public void Scm_local_system_sentinel_resolves_deterministically_to_well_known_sid()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var expected = new SecurityIdentifier(
            WellKnownSidType.LocalSystemSid,
            domainSid: null).Value;

        Assert.Equal(expected, WindowsActivationServiceIdentityApi.ResolveAccountSid("LocalSystem"));
        Assert.Equal(expected, WindowsActivationServiceIdentityApi.ResolveAccountSid("localsystem"));
        Assert.Throws<UnauthorizedAccessException>(() =>
            WindowsActivationServiceIdentityApi.ResolveAccountSid(
                "DistractionFirewall-Definitely-Unmapped-Account"));
    }

    [SupportedOSPlatform("windows")]
    [Fact]
    public async Task Installed_standard_user_rpc_identity_check_is_live_capable_when_opted_in()
    {
        if (!string.Equals(
                Environment.GetEnvironmentVariable("DISTRACTION_FIREWALL_LIVE_INSTALLED_IPC"),
                "1",
                StringComparison.Ordinal))
        {
            return;
        }

        Assert.True(OperatingSystem.IsWindows());
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        Assert.False(principal.IsInRole(WindowsBuiltInRole.Administrator));
        Assert.NotEqual("S-1-5-18", identity.User?.Value);
        var client = new NamedPipeRpcClient();
        var response = await client.CallAsync<ProtocolRequest, CapabilitiesResponse>(
            RpcMethods.GetCapabilities,
            new ProtocolRequest(ProtocolConstants.CurrentVersion),
            TimeSpan.FromSeconds(10));

        Assert.Equal(ProtocolConstants.CurrentVersion, response.ProtocolVersion);
        Assert.Contains(RpcMethods.GetStatus, response.Methods);
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

        public string? LastServiceCommandLine { get; private set; }

        public void DemandExpectedAndProtected(string actualServiceCommandLine)
        {
            CallCount++;
            LastServiceCommandLine = actualServiceCommandLine;
            if (Failure is not null)
            {
                throw Failure;
            }
        }
    }

    private sealed class FakeWindowsActivationServiceIdentityApi
        : IWindowsActivationServiceIdentityApi
    {
        private readonly Queue<uint> _pipeProcessIds;
        private readonly WindowsActivationServiceSnapshot _service;

        public FakeWindowsActivationServiceIdentityApi(
            IEnumerable<uint> pipeProcessIds,
            WindowsActivationServiceSnapshot service)
        {
            _pipeProcessIds = new Queue<uint>(pipeProcessIds);
            _service = service;
        }

        public int PipeProcessIdCallCount { get; private set; }

        public int ServiceQueryCallCount { get; private set; }

        public uint GetNamedPipeServerProcessId(SafePipeHandle pipeHandle)
        {
            PipeProcessIdCallCount++;
            return _pipeProcessIds.Dequeue();
        }

        public WindowsActivationServiceSnapshot QueryActivationService()
        {
            ServiceQueryCallCount++;
            return _service;
        }
    }

    private static WindowsActivationServiceSnapshot CreateServiceSnapshot(
        uint processId,
        string commandLine) => new(
            new WindowsServiceProcessStatus(0x10, 4, processId),
            new WindowsServiceStatus(0x10, 4),
            new WindowsServiceProcessStatus(0x10, 4, processId),
            "S-1-5-18",
            commandLine);

    [SupportedOSPlatform("windows")]
    private static void AssertNativeIdentityRejected(
        IWindowsActivationServiceIdentityApi api,
        SafePipeHandle pipeHandle)
    {
        Assert.Throws<UnauthorizedAccessException>(() =>
            new WindowsNamedPipeServerIdentityNative(api).Inspect(pipeHandle));
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
