using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using DistractionFirewall.ActivationService;

namespace DistractionFirewall.LeaseLifecycleTests;

public sealed class ActivationPipeSecurityTests
{
    private const string OwnerSid = "S-1-5-21-1000-1000-1000-1000";

    [Fact]
    public void Server_creation_forces_first_instance_remote_rejection_async_and_exact_acl_boundary()
    {
        var native = new RecordingNamedPipeServerFactory();
        var factory = new WindowsAclActivationPipeFactory([OwnerSid], native);

        if (!OperatingSystem.IsWindows())
        {
            Assert.Throws<PlatformNotSupportedException>(() => factory.Create());
            Assert.Null(native.Request);
            return;
        }

        Assert.Throws<RecordedCreationException>(() => factory.Create());

        var request = Assert.IsType<WindowsNamedPipeCreationRequest>(native.Request);
        Assert.Equal(
            @"\\.\pipe\DistractionFirewall.Activation.v1",
            request.PipeName);
        Assert.Equal(WindowsAclActivationPipeFactory.RequiredOpenMode, request.OpenMode);
        Assert.Equal(WindowsAclActivationPipeFactory.RequiredPipeMode, request.PipeMode);
        Assert.Equal(1u, request.MaxInstances);
        Assert.Equal(0u, request.InBufferSize);
        Assert.Equal(0u, request.OutBufferSize);

        var descriptor = new RawSecurityDescriptor(request.SecurityDescriptor, offset: 0);
        Assert.True((descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0);
        var acl = Assert.IsType<RawAcl>(descriptor.DiscretionaryAcl);
        var rules = acl
            .Cast<GenericAce>()
            .Select(ace => Assert.IsAssignableFrom<QualifiedAce>(ace))
            .ToDictionary(
                ace => Assert.IsType<SecurityIdentifier>(ace.SecurityIdentifier).Value,
                ace => ace,
                StringComparer.Ordinal);
        Assert.Equal(3, rules.Count);
        AssertAllowContains(
            rules[Sid(WellKnownSidType.LocalSystemSid)],
            PipeAccessRights.FullControl);
        AssertAllowContains(
            rules[Sid(WellKnownSidType.BuiltinAdministratorsSid)],
            PipeAccessRights.FullControl);
        AssertAllowContains(rules[OwnerSid], PipeAccessRights.ReadWrite);
        Assert.Equal(
            0,
            rules[OwnerSid].AccessMask &
                (int)(PipeAccessRights.ChangePermissions | PipeAccessRights.TakeOwnership));
    }

    [Fact]
    public async Task Native_server_factory_wraps_an_overlapped_protected_handle()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        var currentSid = identity.User?.Value
            ?? throw new InvalidOperationException("The test process did not expose a user SID.");
        var recorder = new RecordingNamedPipeServerFactory();
        Assert.Throws<RecordedCreationException>(() =>
            new WindowsAclActivationPipeFactory([currentSid], recorder).Create());
        var shortName = "DistractionFirewall.NativePipeTest." + Guid.NewGuid().ToString("N");
        var request = Assert.IsType<WindowsNamedPipeCreationRequest>(recorder.Request) with
        {
            PipeName = @"\\.\pipe\" + shortName,
        };

        await using var server = new WindowsNativeNamedPipeServerFactory().Create(request);
        await using var client = new NamedPipeClientStream(
            ".",
            shortName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous);
        var accept = server.WaitForConnectionAsync();
        await client.ConnectAsync(5000);
        await accept.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.True(server.IsConnected);
        Assert.True(client.IsConnected);
        using var ioTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var payload = new byte[1];
        var write = client.WriteAsync(new byte[] { 0x2A }, ioTimeout.Token).AsTask();
        var read = server.ReadAsync(payload, ioTimeout.Token).AsTask();
        await Task.WhenAll(write, read);
        Assert.Equal(1, await read);
        Assert.Equal(0x2A, payload[0]);
    }

    private static void AssertAllowContains(QualifiedAce ace, PipeAccessRights rights)
    {
        Assert.Equal(AceQualifier.AccessAllowed, ace.AceQualifier);
        Assert.Equal((int)rights, ace.AccessMask & (int)rights);
    }

    private static string Sid(WellKnownSidType type) =>
        new SecurityIdentifier(type, domainSid: null).Value;

    private sealed class RecordingNamedPipeServerFactory : IWindowsNamedPipeServerFactory
    {
        public WindowsNamedPipeCreationRequest? Request { get; private set; }

        public NamedPipeServerStream Create(WindowsNamedPipeCreationRequest request)
        {
            Request = request;
            throw new RecordedCreationException();
        }
    }

    private sealed class RecordedCreationException : Exception;
}
