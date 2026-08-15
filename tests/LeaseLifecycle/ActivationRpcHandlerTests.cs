using System.Text.Json;
using DistractionFirewall.ActivationService;
using DistractionFirewall.Contracts;
using DistractionFirewall.Ipc;

namespace DistractionFirewall.LeaseLifecycleTests;

public sealed class ActivationRpcHandlerTests
{
    private const string OwnerSid = "S-1-5-21-1000-1000-1000-1000";

    [Fact]
    public async Task Unauthorized_caller_is_rejected_before_dispatch()
    {
        using var harness = new ActivationHarness();
        var handler = new ActivationRpcHandler(
            harness.Coordinator,
            new AllowListedCallerAuthorizationPolicy([OwnerSid]));
        using var stream = new MemoryStream();
        var request = new RpcRequest(
            ProtocolConstants.CurrentVersion,
            Guid.NewGuid(),
            RpcMethods.GetCapabilities,
            JsonSerializer.SerializeToElement(new ProtocolRequest(ProtocolConstants.CurrentVersion)));

        var response = await handler.HandleAsync(
            new RpcConnection(stream),
            request,
            new CallerIdentity("S-1-5-21-2000-2000-2000-2000", Resolved: true, "test caller"),
            CancellationToken.None);

        Assert.False(response.Success);
        Assert.Equal(LeaseErrorCode.UnauthorizedCaller, Assert.IsType<RpcError>(response.Error).Code);
    }

    [Fact]
    public async Task Envelope_and_payload_request_ids_must_match()
    {
        using var harness = new ActivationHarness();
        var handler = new ActivationRpcHandler(
            harness.Coordinator,
            new AllowListedCallerAuthorizationPolicy([OwnerSid]));
        using var stream = new MemoryStream();
        var envelopeRequestId = Guid.NewGuid();
        var payload = new PrepareLeaseRequest(
            ProtocolConstants.CurrentVersion,
            Guid.NewGuid(),
            ["youtube"],
            new LeaseEndRequest(LeaseEndMode.Duration, DurationMinutes: 60, UntilUtc: null));
        var request = new RpcRequest(
            ProtocolConstants.CurrentVersion,
            envelopeRequestId,
            RpcMethods.PrepareLease,
            JsonSerializer.SerializeToElement(payload, ProtocolJson.CreateOptions()));

        var response = await handler.HandleAsync(
            new RpcConnection(stream),
            request,
            new CallerIdentity(OwnerSid, Resolved: true, "test owner"),
            CancellationToken.None);

        Assert.False(response.Success);
        Assert.Equal(LeaseErrorCode.RequestReplayMismatch, Assert.IsType<RpcError>(response.Error).Code);
        Assert.False(await harness.Workspace.Store.HasActiveLeaseAsync(CancellationToken.None));
    }
}
