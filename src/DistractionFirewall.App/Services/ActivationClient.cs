using DistractionFirewall.Contracts;
using DistractionFirewall.Ipc;

namespace DistractionFirewall.App.Services;

public sealed class ActivationClient : IActivationClient
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);
    private readonly NamedPipeRpcClient _client = new();

    public Task<GetTargetCatalogResponse> GetTargetsAsync(CancellationToken cancellationToken) =>
        _client.CallAsync<ProtocolRequest, GetTargetCatalogResponse>(
            RpcMethods.GetTargetCatalog,
            new ProtocolRequest(ProtocolConstants.CurrentVersion),
            Timeout,
            cancellationToken);

    public Task<LeaseStatusResponse> GetStatusAsync(CancellationToken cancellationToken) =>
        _client.CallAsync<ProtocolRequest, LeaseStatusResponse>(
            RpcMethods.GetStatus,
            new ProtocolRequest(ProtocolConstants.CurrentVersion),
            Timeout,
            cancellationToken);

    public Task<PrepareLeaseResponse> PrepareAsync(
        PrepareLeaseRequest request,
        CancellationToken cancellationToken) =>
        _client.CallAsync<PrepareLeaseRequest, PrepareLeaseResponse>(
            RpcMethods.PrepareLease,
            request,
            Timeout,
            cancellationToken);

    public Task<CommitLeaseResponse> CommitAsync(
        CommitLeaseRequest request,
        CancellationToken cancellationToken) =>
        _client.CallAsync<CommitLeaseRequest, CommitLeaseResponse>(
            RpcMethods.CommitLease,
            request,
            Timeout,
            cancellationToken);

    public Task<DiagnosticsResponse> GetDiagnosticsAsync(CancellationToken cancellationToken) =>
        _client.CallAsync<ProtocolRequest, DiagnosticsResponse>(
            RpcMethods.GetDiagnostics,
            new ProtocolRequest(ProtocolConstants.CurrentVersion),
            Timeout,
            cancellationToken);
}
