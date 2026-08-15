using DistractionFirewall.Contracts;

namespace DistractionFirewall.App.Services;

public interface IActivationClient
{
    Task<GetTargetCatalogResponse> GetTargetsAsync(CancellationToken cancellationToken);

    Task<LeaseStatusResponse> GetStatusAsync(CancellationToken cancellationToken);

    Task<PrepareLeaseResponse> PrepareAsync(
        PrepareLeaseRequest request,
        CancellationToken cancellationToken);

    Task<CommitLeaseResponse> CommitAsync(
        CommitLeaseRequest request,
        CancellationToken cancellationToken);

    Task<DiagnosticsResponse> GetDiagnosticsAsync(CancellationToken cancellationToken);
}
