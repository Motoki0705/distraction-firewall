using System.Text.Json;
using DistractionFirewall.Contracts;
using DistractionFirewall.Core.Time;
using DistractionFirewall.Ipc;

namespace DistractionFirewall.ActivationService;

public sealed class ActivationRpcHandler
{
    private readonly LeaseActivationCoordinator _coordinator;
    private readonly ICallerAuthorizationPolicy _authorizationPolicy;

    public ActivationRpcHandler(
        LeaseActivationCoordinator coordinator,
        ICallerAuthorizationPolicy authorizationPolicy)
    {
        ArgumentNullException.ThrowIfNull(coordinator);
        ArgumentNullException.ThrowIfNull(authorizationPolicy);
        _coordinator = coordinator;
        _authorizationPolicy = authorizationPolicy;
    }

    public async Task<RpcResponse> HandleAsync(
        RpcConnection connection,
        RpcRequest request,
        CallerIdentity caller,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(caller);

        if (request.ProtocolVersion != ProtocolConstants.CurrentVersion)
        {
            return RpcConnection.Failure(
                request,
                LeaseErrorCode.UnsupportedProtocol,
                $"Protocol version {request.ProtocolVersion} is not supported.");
        }

        if (request.RequestId == Guid.Empty || !RpcMethods.Supported.Contains(request.Method))
        {
            return RpcConnection.Failure(
                request,
                LeaseErrorCode.InvalidRequest,
                "RPC request ID or method is invalid.");
        }

        if (!_authorizationPolicy.IsAuthorized(caller, request.Method))
        {
            return RpcConnection.Failure(
                request,
                LeaseErrorCode.UnauthorizedCaller,
                $"Caller authorization failed. {caller.Diagnostic} {_authorizationPolicy.Diagnostic}");
        }

        try
        {
            return request.Method switch
            {
                RpcMethods.GetCapabilities => connection.Success(
                    request,
                    LeaseActivationCoordinator.GetCapabilities()),
                RpcMethods.GetTargetCatalog => connection.Success(
                    request,
                    _coordinator.GetTargetCatalog()),
                RpcMethods.GetStatus or RpcMethods.WatchStatus => connection.Success(
                    request,
                    await _coordinator.GetStatusAsync(cancellationToken).ConfigureAwait(false)),
                RpcMethods.GetDiagnostics => connection.Success(
                    request,
                    await _coordinator.GetDiagnosticsAsync(cancellationToken).ConfigureAwait(false)),
                RpcMethods.PrepareLease => connection.Success(
                    request,
                    await PrepareAsync(connection, request, cancellationToken).ConfigureAwait(false)),
                RpcMethods.CommitLease => connection.Success(
                    request,
                    await CommitAsync(connection, request, cancellationToken).ConfigureAwait(false)),
                _ => RpcConnection.Failure(
                    request,
                    LeaseErrorCode.InvalidRequest,
                    $"RPC method '{request.Method}' is not implemented."),
            };
        }
        catch (LeaseOperationException exception)
        {
            return RpcConnection.Failure(
                request,
                exception.ErrorCode,
                exception.Message,
                exception.Retryable);
        }
        catch (LeaseValidationException exception)
        {
            return RpcConnection.Failure(request, exception.ErrorCode, exception.Message);
        }
        catch (Exception exception) when (
            exception is JsonException or InvalidDataException or ArgumentException or FormatException)
        {
            return RpcConnection.Failure(
                request,
                LeaseErrorCode.InvalidRequest,
                $"RPC payload is invalid: {exception.Message}");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            return RpcConnection.Failure(
                request,
                LeaseErrorCode.InternalError,
                $"RPC processing failed with {exception.GetType().Name}.",
                retryable: true);
        }
    }

    private async Task<PrepareLeaseResponse> PrepareAsync(
        RpcConnection connection,
        RpcRequest envelope,
        CancellationToken cancellationToken)
    {
        var request = connection.DeserializePayload<PrepareLeaseRequest>(envelope);
        EnsureMatchingRequestId(envelope.RequestId, request.RequestId);
        return await _coordinator.PrepareAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private async Task<CommitLeaseResponse> CommitAsync(
        RpcConnection connection,
        RpcRequest envelope,
        CancellationToken cancellationToken)
    {
        var request = connection.DeserializePayload<CommitLeaseRequest>(envelope);
        EnsureMatchingRequestId(envelope.RequestId, request.RequestId);
        return await _coordinator.CommitAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private static void EnsureMatchingRequestId(Guid envelopeRequestId, Guid payloadRequestId)
    {
        if (envelopeRequestId != payloadRequestId)
        {
            throw new LeaseOperationException(
                LeaseErrorCode.RequestReplayMismatch,
                "RPC envelope and payload request IDs do not match.");
        }
    }
}
