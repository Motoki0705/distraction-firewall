using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using DistractionFirewall.Contracts;

namespace DistractionFirewall.Ipc;

public sealed class NamedPipeRpcClient
{
    private readonly string _pipeName;
    private readonly JsonSerializerOptions _serializerOptions;
    private readonly INamedPipeServerIdentityVerifier _serverIdentityVerifier;

    public NamedPipeRpcClient(
        string pipeName = ProtocolConstants.ActivationPipeName,
        JsonSerializerOptions? serializerOptions = null)
        : this(
            pipeName,
            serializerOptions,
            WindowsNamedPipeServerIdentityVerifier.CreateDefault())
    {
    }

    internal NamedPipeRpcClient(
        string pipeName,
        JsonSerializerOptions? serializerOptions,
        INamedPipeServerIdentityVerifier serverIdentityVerifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);
        ArgumentNullException.ThrowIfNull(serverIdentityVerifier);
        _pipeName = pipeName;
        _serializerOptions = serializerOptions ?? ProtocolJson.CreateOptions();
        _serverIdentityVerifier = serverIdentityVerifier;
    }

    public async Task<TResponse> CallAsync<TRequest, TResponse>(
        string method,
        TRequest request,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(method);
        if (!RpcMethods.Supported.Contains(method))
        {
            throw new ArgumentOutOfRangeException(nameof(method), method, "Unknown RPC method.");
        }

        if (timeout <= TimeSpan.Zero || timeout.TotalMilliseconds > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        var requestId = GetRequestId(request);
        var envelope = new RpcRequest(
            ProtocolConstants.CurrentVersion,
            requestId,
            method,
            JsonSerializer.SerializeToElement(request, _serializerOptions));

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        var callCancellationToken = timeoutSource.Token;
        await using var pipe = new NamedPipeClientStream(
            ".",
            _pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.WriteThrough,
            TokenImpersonationLevel.Identification);
        RpcResponse response;
        try
        {
            await pipe.ConnectAsync(checked((int)timeout.TotalMilliseconds), callCancellationToken).ConfigureAwait(false);
            _serverIdentityVerifier.Verify(pipe.SafePipeHandle);
            await PipeFrameCodec.WriteAsync(
                pipe,
                envelope,
                _serializerOptions,
                callCancellationToken).ConfigureAwait(false);
            response = await PipeFrameCodec.ReadAsync<RpcResponse>(
                pipe,
                _serializerOptions,
                callCancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException($"RPC call '{method}' exceeded its {timeout} timeout.", exception);
        }

        if (response.RequestId != requestId)
        {
            throw new RpcClientException(
                LeaseErrorCode.StateConflict,
                "RPC response request ID did not match the request.",
                retryable: false);
        }

        if (response.ProtocolVersion != ProtocolConstants.CurrentVersion)
        {
            throw new RpcClientException(
                LeaseErrorCode.UnsupportedProtocol,
                $"Service returned protocol version {response.ProtocolVersion}.",
                retryable: false);
        }

        if (!response.Success)
        {
            var error = response.Error ?? new RpcError(
                LeaseErrorCode.InternalError,
                "Service returned an error without details.",
                Retryable: false);
            throw new RpcClientException(error.Code, error.Message, error.Retryable);
        }

        if (response.Payload is null)
        {
            throw new RpcClientException(
                LeaseErrorCode.InternalError,
                "Service returned success without a payload.",
                retryable: false);
        }

        return response.Payload.Value.Deserialize<TResponse>(_serializerOptions)
            ?? throw new RpcClientException(
                LeaseErrorCode.InternalError,
                "Service returned an empty response payload.",
                retryable: false);
    }

    private static Guid GetRequestId<TRequest>(TRequest request) => request switch
    {
        PrepareLeaseRequest prepare => prepare.RequestId,
        CommitLeaseRequest commit => commit.RequestId,
        _ => Guid.NewGuid(),
    };
}

public sealed class RpcClientException : Exception
{
    public RpcClientException(LeaseErrorCode errorCode, string message, bool retryable)
        : base(message)
    {
        ErrorCode = errorCode;
        Retryable = retryable;
    }

    public LeaseErrorCode ErrorCode { get; }

    public bool Retryable { get; }
}
