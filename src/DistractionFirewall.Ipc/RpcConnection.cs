using System.Text.Json;
using DistractionFirewall.Contracts;

namespace DistractionFirewall.Ipc;

public sealed class RpcConnection
{
    private readonly Stream _stream;
    private readonly JsonSerializerOptions _serializerOptions;

    public RpcConnection(Stream stream, JsonSerializerOptions? serializerOptions = null)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead || !stream.CanWrite)
        {
            throw new ArgumentException("RPC stream must be readable and writable.", nameof(stream));
        }

        _stream = stream;
        _serializerOptions = serializerOptions ?? ProtocolJson.CreateOptions();
    }

    public Task<RpcRequest> ReadRequestAsync(CancellationToken cancellationToken) =>
        PipeFrameCodec.ReadAsync<RpcRequest>(_stream, _serializerOptions, cancellationToken);

    public Task WriteResponseAsync(RpcResponse response, CancellationToken cancellationToken) =>
        PipeFrameCodec.WriteAsync(_stream, response, _serializerOptions, cancellationToken);

    public T DeserializePayload<T>(RpcRequest request) =>
        request.Payload.Deserialize<T>(_serializerOptions)
        ?? throw new InvalidDataException("RPC request contained an empty payload.");

    public RpcResponse Success<T>(RpcRequest request, T payload) => new(
        ProtocolConstants.CurrentVersion,
        request.RequestId,
        Success: true,
        JsonSerializer.SerializeToElement(payload, _serializerOptions),
        Error: null);

    public static RpcResponse Failure(
        RpcRequest request,
        LeaseErrorCode code,
        string message,
        bool retryable = false) => new(
            ProtocolConstants.CurrentVersion,
            request.RequestId,
            Success: false,
            Payload: null,
            new RpcError(code, message, retryable));
}
