using System.Text.Json;

namespace DistractionFirewall.Contracts;

public sealed record RpcRequest(
    int ProtocolVersion,
    Guid RequestId,
    string Method,
    JsonElement Payload);

public sealed record RpcResponse(
    int ProtocolVersion,
    Guid RequestId,
    bool Success,
    JsonElement? Payload,
    RpcError? Error);

public sealed record RpcError(
    LeaseErrorCode Code,
    string Message,
    bool Retryable,
    IReadOnlyDictionary<string, string>? Details = null);
