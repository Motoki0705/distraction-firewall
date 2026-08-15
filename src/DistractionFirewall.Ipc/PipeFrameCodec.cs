using System.Buffers.Binary;
using System.Text.Json;
using DistractionFirewall.Contracts;

namespace DistractionFirewall.Ipc;

public static class PipeFrameCodec
{
    private const int HeaderSize = sizeof(int);

    public static async Task WriteAsync<T>(
        Stream stream,
        T value,
        JsonSerializerOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(options);

        var payload = JsonSerializer.SerializeToUtf8Bytes(value, options);
        if (payload.Length > ProtocolConstants.MaximumFrameBytes)
        {
            throw new InvalidDataException($"RPC frame exceeds {ProtocolConstants.MaximumFrameBytes} bytes.");
        }

        var header = new byte[HeaderSize];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public static async Task<T> ReadAsync<T>(
        Stream stream,
        JsonSerializerOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(options);

        var header = new byte[HeaderSize];
        await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length is <= 0 or > ProtocolConstants.MaximumFrameBytes)
        {
            throw new InvalidDataException($"RPC frame length {length} is invalid.");
        }

        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(false);
        return JsonSerializer.Deserialize<T>(payload, options)
            ?? throw new InvalidDataException("RPC frame contained a JSON null value.");
    }
}
