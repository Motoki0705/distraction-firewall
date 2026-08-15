using DistractionFirewall.Contracts;
using DistractionFirewall.Ipc;

namespace DistractionFirewall.ContractTests;

public sealed class PipeFrameCodecTests
{
    [Fact]
    public async Task Frame_round_trips_a_protocol_request()
    {
        await using var stream = new MemoryStream();
        var request = new RpcRequest(
            ProtocolConstants.CurrentVersion,
            Guid.Parse("94e15fc2-f649-4363-acf2-63e7b8fafdf0"),
            RpcMethods.GetStatus,
            System.Text.Json.JsonSerializer.SerializeToElement(new { }));

        await PipeFrameCodec.WriteAsync(
            stream,
            request,
            ProtocolJson.CreateOptions(),
            CancellationToken.None);
        stream.Position = 0;
        var roundTripped = await PipeFrameCodec.ReadAsync<RpcRequest>(
            stream,
            ProtocolJson.CreateOptions(),
            CancellationToken.None);

        Assert.Equal(request.RequestId, roundTripped.RequestId);
        Assert.Equal(RpcMethods.GetStatus, roundTripped.Method);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(1048577)]
    public async Task Frame_rejects_invalid_lengths(int length)
    {
        await using var stream = new MemoryStream(BitConverter.GetBytes(length));

        await Assert.ThrowsAsync<InvalidDataException>(() => PipeFrameCodec.ReadAsync<RpcRequest>(
            stream,
            ProtocolJson.CreateOptions(),
            CancellationToken.None));
    }
}
