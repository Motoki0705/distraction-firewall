using System.IO.Pipes;
using DistractionFirewall.Ipc;

namespace DistractionFirewall.ActivationService;

public sealed class NamedPipeActivationServer
{
    private readonly ActivationRpcHandler _handler;
    private readonly ICallerIdentityResolver _identityResolver;
    private readonly IActivationPipeFactory _pipeFactory;
    private readonly TextWriter _diagnosticWriter;

    public NamedPipeActivationServer(
        ActivationRpcHandler handler,
        ICallerIdentityResolver identityResolver,
        IActivationPipeFactory pipeFactory,
        TextWriter? diagnosticWriter = null)
    {
        ArgumentNullException.ThrowIfNull(handler);
        ArgumentNullException.ThrowIfNull(identityResolver);
        ArgumentNullException.ThrowIfNull(pipeFactory);
        _handler = handler;
        _identityResolver = identityResolver;
        _pipeFactory = pipeFactory;
        _diagnosticWriter = diagnosticWriter ?? TextWriter.Null;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await using var pipe = _pipeFactory.Create();
            try
            {
                await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                await HandleConnectionAsync(pipe, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                await _diagnosticWriter.WriteLineAsync(
                    $"Activation pipe connection failed: {exception.GetType().Name}.").ConfigureAwait(false);
            }
        }
    }

    private async Task HandleConnectionAsync(
        NamedPipeServerStream pipe,
        CancellationToken cancellationToken)
    {
        var connection = new RpcConnection(pipe);
        var request = await connection.ReadRequestAsync(cancellationToken).ConfigureAwait(false);
        var caller = _identityResolver.Resolve(pipe);
        var response = await _handler.HandleAsync(
            connection,
            request,
            caller,
            cancellationToken).ConfigureAwait(false);
        await connection.WriteResponseAsync(response, cancellationToken).ConfigureAwait(false);
    }
}
