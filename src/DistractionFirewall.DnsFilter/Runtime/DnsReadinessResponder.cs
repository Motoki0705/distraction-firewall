using DistractionFirewall.DnsFilter.DnsProtocol;

namespace DistractionFirewall.DnsFilter.Runtime;

public sealed class DnsReadinessResponder
{
    private readonly byte[] _token;

    public DnsReadinessResponder(ReadOnlySpan<byte> token)
    {
        if (token.Length != DnsReadyProbeProtocol.TokenByteLength)
        {
            throw new ArgumentException("The readiness token must contain exactly 32 bytes.", nameof(token));
        }

        _token = token.ToArray();
    }

    public bool TryCreateResponse(
        ReadOnlySpan<byte> query,
        DnsQuestion question,
        out byte[] response)
    {
        ArgumentNullException.ThrowIfNull(question);
        if (!DnsReadyProbeProtocol.IsReadinessQuestion(query, question))
        {
            response = [];
            return false;
        }

        response = DnsReadyProbeProtocol.CreateResponse(query, question, _token);
        return true;
    }
}
