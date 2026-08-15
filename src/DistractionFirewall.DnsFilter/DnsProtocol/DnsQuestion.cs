namespace DistractionFirewall.DnsFilter.DnsProtocol;

public sealed record DnsQuestion(
    ushort TransactionId,
    string Name,
    ushort Type,
    ushort Class,
    int QuestionEndOffset);

public sealed class DnsProtocolException(string message) : Exception(message);
