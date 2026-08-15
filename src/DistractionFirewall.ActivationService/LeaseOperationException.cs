using DistractionFirewall.Contracts;

namespace DistractionFirewall.ActivationService;

public sealed class LeaseOperationException : Exception
{
    public LeaseOperationException(LeaseErrorCode errorCode, string message, bool retryable = false)
        : base(message)
    {
        ErrorCode = errorCode;
        Retryable = retryable;
    }

    public LeaseOperationException(
        LeaseErrorCode errorCode,
        string message,
        Exception innerException,
        bool retryable = false)
        : base(message, innerException)
    {
        ErrorCode = errorCode;
        Retryable = retryable;
    }

    public LeaseErrorCode ErrorCode { get; }

    public bool Retryable { get; }
}
