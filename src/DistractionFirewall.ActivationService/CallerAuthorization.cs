using System.IO.Pipes;
using System.Security;
using System.Security.Principal;

namespace DistractionFirewall.ActivationService;

public sealed record CallerIdentity(string? Sid, bool Resolved, string Diagnostic);

public interface ICallerIdentityResolver
{
    CallerIdentity Resolve(NamedPipeServerStream pipe);
}

public interface ICallerAuthorizationPolicy
{
    string Diagnostic { get; }

    bool IsAuthorized(CallerIdentity identity, string method);
}

public sealed class WindowsNamedPipeCallerIdentityResolver : ICallerIdentityResolver
{
    public CallerIdentity Resolve(NamedPipeServerStream pipe)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        if (!pipe.IsConnected)
        {
            return new CallerIdentity(null, Resolved: false, "Named pipe client is not connected.");
        }

        string? sid = null;
        try
        {
            pipe.RunAsClient(() =>
            {
                using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
                sid = identity.User?.Value;
            });
        }
        catch (Exception exception) when (
            exception is IOException or InvalidOperationException or SecurityException or UnauthorizedAccessException)
        {
            return new CallerIdentity(
                null,
                Resolved: false,
                $"Caller SID resolution failed: {exception.GetType().Name}.");
        }

        return string.IsNullOrWhiteSpace(sid)
            ? new CallerIdentity(null, Resolved: false, "Caller token did not contain a SID.")
            : new CallerIdentity(sid, Resolved: true, "Caller SID resolved from pipe impersonation token.");
    }
}

public sealed class AllowListedCallerAuthorizationPolicy : ICallerAuthorizationPolicy
{
    private readonly HashSet<string> _allowedSids;

    public AllowListedCallerAuthorizationPolicy(IEnumerable<string> allowedSids, string? diagnostic = null)
    {
        ArgumentNullException.ThrowIfNull(allowedSids);
        _allowedSids = allowedSids
            .Where(sid => !string.IsNullOrWhiteSpace(sid))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        Diagnostic = diagnostic ?? (_allowedSids.Count == 0
            ? "No owner SID is provisioned; every RPC request is denied."
            : "Caller SID is checked against the provisioned owner allowlist after pipe ACL admission.");
    }

    public string Diagnostic { get; }

    public bool IsAuthorized(CallerIdentity identity, string method)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentException.ThrowIfNullOrWhiteSpace(method);
        return identity.Resolved &&
            identity.Sid is not null &&
            _allowedSids.Contains(identity.Sid);
    }
}
