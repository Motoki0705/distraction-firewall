using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;

namespace DistractionFirewall.ActivationService;

public interface IActivationPipeFactory
{
    NamedPipeServerStream Create();
}

public sealed class WindowsAclActivationPipeFactory : IActivationPipeFactory
{
    internal const uint RequiredOpenMode = WindowsNativeNamedPipeServerFactory.PipeAccessDuplex |
        WindowsNativeNamedPipeServerFactory.FileFlagOverlapped |
        WindowsNativeNamedPipeServerFactory.FileFlagWriteThrough |
        WindowsNativeNamedPipeServerFactory.FileFlagFirstPipeInstance;
    internal const uint RequiredPipeMode = WindowsNativeNamedPipeServerFactory.PipeRejectRemoteClients;

    private readonly SecurityIdentifier[] _allowedCallers;
    private readonly IWindowsNamedPipeServerFactory _nativeFactory;

    public WindowsAclActivationPipeFactory(IEnumerable<string> allowedCallerSids)
        : this(allowedCallerSids, new WindowsNativeNamedPipeServerFactory())
    {
    }

    internal WindowsAclActivationPipeFactory(
        IEnumerable<string> allowedCallerSids,
        IWindowsNamedPipeServerFactory nativeFactory)
    {
        ArgumentNullException.ThrowIfNull(allowedCallerSids);
        ArgumentNullException.ThrowIfNull(nativeFactory);
        try
        {
            _allowedCallers = allowedCallerSids
                .Where(sid => !string.IsNullOrWhiteSpace(sid))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Select(sid => new SecurityIdentifier(sid))
                .ToArray();
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException("The activation pipe caller allowlist contains an invalid SID.", exception);
        }

        _nativeFactory = nativeFactory;
    }

    public NamedPipeServerStream Create()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "The protected activation pipe requires Windows native named-pipe security.");
        }

        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var localSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, domainSid: null);
        var administrators = new SecurityIdentifier(
            WellKnownSidType.BuiltinAdministratorsSid,
            domainSid: null);
        security.AddAccessRule(new PipeAccessRule(
            localSystem,
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            administrators,
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        foreach (var caller in _allowedCallers)
        {
            security.AddAccessRule(new PipeAccessRule(
                caller,
                PipeAccessRights.ReadWrite,
                AccessControlType.Allow));
        }

        return _nativeFactory.Create(new WindowsNamedPipeCreationRequest(
            @"\\.\pipe\" + Contracts.ProtocolConstants.ActivationPipeName,
            RequiredOpenMode,
            RequiredPipeMode,
            MaxInstances: 1,
            OutBufferSize: 0,
            InBufferSize: 0,
            security.GetSecurityDescriptorBinaryForm()));
    }
}
