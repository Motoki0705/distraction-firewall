namespace DistractionFirewall.Enforcement.Windows.Mutation;

internal sealed class WindowsMutationGate
{
    private readonly bool _enabled;

    private WindowsMutationGate(bool enabled)
    {
        _enabled = enabled;
    }

    public bool IsEnabled => _enabled;

    public static WindowsMutationGate Disabled { get; } = new(false);

    internal static WindowsMutationGate CreateExplicitLiveWindows()
    {
        return new WindowsMutationGate(true);
    }

    internal static WindowsMutationGate CreateForTests()
    {
        return new WindowsMutationGate(true);
    }

    public void Demand()
    {
        if (!_enabled)
        {
            throw new InvalidOperationException(
                "Windows mutation is disabled. Construct the adapter through " +
                "WindowsEnforcementFactory.CreateLiveWindows to opt in explicitly.");
        }
    }
}
