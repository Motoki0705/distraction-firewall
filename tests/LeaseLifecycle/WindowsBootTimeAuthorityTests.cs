using DistractionFirewall.Runtime.Windows;

namespace DistractionFirewall.LeaseLifecycleTests;

public sealed class WindowsBootTimeAuthorityTests
{
    [Fact]
    public void Separate_process_compositions_share_identifier_for_same_boot()
    {
        var source = new FakeBootIdentifierSource("boot-a");
        var firstProcess = new WindowsBootTimeAuthority(source);
        var secondProcess = new WindowsBootTimeAuthority(source);

        Assert.Equal(firstProcess.Capture().BootId, secondProcess.Capture().BootId);
    }

    [Fact]
    public void Reboot_identifier_change_is_observed_by_new_composition()
    {
        var source = new FakeBootIdentifierSource("boot-a");
        var beforeReboot = new WindowsBootTimeAuthority(source);
        source.Identifier = "boot-b";
        var afterReboot = new WindowsBootTimeAuthority(source);

        Assert.NotEqual(beforeReboot.Capture().BootId, afterReboot.Capture().BootId);
        Assert.Equal("boot-a", beforeReboot.Capture().BootId);
        Assert.Equal("boot-b", afterReboot.Capture().BootId);
    }

    private sealed class FakeBootIdentifierSource : IWindowsBootIdentifierSource
    {
        public FakeBootIdentifierSource(string identifier)
        {
            Identifier = identifier;
        }

        public string Identifier { get; set; }

        public string GetBootIdentifier() => Identifier;
    }
}
