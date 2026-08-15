namespace DistractionFirewall.UiTests;

public sealed class WpfAutomationTests
{
    [Fact(Skip = "Actual WPF UI Automation requires an interactive disposable Windows desktop with a UIA driver; the headless unit runner cannot validate real focus order, keyboard navigation, screen readers, high contrast, or text scaling.")]
    public void Real_window_keyboard_focus_and_accessibility_automation()
    {
        throw new NotSupportedException("This test is intentionally skipped until an interactive WPF automation harness is available.");
    }
}
