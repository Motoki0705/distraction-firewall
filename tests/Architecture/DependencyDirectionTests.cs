using System.Xml.Linq;

namespace DistractionFirewall.ArchitectureTests;

public sealed class DependencyDirectionTests
{
    [Fact]
    public void Core_depends_only_on_contracts()
    {
        var references = ReadProjectReferences("src/DistractionFirewall.Core/DistractionFirewall.Core.csproj");

        Assert.Equal(["DistractionFirewall.Contracts"], references);
    }

    [Fact]
    public void App_and_cli_do_not_reference_privileged_projects()
    {
        var appReferences = ReadProjectReferences("src/DistractionFirewall.App/DistractionFirewall.App.csproj");
        var cliReferences = ReadProjectReferences("src/DistractionFirewall.Cli/DistractionFirewall.Cli.csproj");

        Assert.Equal(["DistractionFirewall.Contracts", "DistractionFirewall.Ipc"], appReferences);
        Assert.Equal(["DistractionFirewall.Contracts", "DistractionFirewall.Ipc"], cliReferences);
    }

    [Fact]
    public void Windows_enforcement_does_not_reference_app_or_runtime_hosts()
    {
        var references = ReadProjectReferences(
            "src/DistractionFirewall.Enforcement.Windows/DistractionFirewall.Enforcement.Windows.csproj");

        Assert.Equal(["DistractionFirewall.Core"], references);
    }

    private static string[] ReadProjectReferences(string relativeProjectPath)
    {
        var root = FindRepositoryRoot();
        var document = XDocument.Load(Path.Combine(root, relativeProjectPath));
        return document
            .Descendants("ProjectReference")
            .Select(reference => Path.GetFileNameWithoutExtension(reference.Attribute("Include")!.Value))
            .Order(StringComparer.Ordinal)
            .ToArray();
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "DistractionFirewall.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new DirectoryNotFoundException("Could not locate repository root.");
    }
}
