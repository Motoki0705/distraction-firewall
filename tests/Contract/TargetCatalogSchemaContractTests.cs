using System.Text.Json;
using DistractionFirewall.Core.Targets;
using Json.Schema;

namespace DistractionFirewall.ContractTests;

public sealed class TargetCatalogSchemaContractTests
{
    private static readonly Lazy<JsonSchema> CatalogSchema = new(() => JsonSchema.FromFile(
        Path.Combine(FindRepositoryRoot(), "config", "schemas", "target-catalog.v1.schema.json")));

    [Fact]
    public void Schema_conforms_to_its_declared_draft_2020_12_metaschema()
    {
        var path = Path.Combine(
            FindRepositoryRoot(),
            "config",
            "schemas",
            "target-catalog.v1.schema.json");
        using var document = JsonDocument.Parse(File.ReadAllText(path));

        var result = MetaSchemas.Draft202012.Evaluate(document.RootElement);

        Assert.Equal(MetaSchemas.Draft202012Id.OriginalString, document.RootElement
            .GetProperty("$schema")
            .GetString());
        Assert.True(result.IsValid, "The target catalog schema is not valid draft 2020-12 JSON Schema.");
    }

    [Fact]
    public async Task Production_and_valid_fixtures_are_accepted_by_schema_and_runtime()
    {
        var repositoryRoot = FindRepositoryRoot();
        var fixtureDirectory = Path.Combine(
            repositoryRoot,
            "config",
            "fixtures",
            "target-catalog",
            "v1",
            "valid");
        var paths = Directory.EnumerateFiles(fixtureDirectory, "*.json")
            .Append(Path.Combine(repositoryRoot, "config", "targets", "youtube.json"))
            .Order(StringComparer.Ordinal)
            .ToArray();
        var schema = CatalogSchema.Value;

        foreach (var path in paths)
        {
            using var document = JsonDocument.Parse(await File.ReadAllTextAsync(path));
            var result = schema.Evaluate(document.RootElement);

            Assert.True(result.IsValid, $"Schema rejected valid catalog '{Path.GetFileName(path)}'.");
            var catalog = await TargetCatalog.LoadAsync(path, CancellationToken.None);
            Assert.NotEmpty(catalog.Targets);
        }
    }

    [Fact]
    public async Task Invalid_fixtures_are_rejected_by_schema_and_runtime()
    {
        var repositoryRoot = FindRepositoryRoot();
        var fixtureDirectory = Path.Combine(
            repositoryRoot,
            "config",
            "fixtures",
            "target-catalog",
            "v1",
            "invalid");
        var schema = CatalogSchema.Value;

        foreach (var path in Directory.EnumerateFiles(fixtureDirectory, "*.json").Order(StringComparer.Ordinal))
        {
            using var document = JsonDocument.Parse(await File.ReadAllTextAsync(path));
            var result = schema.Evaluate(document.RootElement);

            Assert.False(result.IsValid, $"Schema accepted invalid catalog '{Path.GetFileName(path)}'.");
            await Assert.ThrowsAnyAsync<Exception>(
                () => TargetCatalog.LoadAsync(path, CancellationToken.None));
        }
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
