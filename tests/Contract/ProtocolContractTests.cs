using System.Reflection;
using System.Text.Json;
using DistractionFirewall.Contracts;

namespace DistractionFirewall.ContractTests;

public sealed class ProtocolContractTests
{
    [Fact]
    public void Supported_methods_have_no_early_release_operation()
    {
        var forbiddenWords = new[] { "cancel", "shorten", "extend", "removeactivetarget", "changeactivedeadline" };

        Assert.DoesNotContain(
            RpcMethods.Supported,
            method => forbiddenWords.Any(word => method.Contains(word, StringComparison.OrdinalIgnoreCase)));
    }

    [Fact]
    public void Public_contract_types_have_no_hidden_early_release_member()
    {
        var forbiddenWords = new[] { "CancelLease", "ShortenLease", "ExtendLease", "RemoveActiveTarget" };
        var exportedMembers = typeof(ProtocolConstants).Assembly
            .ExportedTypes
            .SelectMany(type => type.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static))
            .Select(member => member.Name)
            .ToArray();

        Assert.DoesNotContain(exportedMembers, name => forbiddenWords.Contains(name, StringComparer.OrdinalIgnoreCase));
    }

    [Fact]
    public void Protocol_json_is_snake_case_and_rejects_unknown_fields()
    {
        var request = new PrepareLeaseRequest(
            ProtocolConstants.CurrentVersion,
            Guid.Parse("b8dd021d-654e-40d7-8d52-2056ff0925ed"),
            ["youtube"],
            new LeaseEndRequest(LeaseEndMode.Duration, 60, null));

        var json = JsonSerializer.Serialize(request, ProtocolJson.CreateOptions());

        Assert.Contains("\"protocol_version\":1", json, StringComparison.Ordinal);
        Assert.Contains("\"duration_minutes\":60", json, StringComparison.Ordinal);
        Assert.Contains("\"mode\":\"duration\"", json, StringComparison.Ordinal);
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<PrepareLeaseRequest>(
            json.Insert(json.Length - 1, ",\"unexpected\":true"),
            ProtocolJson.CreateOptions()));
    }
}
