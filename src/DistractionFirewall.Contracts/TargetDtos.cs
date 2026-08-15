namespace DistractionFirewall.Contracts;

public sealed record TargetDescriptor(
    string StableId,
    string DisplayName,
    string Description,
    string CatalogVersion,
    IReadOnlyList<string> Coverage,
    IReadOnlyList<string> KnownCollateral);

public sealed record TargetSnapshotDto(
    string StableId,
    string DisplayName,
    string CatalogVersion,
    string DefinitionHash);

public sealed record GetTargetCatalogResponse(
    int ProtocolVersion,
    IReadOnlyList<TargetDescriptor> Targets);
