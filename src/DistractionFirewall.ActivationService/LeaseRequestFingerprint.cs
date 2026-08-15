using System.Security.Cryptography;
using System.Text.Json;
using DistractionFirewall.Contracts;

namespace DistractionFirewall.ActivationService;

public static class LeaseRequestFingerprint
{
    public static string ForPrepare(PrepareLeaseRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber("protocol_version", request.ProtocolVersion);
            writer.WriteStartArray("target_ids");
            foreach (var targetId in request.TargetIds.Order(StringComparer.Ordinal))
            {
                writer.WriteStringValue(targetId);
            }

            writer.WriteEndArray();
            writer.WriteString("end_mode", request.End.Mode.ToString());
            if (request.End.DurationMinutes is { } durationMinutes)
            {
                writer.WriteNumber("duration_minutes", durationMinutes);
            }
            else
            {
                writer.WriteNull("duration_minutes");
            }

            if (request.End.UntilUtc is { } untilUtc)
            {
                writer.WriteString("until_utc", untilUtc.ToUniversalTime());
            }
            else
            {
                writer.WriteNull("until_utc");
            }

            writer.WriteString("input_time_zone_id", request.End.InputTimeZoneId);
            if (request.End.InputLocalTime is { } inputLocalTime)
            {
                writer.WriteString("input_local_time", DateTime.SpecifyKind(inputLocalTime, DateTimeKind.Unspecified));
            }
            else
            {
                writer.WriteNull("input_local_time");
            }

            writer.WriteEndObject();
        }

        return Convert.ToHexStringLower(SHA256.HashData(buffer.ToArray()));
    }

    public static string ForCommit(CommitLeaseRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber("protocol_version", request.ProtocolVersion);
            writer.WriteString("preparation_id", request.PreparationId);
            writer.WriteString("nonce_hash", LeaseNonceService.HashNonce(request.Nonce));
            writer.WriteEndObject();
        }

        return Convert.ToHexStringLower(SHA256.HashData(buffer.ToArray()));
    }
}
