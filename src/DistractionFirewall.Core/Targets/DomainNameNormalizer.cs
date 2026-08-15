using System.Globalization;

namespace DistractionFirewall.Core.Targets;

public static class DomainNameNormalizer
{
    private static readonly IdnMapping IdnMapping = new();

    public static string Normalize(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);

        var candidate = value.Trim().TrimEnd('.');
        if (candidate.Length is 0 or > 253 ||
            candidate.Contains("://", StringComparison.Ordinal) ||
            candidate.IndexOfAny(['/', '\\', ':', '*', ' ']) >= 0)
        {
            throw new FormatException($"'{value}' is not a valid DNS name.");
        }

        string ascii;
        try
        {
            ascii = IdnMapping.GetAscii(candidate).ToLowerInvariant();
        }
        catch (ArgumentException exception)
        {
            throw new FormatException($"'{value}' is not a valid international DNS name.", exception);
        }

        foreach (var label in ascii.Split('.'))
        {
            if (label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-')
            {
                throw new FormatException($"'{value}' contains an invalid DNS label.");
            }

            if (label.Any(character => !IsAsciiLetterOrDigit(character) && character != '-'))
            {
                throw new FormatException($"'{value}' contains a character that is not valid in DNS.");
            }
        }

        return ascii;
    }

    private static bool IsAsciiLetterOrDigit(char character) =>
        character is >= 'a' and <= 'z' or >= '0' and <= '9';
}
