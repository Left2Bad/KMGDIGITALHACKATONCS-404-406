using System.Globalization;

namespace IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

public static class LdapAttributeRangeParser
{
    private const string RangePrefix = "member;range=";

    public static bool TryParse(string? attributeName, out LdapAttributeRange range)
    {
        range = default;
        if (attributeName is null || !attributeName.StartsWith(RangePrefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var bounds = attributeName.AsSpan(RangePrefix.Length);
        var separator = bounds.IndexOf('-');
        if (separator <= 0 || separator == bounds.Length - 1)
        {
            return false;
        }

        if (!long.TryParse(bounds[..separator], NumberStyles.None, CultureInfo.InvariantCulture, out var start))
        {
            return false;
        }

        var endText = bounds[(separator + 1)..];
        if (endText.SequenceEqual("*"))
        {
            range = new LdapAttributeRange(start, null, IsFinal: true);
            return true;
        }

        if (!long.TryParse(endText, NumberStyles.None, CultureInfo.InvariantCulture, out var end) || end < start)
        {
            return false;
        }

        range = new LdapAttributeRange(start, end, IsFinal: false);
        return true;
    }
}
