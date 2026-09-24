using System.Globalization;
using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Options;

namespace IdentityRiskAnalyzer.Web.Services.GroupAnalysis;

public static class PrivilegedGroupMatcher
{
    public static bool TryMatch(
        AdGroupRecord group,
        PrivilegedGroupDefinition definition,
        out PrivilegedGroupMatchMethod matchMethod)
    {
        ArgumentNullException.ThrowIfNull(group);
        ArgumentNullException.ThrowIfNull(definition);

        if (!definition.Enabled)
        {
            matchMethod = default;
            return false;
        }

        if (!string.IsNullOrWhiteSpace(definition.Sid)
            && !string.IsNullOrWhiteSpace(group.Sid)
            && string.Equals(definition.Sid.Trim(), group.Sid.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            matchMethod = PrivilegedGroupMatchMethod.Sid;
            return true;
        }

        if (definition.Rid is > 0 && HasDomainRelativeRid(group.Sid, definition.Rid.Value))
        {
            matchMethod = PrivilegedGroupMatchMethod.Rid;
            return true;
        }

        if (MatchesName(group.CommonName, definition.Name)
            || MatchesName(group.SamAccountName, definition.Name))
        {
            matchMethod = PrivilegedGroupMatchMethod.ConfiguredName;
            return true;
        }

        matchMethod = default;
        return false;
    }

    public static bool MatchesConfiguredName(string? groupName, PrivilegedGroupDefinition definition)
    {
        return definition.Enabled && MatchesName(groupName, definition.Name);
    }

    private static bool HasDomainRelativeRid(string? sid, int expectedRid)
    {
        if (string.IsNullOrWhiteSpace(sid))
        {
            return false;
        }

        var components = sid.Split('-');
        if (components.Length != 8
            || !string.Equals(components[0], "S", StringComparison.OrdinalIgnoreCase)
            || components[1] != "1"
            || components[2] != "5"
            || components[3] != "21"
            || !int.TryParse(components[^1], NumberStyles.None, CultureInfo.InvariantCulture, out var rid))
        {
            return false;
        }

        return rid == expectedRid
            && components.Skip(4).Take(3).All(component =>
                uint.TryParse(component, NumberStyles.None, CultureInfo.InvariantCulture, out _));
    }

    private static bool MatchesName(string? candidate, string configuredName)
    {
        return !string.IsNullOrWhiteSpace(candidate)
            && !string.IsNullOrWhiteSpace(configuredName)
            && string.Equals(candidate.Trim(), configuredName.Trim(), StringComparison.OrdinalIgnoreCase);
    }
}
