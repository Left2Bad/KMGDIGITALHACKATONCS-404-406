using System.Globalization;

namespace IdentityRiskAnalyzer.Web.Services.GroupAnalysis;

public static class PrimaryGroupResolver
{
    public static bool TryCreatePrimaryGroupSid(
        string? userSid,
        int? primaryGroupId,
        out string? primaryGroupSid)
    {
        primaryGroupSid = null;
        if (string.IsNullOrWhiteSpace(userSid) || primaryGroupId is null or <= 0)
        {
            return false;
        }

        var components = userSid.Split('-');
        if (components.Length != 8
            || !string.Equals(components[0], "S", StringComparison.OrdinalIgnoreCase)
            || components[1] != "1"
            || components[2] != "5"
            || components[3] != "21")
        {
            return false;
        }

        for (var index = 4; index < components.Length; index++)
        {
            if (!uint.TryParse(components[index], NumberStyles.None, CultureInfo.InvariantCulture, out _))
            {
                return false;
            }
        }

        var domainSid = string.Join("-", components.Take(components.Length - 1));
        primaryGroupSid = string.Concat(
            domainSid,
            "-",
            primaryGroupId.Value.ToString(CultureInfo.InvariantCulture));
        return true;
    }
}
