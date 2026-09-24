using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.Services.RiskRules.Privilege;

internal static class PrivilegedMembershipRuleHelpers
{
    public static IReadOnlyList<PrivilegedMembershipResult> GetDistinctMemberships(AdRiskEvaluationContext context) =>
        (context.PrivilegeAnalysis?.PrivilegedMemberships ?? Array.Empty<PrivilegedMembershipResult>())
            .Where(membership => membership is not null)
            .GroupBy(GetIdentity, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .OrderBy(membership => membership.GroupName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(membership => membership.GroupObjectGuid)
            .ToArray();

    public static string FormatPath(AdRiskEvaluationContext context, PrivilegedMembershipResult membership)
    {
        var path = membership.PathDisplayNames?.Where(name => !string.IsNullOrWhiteSpace(name)).ToArray()
            ?? Array.Empty<string>();
        if (path.Length == 0)
        {
            return $"{context.ObjectName} → {membership.GroupName}";
        }

        if (!string.Equals(path[0], context.ObjectName, StringComparison.OrdinalIgnoreCase))
        {
            path = [context.ObjectName, .. path];
        }

        return string.Join(" → ", path);
    }

    private static string GetIdentity(PrivilegedMembershipResult membership) =>
        membership.GroupObjectGuid != Guid.Empty
            ? $"guid:{membership.GroupObjectGuid:D}"
            : $"dn:{membership.GroupDistinguishedName}";
}
