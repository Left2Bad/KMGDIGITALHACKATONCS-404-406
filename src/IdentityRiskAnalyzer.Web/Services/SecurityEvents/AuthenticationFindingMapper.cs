using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Options;
using IdentityRiskAnalyzer.Web.Services.RiskRules;
using IdentityRiskAnalyzer.Web.Services.Scanning;

namespace IdentityRiskAnalyzer.Web.Services.SecurityEvents;

public static class AuthenticationFindingMapper
{
    public static IReadOnlyDictionary<Guid, IReadOnlyList<RiskFindingResult>> Map(
        IReadOnlyCollection<AuthenticationThreat> threats, IReadOnlyCollection<AdUserRecord> users, RiskSettings settings)
    {
        var usersBySam = users.Where(user => !string.IsNullOrWhiteSpace(user.SamAccountName))
            .GroupBy(user => user.SamAccountName!, StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Select(user => user.ObjectGuid).Distinct().Count() == 1)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);
        var output = new Dictionary<Guid, List<RiskFindingResult>>();
        var seen = new HashSet<(Guid Guid, string RuleId, string Correlation)>();
        foreach (var threat in threats)
        {
            var ruleId = threat.Type == AuthenticationThreatType.PossiblePasswordSpray
                ? RiskRuleIds.PossiblePasswordSpray : RiskRuleIds.PossibleBruteForce;
            var rule = settings.GetRule(ruleId);
            var names = threat.AffectedUserNames.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            var sample = string.Join(", ", names.Take(10));
            var more = names.Length > 10 ? $" (+{names.Length - 10} more)" : "";
            var evidence = $"Source: {threat.Source ?? "multiple or unknown"}; Window: {threat.WindowStartUtc:u} to {threat.WindowEndUtc:u}; " +
                $"failed attempts: {threat.FailedAttempts}; distinct usernames: {names.Length}; usernames: {sample}{more}.";
            foreach (var name in names)
            {
                if (!usersBySam.TryGetValue(name, out var user)) continue;
                var correlation = $"{threat.Source}:{threat.WindowStartUtc.Ticks}";
                if (!seen.Add((user.ObjectGuid, ruleId, correlation))) continue;
                var finding = new RiskFindingResult
                {
                    ObjectGuid = user.ObjectGuid, ObjectType = ScanSnapshotMapper.GetObjectType(user),
                    ObjectName = user.SamAccountName ?? user.DistinguishedName, RuleId = ruleId,
                    Category = RiskCategories.Authentication,
                    Title = threat.Type == AuthenticationThreatType.PossiblePasswordSpray ? "Possible Password Spray" : "Possible Brute Force",
                    Description = threat.Type == AuthenticationThreatType.PossiblePasswordSpray
                        ? "Multiple account names had failed authentications from one source in a short window."
                        : "This account had repeated failed authentications in a short window.",
                    Evidence = evidence,
                    Recommendation = "Review the authentication events and source, verify whether the activity is expected, and investigate account protection controls.",
                    RiskPoints = rule.RiskPoints, Severity = rule.Severity
                };
                if (!output.TryGetValue(user.ObjectGuid, out var list)) output[user.ObjectGuid] = list = [];
                list.Add(finding);
            }
        }
        return output.ToDictionary(item => item.Key, item => (IReadOnlyList<RiskFindingResult>)item.Value);
    }
}
