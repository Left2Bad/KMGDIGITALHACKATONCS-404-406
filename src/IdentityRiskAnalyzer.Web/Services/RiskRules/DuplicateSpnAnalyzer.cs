using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.Services.RiskRules;

public sealed class DuplicateSpnAnalyzer
{
    public IReadOnlyDictionary<Guid, IReadOnlyList<DuplicateSpnEvidence>> AnalyzeAll(
        IEnumerable<AdUserRecord> principals)
    {
        ArgumentNullException.ThrowIfNull(principals);

        var assignmentsBySpn = new Dictionary<string, Dictionary<Guid, AdUserRecord>>(StringComparer.OrdinalIgnoreCase);
        foreach (var principal in principals)
        {
            ArgumentNullException.ThrowIfNull(principal);
            var seenOnPrincipal = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var value in principal.ServicePrincipalNames ?? Array.Empty<string>())
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }

                var normalizedSpn = value.Trim();
                if (!seenOnPrincipal.Add(normalizedSpn))
                {
                    continue;
                }

                if (!assignmentsBySpn.TryGetValue(normalizedSpn, out var assignments))
                {
                    assignments = new Dictionary<Guid, AdUserRecord>();
                    assignmentsBySpn.Add(normalizedSpn, assignments);
                }

                assignments.TryAdd(principal.ObjectGuid, principal);
            }
        }

        var evidenceByObject = new Dictionary<Guid, List<DuplicateSpnEvidence>>();
        foreach (var (spn, assignments) in assignmentsBySpn.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            if (assignments.Count < 2)
            {
                continue;
            }

            foreach (var (objectGuid, principal) in assignments.OrderBy(pair => GetName(pair.Value), StringComparer.OrdinalIgnoreCase))
            {
                if (!evidenceByObject.TryGetValue(objectGuid, out var evidence))
                {
                    evidence = [];
                    evidenceByObject.Add(objectGuid, evidence);
                }

                evidence.Add(new DuplicateSpnEvidence
                {
                    ObjectGuid = objectGuid,
                    ObjectName = GetName(principal),
                    ServicePrincipalName = spn,
                    OtherObjectNames = assignments
                        .Where(pair => pair.Key != objectGuid)
                        .Select(pair => GetName(pair.Value))
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                        .ToArray()
                });
            }
        }

        return evidenceByObject.ToDictionary(
            pair => pair.Key,
            pair => (IReadOnlyList<DuplicateSpnEvidence>)pair.Value.AsReadOnly());
    }

    private static string GetName(AdUserRecord principal) =>
        FirstNonEmpty(principal.SamAccountName, principal.UserPrincipalName, principal.DisplayName, principal.DistinguishedName);

    private static string FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;
}
