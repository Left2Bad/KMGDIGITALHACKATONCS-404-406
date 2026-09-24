using System.ComponentModel.DataAnnotations;
using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Services.RiskRules;

namespace IdentityRiskAnalyzer.Web.Options;

public sealed class RiskSettings : IValidatableObject
{
    public const string SectionName = "RiskSettings";

    public int InactiveUserDays { get; set; } = 90;
    public int InactivePrivilegedUserDays { get; set; } = 30;
    public int OldPasswordDays { get; set; } = 180;
    public int MediumFrom { get; set; } = 25;
    public int HighFrom { get; set; } = 50;
    public int CriticalFrom { get; set; } = 75;
    public Dictionary<string, RiskRuleSettings> Rules { get; set; } = CreateDefaultRules();

    public RiskRuleSettings GetRule(string ruleId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleId);
        var pair = Rules.FirstOrDefault(item => string.Equals(item.Key, ruleId, StringComparison.OrdinalIgnoreCase));
        return pair.Value ?? throw new InvalidOperationException($"Risk settings are missing configuration for rule '{ruleId}'.");
    }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (InactiveUserDays <= 0)
        {
            yield return new ValidationResult("InactiveUserDays must be greater than zero.", [nameof(InactiveUserDays)]);
        }

        if (InactivePrivilegedUserDays <= 0)
        {
            yield return new ValidationResult("InactivePrivilegedUserDays must be greater than zero.", [nameof(InactivePrivilegedUserDays)]);
        }

        if (OldPasswordDays <= 0)
        {
            yield return new ValidationResult("OldPasswordDays must be greater than zero.", [nameof(OldPasswordDays)]);
        }

        if (MediumFrom < 0 || MediumFrom >= HighFrom || HighFrom >= CriticalFrom || CriticalFrom > 100)
        {
            yield return new ValidationResult(
                "Score thresholds must satisfy 0 <= MediumFrom < HighFrom < CriticalFrom <= 100.",
                [nameof(MediumFrom), nameof(HighFrom), nameof(CriticalFrom)]);
        }

        if (Rules is null)
        {
            yield return new ValidationResult("Rules cannot be null.", [nameof(Rules)]);
            yield break;
        }

        foreach (var ruleId in RiskRuleIds.All)
        {
            if (!Rules.Keys.Any(key => string.Equals(key, ruleId, StringComparison.OrdinalIgnoreCase)))
            {
                yield return new ValidationResult($"Risk settings are missing '{ruleId}'.", [nameof(Rules)]);
            }
        }

        var duplicateId = Rules.Keys
            .GroupBy(ruleId => ruleId, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicateId is not null)
        {
            yield return new ValidationResult($"Rule ID '{duplicateId.Key}' is configured more than once.", [nameof(Rules)]);
        }

        foreach (var (ruleId, settings) in Rules)
        {
            if (string.IsNullOrWhiteSpace(ruleId))
            {
                yield return new ValidationResult("Rule IDs cannot be empty.", [nameof(Rules)]);
                continue;
            }

            if (settings is null)
            {
                yield return new ValidationResult($"Settings for '{ruleId}' cannot be null.", [nameof(Rules)]);
                continue;
            }

            if (settings.RiskPoints < 0)
            {
                yield return new ValidationResult($"RiskPoints for '{ruleId}' cannot be negative.", [nameof(Rules)]);
            }

            if (!Enum.IsDefined(settings.Severity))
            {
                yield return new ValidationResult($"Severity for '{ruleId}' is invalid.", [nameof(Rules)]);
            }
        }
    }

    public static Dictionary<string, RiskRuleSettings> CreateDefaultRules() => new(StringComparer.OrdinalIgnoreCase)
    {
        [RiskRuleIds.StaleEnabledAccount] = new() { RiskPoints = 15, Severity = RiskSeverity.Medium },
        [RiskRuleIds.ExpiredAccount] = new() { RiskPoints = 10, Severity = RiskSeverity.Low },
        [RiskRuleIds.LockedAccount] = new() { RiskPoints = 5, Severity = RiskSeverity.Low },
        [RiskRuleIds.PasswordNeverExpires] = new() { RiskPoints = 15, Severity = RiskSeverity.Medium },
        [RiskRuleIds.OldPassword] = new() { RiskPoints = 10, Severity = RiskSeverity.Medium },
        [RiskRuleIds.ServicePasswordNeverExpires] = new() { RiskPoints = 25, Severity = RiskSeverity.High },
        [RiskRuleIds.DirectPrivilegedMembership] = new() { RiskPoints = 30, Severity = RiskSeverity.High },
        [RiskRuleIds.NestedPrivilegedMembership] = new() { RiskPoints = 30, Severity = RiskSeverity.High },
        [RiskRuleIds.MultipleAdministrativeRoles] = new() { RiskPoints = 20, Severity = RiskSeverity.Medium },
        [RiskRuleIds.InactivePrivilegedAccount] = new() { RiskPoints = 30, Severity = RiskSeverity.High },
        [RiskRuleIds.UnconstrainedDelegation] = new() { RiskPoints = 50, Severity = RiskSeverity.Critical },
        [RiskRuleIds.ConstrainedDelegation] = new() { RiskPoints = 20, Severity = RiskSeverity.Medium },
        [RiskRuleIds.ProtocolTransition] = new() { RiskPoints = 35, Severity = RiskSeverity.High },
        [RiskRuleIds.ResourceBasedConstrainedDelegation] = new() { RiskPoints = 25, Severity = RiskSeverity.High },
        [RiskRuleIds.SidHistoryPresent] = new() { RiskPoints = 15, Severity = RiskSeverity.Medium },
        [RiskRuleIds.DuplicateSpn] = new() { RiskPoints = 25, Severity = RiskSeverity.High },
        [RiskRuleIds.PossiblePasswordSpray] = new() { RiskPoints = 30, Severity = RiskSeverity.High },
        [RiskRuleIds.PossibleBruteForce] = new() { RiskPoints = 25, Severity = RiskSeverity.High }
    };
}
