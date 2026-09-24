using System.ComponentModel.DataAnnotations;

namespace IdentityRiskAnalyzer.Web.Options;

public sealed class SecurityEventLogOptions : IValidatableObject
{
    public const string SectionName = "SecurityEventLog";
    public bool Enabled { get; set; }
    public string? Server { get; set; }
    public int LookbackMinutes { get; set; } = 60;
    public int PasswordSprayWindowMinutes { get; set; } = 10;
    public int PasswordSprayMinimumDistinctUsers { get; set; } = 5;
    public int PasswordSprayMinimumFailures { get; set; } = 10;
    public int BruteForceWindowMinutes { get; set; } = 10;
    public int BruteForceMinimumFailures { get; set; } = 10;
    public int MaximumEvents { get; set; } = 10_000;
    public int[] IncludeEventIds { get; set; } = [4625, 4771, 4776, 4740];

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (LookbackMinutes is < 1 or > 10_080) yield return Invalid(nameof(LookbackMinutes));
        if (PasswordSprayWindowMinutes is < 1 or > 10_080 || PasswordSprayWindowMinutes > LookbackMinutes)
            yield return Invalid(nameof(PasswordSprayWindowMinutes));
        if (BruteForceWindowMinutes is < 1 or > 10_080 || BruteForceWindowMinutes > LookbackMinutes)
            yield return Invalid(nameof(BruteForceWindowMinutes));
        if (PasswordSprayMinimumDistinctUsers < 2) yield return Invalid(nameof(PasswordSprayMinimumDistinctUsers));
        if (PasswordSprayMinimumFailures < 1) yield return Invalid(nameof(PasswordSprayMinimumFailures));
        if (BruteForceMinimumFailures < 1) yield return Invalid(nameof(BruteForceMinimumFailures));
        if (MaximumEvents is < 1 or > 100_000) yield return Invalid(nameof(MaximumEvents));
        if (IncludeEventIds is null || IncludeEventIds.Length == 0 || IncludeEventIds.Any(id => id is not (4625 or 4771 or 4776 or 4740)))
            yield return Invalid(nameof(IncludeEventIds));
    }

    private static ValidationResult Invalid(string member) => new($"SecurityEventLog:{member} is invalid.", [member]);
}
