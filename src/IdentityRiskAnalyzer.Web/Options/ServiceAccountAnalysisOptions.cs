using System.ComponentModel.DataAnnotations;

namespace IdentityRiskAnalyzer.Web.Options;

public sealed class ServiceAccountAnalysisOptions : IValidatableObject
{
    public const string SectionName = "ServiceAccountAnalysis";

    public bool EnableNameHeuristics { get; set; } = true;
    public List<string> NamePatterns { get; set; } = [];

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (NamePatterns is null)
        {
            yield return new ValidationResult("NamePatterns cannot be null.", [nameof(NamePatterns)]);
            yield break;
        }

        for (var index = 0; index < NamePatterns.Count; index++)
        {
            var pattern = NamePatterns[index];
            if (string.IsNullOrWhiteSpace(pattern)
                || pattern.Length > 128
                || pattern.All(character => character == '*'))
            {
                yield return new ValidationResult(
                    $"Name pattern at index {index} must contain a non-wildcard character and be at most 128 characters long.",
                    [nameof(NamePatterns)]);
            }
        }
    }
}
