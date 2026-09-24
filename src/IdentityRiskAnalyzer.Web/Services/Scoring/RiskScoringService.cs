using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Options;
using Microsoft.Extensions.Options;

namespace IdentityRiskAnalyzer.Web.Services.Scoring;

public sealed class RiskScoringService(
    IOptions<RiskSettings> options,
    ILogger<RiskScoringService> logger)
{
    private const int MaximumScore = 100;
    private readonly RiskSettings _settings = options.Value;

    public ObjectRiskScoreResult ScoreObject(
        Guid objectGuid,
        string objectName,
        IEnumerable<RiskFindingResult> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);
        var uniqueFindings = DeduplicateFindings(findings)
            .Where(finding => finding.ObjectGuid == objectGuid)
            .ToArray();

        long totalPoints = 0;
        foreach (var finding in uniqueFindings)
        {
            var points = Math.Max(finding.RiskPoints, 0);
            totalPoints = totalPoints > long.MaxValue - points
                ? long.MaxValue
                : totalPoints + points;
        }

        var displayedRawScore = (int)Math.Min(totalPoints, int.MaxValue);
        var score = (int)Math.Min(totalPoints, MaximumScore);
        return new ObjectRiskScoreResult
        {
            ObjectGuid = objectGuid,
            ObjectName = string.IsNullOrWhiteSpace(objectName)
                ? uniqueFindings.Select(finding => finding.ObjectName).FirstOrDefault(name => !string.IsNullOrWhiteSpace(name)) ?? string.Empty
                : objectName,
            RawScore = displayedRawScore,
            RiskScore = score,
            RiskLevel = GetRiskLevel(score),
            FindingsCount = uniqueFindings.Length,
            CriticalFindings = uniqueFindings.Count(finding => finding.Severity == RiskSeverity.Critical),
            HighFindings = uniqueFindings.Count(finding => finding.Severity == RiskSeverity.High),
            MediumFindings = uniqueFindings.Count(finding => finding.Severity == RiskSeverity.Medium),
            LowFindings = uniqueFindings.Count(finding => finding.Severity == RiskSeverity.Low),
            Findings = uniqueFindings
        };
    }

    public IReadOnlyList<ObjectRiskScoreResult> ScoreObjects(
        IEnumerable<RiskScoringObject> objects,
        IEnumerable<RiskFindingResult> findings)
    {
        ArgumentNullException.ThrowIfNull(objects);
        ArgumentNullException.ThrowIfNull(findings);

        var uniqueFindings = DeduplicateFindings(findings).ToArray();
        var inputNamesByObject = new Dictionary<Guid, List<string>>();
        var findingNamesByObject = new Dictionary<Guid, List<string>>();
        foreach (var scoringObject in objects)
        {
            ArgumentNullException.ThrowIfNull(scoringObject);
            AddName(inputNamesByObject, scoringObject.ObjectGuid, scoringObject.ObjectName);
        }

        foreach (var finding in uniqueFindings)
        {
            AddName(findingNamesByObject, finding.ObjectGuid, finding.ObjectName);
        }

        var findingsByObject = uniqueFindings
            .GroupBy(finding => finding.ObjectGuid)
            .ToDictionary(group => group.Key, group => (IReadOnlyList<RiskFindingResult>)group.ToArray());

        return inputNamesByObject.Keys
            .Concat(findingNamesByObject.Keys)
            .Distinct()
            .OrderBy(objectGuid => objectGuid)
            .Select(objectGuid =>
            {
                var preferredNames = inputNamesByObject.TryGetValue(objectGuid, out var inputNames)
                    ? inputNames
                    : findingNamesByObject[objectGuid];
                var objectName = preferredNames
                    .Where(name => !string.IsNullOrWhiteSpace(name))
                    .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(name => name, StringComparer.Ordinal)
                    .FirstOrDefault() ?? string.Empty;
                if (string.IsNullOrWhiteSpace(objectName)
                    && findingNamesByObject.TryGetValue(objectGuid, out var fallbackNames))
                {
                    objectName = fallbackNames
                        .Where(name => !string.IsNullOrWhiteSpace(name))
                        .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                        .ThenBy(name => name, StringComparer.Ordinal)
                        .FirstOrDefault() ?? string.Empty;
                }

                findingsByObject.TryGetValue(objectGuid, out var objectFindings);
                return ScoreObject(objectGuid, objectName, objectFindings ?? Array.Empty<RiskFindingResult>());
            })
            .ToArray();
    }

    public AdSecurityScoreResult ScoreAll(
        IEnumerable<RiskScoringObject> objects,
        IEnumerable<RiskFindingResult> findings,
        int topRiskyObjectsCount = 10)
    {
        ArgumentNullException.ThrowIfNull(findings);
        var uniqueFindings = DeduplicateFindings(findings).ToArray();
        var objectsScored = ScoreObjects(objects, uniqueFindings);
        return Summarize(objectsScored, topRiskyObjectsCount);
    }

    public AdSecurityScoreResult Summarize(
        IEnumerable<ObjectRiskScoreResult> objectScores,
        int topRiskyObjectsCount = 10)
    {
        ArgumentNullException.ThrowIfNull(objectScores);
        ArgumentOutOfRangeException.ThrowIfNegative(topRiskyObjectsCount);

        var uniqueObjects = objectScores
            .Where(score => score is not null)
            .GroupBy(score => score.ObjectGuid)
            .Select(group => group
                .OrderByDescending(score => score.RiskScore)
                .ThenByDescending(score => score.RawScore)
                .ThenByDescending(score => score.FindingsCount)
                .ThenByDescending(score => (int)score.RiskLevel)
                .ThenBy(score => score.ObjectName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(score => score.ObjectName, StringComparer.Ordinal)
                .ThenBy(BuildFindingSignature, StringComparer.Ordinal)
                .First())
            .ToArray();
        var allFindings = DeduplicateFindings(uniqueObjects.SelectMany(score => score.Findings ?? Array.Empty<RiskFindingResult>()))
            .ToArray();

        if (uniqueObjects.Length == 0)
        {
            return new AdSecurityScoreResult
            {
                SecurityScore = null,
                AnalysedObjects = 0,
                AverageRiskScore = null,
                TotalFindings = allFindings.Length,
                CategorySummaries = BuildCategorySummaries(allFindings),
                TopRiskyObjects = Array.Empty<ObjectRiskScoreResult>()
            };
        }

        var averageRiskScore = uniqueObjects.Average(score => score.RiskScore);
        var securityScore = (int)Math.Round(MaximumScore - averageRiskScore, MidpointRounding.AwayFromZero);
        securityScore = Math.Clamp(securityScore, 0, MaximumScore);

        var result = new AdSecurityScoreResult
        {
            SecurityScore = securityScore,
            AnalysedObjects = uniqueObjects.Length,
            AverageRiskScore = averageRiskScore,
            CriticalObjects = uniqueObjects.Count(score => score.RiskLevel == RiskSeverity.Critical),
            HighRiskObjects = uniqueObjects.Count(score => score.RiskLevel == RiskSeverity.High),
            MediumRiskObjects = uniqueObjects.Count(score => score.RiskLevel == RiskSeverity.Medium),
            LowRiskObjects = uniqueObjects.Count(score => score.RiskLevel == RiskSeverity.Low),
            TotalFindings = allFindings.Length,
            CriticalFindings = allFindings.Count(finding => finding.Severity == RiskSeverity.Critical),
            HighFindings = allFindings.Count(finding => finding.Severity == RiskSeverity.High),
            MediumFindings = allFindings.Count(finding => finding.Severity == RiskSeverity.Medium),
            LowFindings = allFindings.Count(finding => finding.Severity == RiskSeverity.Low),
            CategorySummaries = BuildCategorySummaries(allFindings),
            TopRiskyObjects = uniqueObjects
                .OrderByDescending(score => score.RiskScore)
                .ThenByDescending(score => score.CriticalFindings)
                .ThenByDescending(score => score.FindingsCount)
                .ThenBy(score => score.ObjectName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(score => score.ObjectName, StringComparer.Ordinal)
                .ThenBy(score => score.ObjectGuid)
                .Take(topRiskyObjectsCount)
                .ToArray()
        };

        logger.LogInformation(
            "Risk scoring completed. Objects: {Objects}; Critical: {CriticalObjects}; High: {HighObjects}; Average risk: {AverageRiskScore}; AD Security Score: {SecurityScore}.",
            result.AnalysedObjects,
            result.CriticalObjects,
            result.HighRiskObjects,
            result.AverageRiskScore,
            result.SecurityScore);
        return result;
    }

    private RiskSeverity GetRiskLevel(int score)
    {
        if (score >= _settings.CriticalFrom)
        {
            return RiskSeverity.Critical;
        }

        if (score >= _settings.HighFrom)
        {
            return RiskSeverity.High;
        }

        if (score >= _settings.MediumFrom)
        {
            return RiskSeverity.Medium;
        }

        return RiskSeverity.Low;
    }

    private static IReadOnlyList<RiskFindingResult> DeduplicateFindings(IEnumerable<RiskFindingResult> findings) => findings
        .Where(finding => finding is not null)
        .GroupBy(finding => new FindingIdentity(
            finding.ObjectGuid,
            finding.RuleId,
            finding.Category,
            finding.Evidence ?? finding.Title ?? finding.Description), FindingIdentityComparer.Instance)
        .Select(group => group
            .OrderByDescending(finding => finding.RiskPoints)
            .ThenByDescending(finding => (int)finding.Severity)
            .ThenBy(finding => finding.Title, StringComparer.Ordinal)
            .ThenBy(finding => finding.Description, StringComparer.Ordinal)
            .ThenBy(finding => finding.Recommendation, StringComparer.Ordinal)
            .ThenBy(finding => finding.ObjectName, StringComparer.Ordinal)
            .First())
        .OrderBy(finding => finding.ObjectGuid)
        .ThenBy(finding => finding.RuleId, StringComparer.Ordinal)
        .ThenBy(finding => finding.Evidence, StringComparer.Ordinal)
        .ToArray();

    private static IReadOnlyList<RiskCategorySummary> BuildCategorySummaries(IReadOnlyCollection<RiskFindingResult> findings) => findings
        .Where(finding => !string.IsNullOrWhiteSpace(finding.Category))
        .GroupBy(finding => finding.Category.Trim(), StringComparer.OrdinalIgnoreCase)
        .Select(group => new RiskCategorySummary
        {
            Category = group.Select(finding => finding.Category.Trim())
                .OrderBy(category => category, StringComparer.OrdinalIgnoreCase)
                .ThenBy(category => category, StringComparer.Ordinal)
                .First(),
            FindingsCount = group.Count(),
            AffectedObjects = group.Select(finding => finding.ObjectGuid).Distinct().Count()
        })
        .OrderBy(summary => summary.Category, StringComparer.OrdinalIgnoreCase)
        .ThenBy(summary => summary.Category, StringComparer.Ordinal)
        .ToArray();

    private static string BuildFindingSignature(ObjectRiskScoreResult score) => string.Join(
        "\n",
        (score.Findings ?? Array.Empty<RiskFindingResult>())
            .OrderBy(finding => finding.RuleId, StringComparer.Ordinal)
            .ThenBy(finding => finding.Evidence, StringComparer.Ordinal)
            .Select(finding => $"{finding.RuleId}\0{finding.Category}\0{finding.Evidence}\0{finding.RiskPoints}\0{(int)finding.Severity}"));

    private static void AddName(Dictionary<Guid, List<string>> namesByObject, Guid objectGuid, string? objectName)
    {
        if (!namesByObject.TryGetValue(objectGuid, out var names))
        {
            names = [];
            namesByObject.Add(objectGuid, names);
        }

        if (!string.IsNullOrWhiteSpace(objectName))
        {
            names.Add(objectName.Trim());
        }
    }

    private sealed record FindingIdentity(Guid ObjectGuid, string RuleId, string Category, string? EvidenceKey);

    private sealed class FindingIdentityComparer : IEqualityComparer<FindingIdentity>
    {
        public static FindingIdentityComparer Instance { get; } = new();

        public bool Equals(FindingIdentity? x, FindingIdentity? y) =>
            ReferenceEquals(x, y)
            || (x is not null && y is not null
                && x.ObjectGuid == y.ObjectGuid
                && string.Equals(x.RuleId, y.RuleId, StringComparison.OrdinalIgnoreCase)
                && string.Equals(x.Category, y.Category, StringComparison.OrdinalIgnoreCase)
                && string.Equals(x.EvidenceKey, y.EvidenceKey, StringComparison.OrdinalIgnoreCase));

        public int GetHashCode(FindingIdentity value) => HashCode.Combine(
            value.ObjectGuid,
            StringComparer.OrdinalIgnoreCase.GetHashCode(value.RuleId ?? string.Empty),
            StringComparer.OrdinalIgnoreCase.GetHashCode(value.Category ?? string.Empty),
            value.EvidenceKey is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(value.EvidenceKey));
    }
}
