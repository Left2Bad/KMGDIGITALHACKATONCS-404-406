using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Options;
using Microsoft.Extensions.Options;

namespace IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

public sealed class ServiceAccountClassifier(
    ILogger<ServiceAccountClassifier> logger,
    IOptions<ServiceAccountAnalysisOptions> options)
{
    private const string MsaObjectClass = "msDS-ManagedServiceAccount";
    private const string GmsaObjectClass = "msDS-GroupManagedServiceAccount";
    private readonly ServiceAccountAnalysisOptions _options = options.Value;
    private readonly string[] _namePatterns = options.Value.NamePatterns
        .Where(pattern => !string.IsNullOrWhiteSpace(pattern))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();

    public ServiceAccountClassification Classify(AdUserRecord user)
    {
        ArgumentNullException.ThrowIfNull(user);

        var objectClasses = new HashSet<string>(user.ObjectClasses, StringComparer.OrdinalIgnoreCase);
        var isGmsa = objectClasses.Contains(GmsaObjectClass);
        // A gMSA is a managed service account subclass; treat the class hierarchy as one signal.
        var isMsa = !isGmsa && objectClasses.Contains(MsaObjectClass);
        var servicePrincipalNames = Deduplicate(user.ServicePrincipalNames);
        var matchedPatterns = _options.EnableNameHeuristics && !string.IsNullOrWhiteSpace(user.SamAccountName)
            ? _namePatterns.Where(pattern => MatchesPattern(user.SamAccountName, pattern)).ToArray()
            : Array.Empty<string>();

        var signalCount = (isGmsa || isMsa ? 1 : 0)
            + (servicePrincipalNames.Count > 0 ? 1 : 0)
            + (matchedPatterns.Length > 0 ? 1 : 0);
        var isServiceAccount = signalCount > 0;
        var method = signalCount switch
        {
            0 => ServiceAccountDetectionMethod.None,
            > 1 => ServiceAccountDetectionMethod.MultipleSignals,
            _ when isGmsa => ServiceAccountDetectionMethod.GroupManagedServiceAccount,
            _ when isMsa => ServiceAccountDetectionMethod.ManagedServiceAccount,
            _ when servicePrincipalNames.Count > 0 => ServiceAccountDetectionMethod.ServicePrincipalName,
            _ => ServiceAccountDetectionMethod.NameHeuristic
        };
        var confidence = isGmsa || isMsa
            ? ServiceAccountDetectionConfidence.Definitive
            : servicePrincipalNames.Count > 0
                ? ServiceAccountDetectionConfidence.High
                : matchedPatterns.Length > 0
                    ? ServiceAccountDetectionConfidence.Heuristic
                    : ServiceAccountDetectionConfidence.None;

        var evidence = new List<string>();
        if (isGmsa)
        {
            evidence.Add("Object class includes msDS-GroupManagedServiceAccount.");
        }
        else if (isMsa)
        {
            evidence.Add("Object class includes msDS-ManagedServiceAccount.");
        }

        if (servicePrincipalNames.Count > 0)
        {
            evidence.Add($"Account has {servicePrincipalNames.Count} Service Principal Name(s).");
        }

        evidence.AddRange(matchedPatterns.Select(pattern => $"Account name matches configured pattern: {pattern}"));

        return new ServiceAccountClassification
        {
            ObjectGuid = user.ObjectGuid,
            AccountName = GetAccountName(user),
            IsServiceAccount = isServiceAccount,
            DetectionMethod = method,
            Confidence = confidence,
            Evidence = evidence.AsReadOnly(),
            ServicePrincipalNames = servicePrincipalNames
        };
    }

    public IReadOnlyList<ServiceAccountClassification> ClassifyAll(
        IReadOnlyCollection<AdUserRecord> users,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(users);
        logger.LogInformation("Service account classification started for {UserCount} directory accounts.", users.Count);

        var results = new List<ServiceAccountClassification>(users.Count);
        foreach (var user in users)
        {
            cancellationToken.ThrowIfCancellationRequested();
            results.Add(Classify(user));
        }

        logger.LogInformation(
            "Service account classification completed: {UsersAnalysed} accounts, {ServiceAccounts} detected ({SpnCount} by SPN, {MsaCount} MSA, {GmsaCount} gMSA, {HeuristicCount} by name heuristic, {MultipleSignalCount} with multiple signals).",
            results.Count,
            results.Count(result => result.IsServiceAccount),
            results.Count(result => result.ServicePrincipalNames.Count > 0),
            results.Count(result => result.Evidence.Contains("Object class includes msDS-ManagedServiceAccount.", StringComparer.Ordinal)),
            results.Count(result => result.Evidence.Contains("Object class includes msDS-GroupManagedServiceAccount.", StringComparer.Ordinal)),
            results.Count(result => result.Evidence.Any(evidence => evidence.StartsWith(
                "Account name matches configured pattern:",
                StringComparison.Ordinal))),
            results.Count(result => result.DetectionMethod == ServiceAccountDetectionMethod.MultipleSignals));

        return results.AsReadOnly();
    }

    private static IReadOnlyList<string> Deduplicate(IEnumerable<string>? values)
    {
        if (values is null)
        {
            return Array.Empty<string>();
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var unique = new List<string>();
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value) && seen.Add(value.Trim()))
            {
                unique.Add(value);
            }
        }

        return unique.AsReadOnly();
    }

    private static bool MatchesPattern(string value, string pattern)
    {
        var segments = pattern.Split('*', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0)
        {
            return false;
        }

        var searchFrom = 0;
        for (var index = 0; index < segments.Length; index++)
        {
            var foundAt = value.IndexOf(segments[index], searchFrom, StringComparison.OrdinalIgnoreCase);
            if (foundAt < 0
                || (index == 0 && !pattern.StartsWith('*') && foundAt != 0)
                || (index == segments.Length - 1
                    && !pattern.EndsWith('*')
                    && foundAt + segments[index].Length != value.Length))
            {
                return false;
            }

            searchFrom = foundAt + segments[index].Length;
        }

        return true;
    }

    private static string GetAccountName(AdUserRecord user) =>
        FirstNonEmpty(user.SamAccountName, user.UserPrincipalName, user.DisplayName, user.DistinguishedName);

    private static string FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;
}
