using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

namespace IdentityRiskAnalyzer.Web.Services.Delegation;

public sealed class DelegationAnalyzer(ILogger<DelegationAnalyzer> logger)
{
    public IReadOnlyList<DelegationAnalysisResult> Analyze(AdUserRecord user)
    {
        ArgumentNullException.ThrowIfNull(user);

        var results = new List<DelegationAnalysisResult>();
        var targets = DeduplicateTargets(user.AllowedToDelegateTo);
        var hasUnconstrainedDelegation = UserAccountControlHelper.HasUnconstrainedDelegation(user.UserAccountControl);
        var hasProtocolTransition = UserAccountControlHelper.HasProtocolTransition(user.UserAccountControl);

        if (hasUnconstrainedDelegation)
        {
            results.Add(CreateResult(
                user,
                DelegationType.Unconstrained,
                Array.Empty<string>(),
                "userAccountControl includes TRUSTED_FOR_DELEGATION."));
        }

        if (targets.Count > 0)
        {
            var delegationType = hasProtocolTransition
                ? DelegationType.ProtocolTransition
                : DelegationType.Constrained;
            var evidence = hasProtocolTransition
                ? $"TRUSTED_TO_AUTH_FOR_DELEGATION is enabled and msDS-AllowedToDelegateTo contains {targets.Count} target service(s):{Environment.NewLine}{string.Join(Environment.NewLine, targets)}"
                : $"msDS-AllowedToDelegateTo contains {targets.Count} target service(s):{Environment.NewLine}{string.Join(Environment.NewLine, targets)}";

            results.Add(CreateResult(user, delegationType, targets, evidence));
        }

        if (user.HasResourceBasedConstrainedDelegation)
        {
            results.Add(CreateResult(
                user,
                DelegationType.ResourceBasedConstrained,
                Array.Empty<string>(),
                "msDS-AllowedToActOnBehalfOfOtherIdentity is configured. Detailed ACL parsing is not implemented in the MVP.",
                requiresDetailedReview: true));
        }

        return results.AsReadOnly();
    }

    public IReadOnlyList<DelegationAnalysisResult> AnalyzeAll(
        IEnumerable<AdUserRecord> users,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(users);

        var results = new List<DelegationAnalysisResult>();
        var userCount = 0;
        foreach (var user in users)
        {
            cancellationToken.ThrowIfCancellationRequested();
            userCount++;
            results.AddRange(Analyze(user));
        }

        logger.LogInformation(
            "Kerberos delegation analysis completed for {UserCount} users; found {MechanismCount} delegation mechanisms.",
            userCount,
            results.Count);
        return results.AsReadOnly();
    }

    private static DelegationAnalysisResult CreateResult(
        AdUserRecord user,
        DelegationType delegationType,
        IReadOnlyList<string> targets,
        string evidence,
        bool requiresDetailedReview = false) => new()
    {
        ObjectGuid = user.ObjectGuid,
        ObjectName = user.SamAccountName
            ?? user.UserPrincipalName
            ?? user.DisplayName
            ?? user.DistinguishedName,
        DistinguishedName = user.DistinguishedName,
        DelegationType = delegationType,
        Targets = targets,
        Evidence = evidence,
        RequiresDetailedReview = requiresDetailedReview
    };

    private static IReadOnlyList<string> DeduplicateTargets(IEnumerable<string>? targets)
    {
        if (targets is null)
        {
            return Array.Empty<string>();
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var results = new List<string>();
        foreach (var target in targets)
        {
            if (string.IsNullOrWhiteSpace(target))
            {
                continue;
            }

            if (seen.Add(target.Trim()))
            {
                // Keep the original LDAP value for display and evidence.
                results.Add(target);
            }
        }

        return results.AsReadOnly();
    }
}
