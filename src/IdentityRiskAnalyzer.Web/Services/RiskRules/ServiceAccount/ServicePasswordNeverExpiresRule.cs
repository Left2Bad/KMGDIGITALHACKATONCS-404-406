using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

namespace IdentityRiskAnalyzer.Web.Services.RiskRules.ServiceAccount;

public sealed class ServicePasswordNeverExpiresRule : AdRiskRuleBase
{
    public override string RuleId => RiskRuleIds.ServicePasswordNeverExpires;
    public override string Category => RiskCategories.ServiceAccount;
    protected override string Title => "Service account password never expires";
    protected override string Description => "A classified service account is configured so its password does not expire.";
    protected override string Recommendation => "Подтвердить владельца и способ управления учетной записью, затем проверить возможность безопасной ротации секрета.";

    public override IEnumerable<RiskFindingResult> Evaluate(AdRiskEvaluationContext context)
    {
        var classification = context.ServiceAccountClassification;
        if (classification is null
            || !classification.IsServiceAccount
            || !UserAccountControlHelper.HasFlag(context.User.UserAccountControl, UserAccountControlFlags.DontExpirePassword))
        {
            yield break;
        }

        var evidence = new List<string>
        {
            $"Service-account classification: {classification.DetectionMethod} ({classification.Confidence} confidence)."
        };
        evidence.AddRange(classification.Evidence);
        if (classification.Confidence == ServiceAccountDetectionConfidence.Heuristic)
        {
            evidence.Add("Service account classification is heuristic and should be confirmed.");
        }
        evidence.Add("Password setting: userAccountControl contains DONT_EXPIRE_PASSWORD.");

        yield return Finding(context, string.Join(Environment.NewLine, evidence));
    }
}
