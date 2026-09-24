using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.ViewModels;

public sealed class ServiceAccountClassificationViewModel
{
    public string Status { get; init; } = "No";
    public string BadgeCssClass { get; init; } = "text-bg-secondary";
    public string DetectionMethod { get; init; } = "None";
    public string Confidence { get; init; } = "None";
    public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> ServicePrincipalNames { get; init; } = Array.Empty<string>();
    public string InteractiveLogonPolicyStatus { get; init; } = "Not evaluated in this MVP.";

    public static ServiceAccountClassificationViewModel From(ServiceAccountClassification result)
    {
        var status = !result.IsServiceAccount
            ? "No"
            : result.Confidence == ServiceAccountDetectionConfidence.Heuristic
                ? "Possible"
                : "Yes";
        return new ServiceAccountClassificationViewModel
        {
            Status = status,
            BadgeCssClass = status switch
            {
                "Yes" => "text-bg-success",
                "Possible" => "text-bg-warning",
                _ => "text-bg-secondary"
            },
            DetectionMethod = result.DetectionMethod switch
            {
                ServiceAccountDetectionMethod.ServicePrincipalName => "Service Principal Name",
                ServiceAccountDetectionMethod.ManagedServiceAccount => "Managed Service Account (MSA)",
                ServiceAccountDetectionMethod.GroupManagedServiceAccount => "Group Managed Service Account (gMSA)",
                ServiceAccountDetectionMethod.NameHeuristic => "Name heuristic",
                ServiceAccountDetectionMethod.MultipleSignals => "Multiple signals",
                _ => "None"
            },
            Confidence = result.Confidence.ToString(),
            Evidence = result.Evidence,
            ServicePrincipalNames = result.ServicePrincipalNames
        };
    }
}
