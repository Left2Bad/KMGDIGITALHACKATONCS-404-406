using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.ViewModels;

public sealed class DelegationViewModel
{
    public string Type { get; init; } = string.Empty;
    public IReadOnlyList<string> Targets { get; init; } = Array.Empty<string>();
    public string Evidence { get; init; } = string.Empty;
    public bool RequiresDetailedReview { get; init; }

    public static DelegationViewModel From(DelegationAnalysisResult result) => new()
    {
        Type = result.DelegationType switch
        {
            DelegationType.ProtocolTransition => "Protocol Transition",
            DelegationType.ResourceBasedConstrained => "Resource-Based Constrained Delegation",
            _ => result.DelegationType.ToString()
        },
        Targets = result.Targets,
        Evidence = result.Evidence,
        RequiresDetailedReview = result.RequiresDetailedReview
    };
}
