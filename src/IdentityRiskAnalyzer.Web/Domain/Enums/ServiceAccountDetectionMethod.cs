namespace IdentityRiskAnalyzer.Web.Domain.Enums;

public enum ServiceAccountDetectionMethod
{
    None,
    ServicePrincipalName,
    ManagedServiceAccount,
    GroupManagedServiceAccount,
    NameHeuristic,
    MultipleSignals
}
