namespace IdentityRiskAnalyzer.Web.Domain.Enums;

public enum ScanStatus
{
    Pending,
    Running,
    Completed,
    CompletedWithErrors,
    Failed,
    Cancelled
}
