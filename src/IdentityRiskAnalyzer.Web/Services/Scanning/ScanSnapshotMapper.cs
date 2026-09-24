using System.Text.Json;
using IdentityRiskAnalyzer.Web.Domain.Entities;
using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

namespace IdentityRiskAnalyzer.Web.Services.Scanning;

public static class ScanSnapshotMapper
{
    public static AdObjectType GetObjectType(AdUserRecord user) =>
        user.ObjectClasses.Any(value => string.Equals(value, "msDS-ManagedServiceAccount", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "msDS-GroupManagedServiceAccount", StringComparison.OrdinalIgnoreCase))
            ? AdObjectType.ServiceAccount
            : AdObjectType.User;

    public static AdObjectSnapshot ToSnapshot(long scanRunId, AdUserRecord user,
        ServiceAccountClassification serviceAccount, PrivilegeAnalysisResult privileges,
        ObjectRiskScoreResult score, DateTimeOffset scanUtc) => new()
    {
        ScanRunId = scanRunId,
        ObjectGuid = user.ObjectGuid,
        Sid = user.Sid,
        ObjectType = GetObjectType(user),
        SamAccountName = user.SamAccountName,
        DisplayName = user.DisplayName,
        DistinguishedName = user.DistinguishedName,
        UserPrincipalName = user.UserPrincipalName,
        Enabled = !UserAccountControlHelper.IsDisabled(user.UserAccountControl),
        Locked = user.ComputedUserAccountControl.HasValue
            ? UserAccountControlHelper.IsLocked(user.ComputedUserAccountControl) : null,
        AccountExpired = user.AccountExpiresUtc.HasValue && user.AccountExpiresUtc.Value < scanUtc,
        IsServiceAccount = serviceAccount.IsServiceAccount,
        IsPrivileged = privileges.IsPrivileged,
        LastKnownActivityUtc = user.LastKnownActivityUtc,
        PasswordLastSetUtc = user.PasswordLastSetUtc,
        PasswordNeverExpires = UserAccountControlHelper.HasFlag(user.UserAccountControl, UserAccountControlFlags.DontExpirePassword),
        RiskScore = score.RiskScore,
        RiskLevel = score.RiskLevel
    };

    public static GroupMembership ToMembership(long scanRunId, GroupMembershipPathResult path, bool isPrivileged) => new()
    {
        ScanRunId = scanRunId,
        PrincipalObjectGuid = path.PrincipalObjectGuid,
        GroupObjectGuid = path.TargetGroupObjectGuid,
        GroupName = path.TargetGroupName,
        GroupDistinguishedName = path.TargetGroupDistinguishedName,
        IsDirect = path.IsDirect,
        Depth = path.Depth,
        PathJson = JsonSerializer.Serialize(path.PathDisplayNames),
        IsPrivileged = isPrivileged
    };

    public static DelegationRecord ToDelegation(long scanRunId, DelegationAnalysisResult result) => new()
    {
        ScanRunId = scanRunId,
        ObjectGuid = result.ObjectGuid,
        ObjectName = result.ObjectName,
        DelegationType = result.DelegationType,
        TargetsJson = JsonSerializer.Serialize(result.Targets)
    };

    public static RiskFinding ToFinding(long scanRunId, RiskFindingResult result) => new()
    {
        ScanRunId = scanRunId,
        ObjectGuid = result.ObjectGuid,
        ObjectType = result.ObjectType,
        ObjectName = result.ObjectName,
        RuleId = result.RuleId,
        Category = result.Category,
        Title = result.Title,
        Description = result.Description,
        Evidence = result.Evidence,
        Recommendation = result.Recommendation,
        RiskPoints = result.RiskPoints,
        Severity = result.Severity
    };
}
